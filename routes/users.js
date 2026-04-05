var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { OAuth2Client } = require("google-auth-library");

const User = require("../models/users");

// Client Google OAuth2 — vérifie les ID tokens émis par Google Sign-In
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// =============================================================================
// RATE LIMITING
// Limite les tentatives de connexion à 10 par IP par tranche de 15 minutes.
// =============================================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    result: false,
    message: "Trop de tentatives de connexion. Réessayez dans 15 minutes.",
  },
});

// =============================================================================
// MIDDLEWARES D'AUTHENTIFICATION
// =============================================================================

/**
 * Vérifie le token JWT dans Authorization: Bearer <token>.
 * Attache le payload décodé à req.user : { userId, role, iat, exp }
 */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ result: false, message: "Non autorisé" });
  }
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ result: false, message: "Token invalide ou expiré" });
  }
};

/**
 * Vérifie que l'utilisateur connecté a le rôle "admin".
 * Doit être utilisé après authenticate.
 */
const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ result: false, message: "Accès réservé aux administrateurs" });
  }
  next();
};

// =============================================================================
// MIDDLEWARES DE VALIDATION
// =============================================================================
const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

const PASSWORD_ERROR_MSG =
  "Le mot de passe doit contenir au moins 8 caractères, une majuscule, un chiffre et un caractère spécial (@$!%*?&).";

const validatePassword = (req, res, next) => {
  const { email, password } = req.body;
  const validationError = new User({ email, password }).validateSync();
  if (validationError) {
    return res.status(400).json({ result: false, message: validationError.errors });
  }
  if (!PASSWORD_REGEX.test(password)) {
    return res.status(400).json({ result: false, message: PASSWORD_ERROR_MSG });
  }
  next();
};

const validateSignIn = (req, res, next) => {
  const { email, password } = req.body;
  const validationError = new User({ email, password }).validateSync();
  if (validationError) {
    return res.status(400).json({ result: false, message: validationError.errors });
  }
  next();
};

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Génère un JWT signé avec userId + role, valide 7 jours.
 */
const signToken = (user) =>
  jwt.sign(
    { userId: user._id.toString(), role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

// =============================================================================
// ROUTES
// =============================================================================

/**
 * POST /users/auth/google
 * Connexion via Google Sign-In.
 * - Vérifie le credential (ID token) auprès de Google
 * - Crée le compte si c'est la première connexion
 * - L'email défini dans ADMIN_EMAIL reçoit automatiquement le rôle "admin"
 * - Retourne un JWT interne + rôle
 *
 * Body : { credential: "<google_id_token>" }
 */
router.post("/auth/google", loginLimiter, async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ result: false, message: "Credential manquant" });
    }

    // Vérification du token Google
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email;

    if (!payload.email_verified) {
      return res.status(401).json({ result: false, message: "Email Google non vérifié" });
    }

    // Trouver ou créer l'utilisateur
    let user = await User.findOne({ email });

    if (!user) {
      // Premier login : détermine le rôle selon ADMIN_EMAIL
      const adminEmails = (process.env.ADMIN_EMAIL || "").split(",").map((e) => e.trim().toLowerCase());
      const role = adminEmails.includes(email.toLowerCase()) ? "admin" : "user";

      user = await new User({
        email,
        password: bcrypt.hashSync(Math.random().toString(36), 10), // Mot de passe inutilisable (connexion Google uniquement)
        role,
      }).save();
    }

    res.json({ result: true, token: signToken(user), role: user.role });
  } catch (error) {
    console.error("Erreur auth Google:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * POST /users/create
 * Crée un nouveau compte email/mot de passe.
 * Réservé aux admins connectés.
 *
 * Body : { email, password, role? }
 */
router.post("/create", authenticate, adminOnly, validatePassword, async (req, res) => {
  try {
    const { email, password, role } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ result: false, message: "Cet email est déjà utilisé" });
    }

    const newUser = await new User({
      email,
      password: bcrypt.hashSync(password, 10),
      role: role === "admin" ? "admin" : "user",
    }).save();

    res.status(201).json({ result: true, email: newUser.email, role: newUser.role });
  } catch (error) {
    console.error("Erreur création utilisateur:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * POST /users/get/token
 * Connexion email/mot de passe — retourne un JWT signé (7 jours).
 * Protégé par rate limiting.
 *
 * Body : { email, password }
 */
router.post("/get/token", loginLimiter, validateSignIn, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ result: false, message: "Email ou mot de passe incorrect" });
    }

    res.json({ result: true, token: signToken(user), role: user.role });
  } catch (error) {
    console.error("Erreur connexion:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * POST /users/post/modify
 * Changement de mot de passe — nécessite d'être connecté.
 *
 * Body : { lastPassword, newPassword }
 */
router.post("/post/modify", authenticate, async (req, res) => {
  try {
    const { lastPassword, newPassword } = req.body;

    if (lastPassword === newPassword) {
      return res.status(400).json({
        result: false,
        message: "Le nouveau mot de passe doit être différent de l'ancien",
      });
    }
    if (!PASSWORD_REGEX.test(newPassword)) {
      return res.status(400).json({ result: false, message: PASSWORD_ERROR_MSG });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ result: false, message: "Utilisateur introuvable" });
    }
    if (!bcrypt.compareSync(lastPassword, user.password)) {
      return res.status(401).json({ result: false, message: "L'ancien mot de passe est incorrect" });
    }

    await User.updateOne({ _id: user._id }, { $set: { password: await bcrypt.hash(newPassword, 10) } });
    res.json({ result: true });
  } catch (error) {
    console.error("Erreur modification mot de passe:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

// =============================================================================
// GESTION DES UTILISATEURS (admin seulement)
// =============================================================================

/**
 * GET /users/all
 * Retourne la liste de tous les utilisateurs (email + rôle).
 * Les mots de passe ne sont jamais renvoyés.
 * Réservé aux admins.
 */
router.get("/all", authenticate, adminOnly, async (req, res) => {
  try {
    const users = await User.find({}, { email: 1, role: 1 }).sort({ email: 1 });
    res.json({ result: true, users });
  } catch (error) {
    console.error("Erreur liste utilisateurs:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * PUT /users/:id/role
 * Modifie le rôle d'un utilisateur (admin ↔ user).
 * Un admin ne peut pas rétrograder son propre compte.
 * Réservé aux admins.
 *
 * Body : { role: "admin"|"user" }
 */
router.put("/:id/role", authenticate, adminOnly, async (req, res) => {
  try {
    const { role } = req.body;

    if (!["admin", "user"].includes(role)) {
      return res.status(400).json({ result: false, message: "Rôle invalide" });
    }

    // Empêcher un admin de se rétrograder lui-même
    if (req.params.id === req.user.userId) {
      return res.status(403).json({
        result: false,
        message: "Vous ne pouvez pas modifier votre propre rôle",
      });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { role } },
      { new: true, select: "email role" }
    );

    if (!user) {
      return res.status(404).json({ result: false, message: "Utilisateur introuvable" });
    }

    res.json({ result: true, user });
  } catch (error) {
    console.error("Erreur modification rôle:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * DELETE /users/:id
 * Supprime un utilisateur.
 * Un admin ne peut pas supprimer son propre compte.
 * Réservé aux admins.
 */
router.delete("/:id", authenticate, adminOnly, async (req, res) => {
  try {
    if (req.params.id === req.user.userId) {
      return res.status(403).json({
        result: false,
        message: "Vous ne pouvez pas supprimer votre propre compte",
      });
    }

    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ result: false, message: "Utilisateur introuvable" });
    }

    res.json({ result: true });
  } catch (error) {
    console.error("Erreur suppression utilisateur:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

module.exports = router;
