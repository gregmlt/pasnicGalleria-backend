var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { OAuth2Client } = require("google-auth-library");

const User = require("../models/users");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// =============================================================================
// RATE LIMITING — 10 tentatives de connexion max par IP par 15 minutes
// =============================================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { result: false, message: "Trop de tentatives. Réessayez dans 15 minutes." },
});

// =============================================================================
// MIDDLEWARES D'AUTHENTIFICATION
// =============================================================================

/**
 * Vérifie le JWT dans Authorization: Bearer <token>.
 * req.user = { userId, role, iat, exp }
 */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ result: false, message: "Non autorisé" });
  }
  try {
    req.user = jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ result: false, message: "Token invalide ou expiré" });
  }
};

/**
 * Autorise admin ET superadmin.
 */
const adminOnly = (req, res, next) => {
  if (!["admin", "superadmin"].includes(req.user.role)) {
    return res.status(403).json({ result: false, message: "Accès réservé aux administrateurs" });
  }
  next();
};

/**
 * Autorise uniquement superadmin.
 */
const superadminOnly = (req, res, next) => {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({ result: false, message: "Accès réservé au super administrateur" });
  }
  next();
};

// =============================================================================
// VALIDATION MOT DE PASSE
// =============================================================================
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const PASSWORD_ERROR_MSG = "Le mot de passe doit contenir au moins 8 caractères, une majuscule, un chiffre et un caractère spécial (@$!%*?&).";

const validatePassword = (req, res, next) => {
  const { email, password } = req.body;
  const validationError = new User({ email, password }).validateSync();
  if (validationError) return res.status(400).json({ result: false, message: validationError.errors });
  if (!PASSWORD_REGEX.test(password)) return res.status(400).json({ result: false, message: PASSWORD_ERROR_MSG });
  next();
};

const validateSignIn = (req, res, next) => {
  const { email, password } = req.body;
  const validationError = new User({ email, password }).validateSync();
  if (validationError) return res.status(400).json({ result: false, message: validationError.errors });
  next();
};

// =============================================================================
// HELPER
// =============================================================================
const signToken = (user) =>
  jwt.sign({ userId: user._id.toString(), role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });

// =============================================================================
// CONNEXION GOOGLE
// =============================================================================

/**
 * POST /users/auth/google
 * Vérifie l'ID token Google, crée le compte si première connexion.
 * SUPERADMIN_EMAIL → rôle superadmin, ADMIN_EMAIL → rôle admin, sinon user.
 */
router.post("/auth/google", loginLimiter, async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ result: false, message: "Credential manquant" });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email;

    if (!payload.email_verified) {
      return res.status(401).json({ result: false, message: "Email Google non vérifié" });
    }

    let user = await User.findOne({ email });

    if (!user) {
      const superadminEmails = (process.env.SUPERADMIN_EMAIL || "").split(",").map((e) => e.trim().toLowerCase());
      const adminEmails = (process.env.ADMIN_EMAIL || "").split(",").map((e) => e.trim().toLowerCase());
      const emailLower = email.toLowerCase();

      let role = "user";
      if (superadminEmails.includes(emailLower)) role = "superadmin";
      else if (adminEmails.includes(emailLower)) role = "admin";

      user = await new User({
        email,
        password: bcrypt.hashSync(Math.random().toString(36), 10),
        role,
      }).save();
    }

    res.json({ result: true, token: signToken(user), role: user.role });
  } catch (error) {
    console.error("Erreur auth Google:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

// =============================================================================
// CONNEXION EMAIL / MOT DE PASSE
// =============================================================================

/**
 * POST /users/get/token
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

// =============================================================================
// CRÉATION DE COMPTE (admin/superadmin seulement)
// =============================================================================

/**
 * POST /users/create
 */
router.post("/create", authenticate, adminOnly, validatePassword, async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ result: false, message: "Cet email est déjà utilisé" });

    // Un admin ne peut pas créer un superadmin
    const allowedRole = role === "admin" ? "admin" : "user";
    const finalRole = req.user.role === "superadmin" && role === "superadmin" ? "superadmin" : allowedRole;

    const newUser = await new User({
      email,
      password: bcrypt.hashSync(password, 10),
      role: finalRole,
    }).save();

    res.status(201).json({ result: true, email: newUser.email, role: newUser.role });
  } catch (error) {
    console.error("Erreur création utilisateur:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

// =============================================================================
// PARAMÈTRES DU COMPTE (utilisateur connecté)
// =============================================================================

/**
 * GET /users/me
 * Retourne l'email et le rôle de l'utilisateur connecté.
 */
router.get("/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId, { email: 1, role: 1 });
    if (!user) return res.status(404).json({ result: false, message: "Utilisateur introuvable" });
    res.json({ result: true, email: user.email, role: user.role });
  } catch (error) {
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * PUT /users/me/email
 * Modifie l'email de l'utilisateur connecté.
 * Body : { newEmail, password }
 */
router.put("/me/email", authenticate, async (req, res) => {
  try {
    const { newEmail, password } = req.body;
    if (!newEmail || !password) {
      return res.status(400).json({ result: false, message: "Email et mot de passe requis" });
    }

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ result: false, message: "Utilisateur introuvable" });

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ result: false, message: "Mot de passe incorrect" });
    }

    const existing = await User.findOne({ email: newEmail });
    if (existing) return res.status(409).json({ result: false, message: "Cet email est déjà utilisé" });

    await User.updateOne({ _id: user._id }, { $set: { email: newEmail } });
    res.json({ result: true });
  } catch (error) {
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * PUT /users/me/password
 * Modifie le mot de passe de l'utilisateur connecté.
 * Body : { lastPassword, newPassword }
 */
router.put("/me/password", authenticate, async (req, res) => {
  try {
    const { lastPassword, newPassword } = req.body;

    if (lastPassword === newPassword) {
      return res.status(400).json({ result: false, message: "Le nouveau mot de passe doit être différent" });
    }
    if (!PASSWORD_REGEX.test(newPassword)) {
      return res.status(400).json({ result: false, message: PASSWORD_ERROR_MSG });
    }

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ result: false, message: "Utilisateur introuvable" });

    if (!bcrypt.compareSync(lastPassword, user.password)) {
      return res.status(401).json({ result: false, message: "L'ancien mot de passe est incorrect" });
    }

    await User.updateOne({ _id: user._id }, { $set: { password: await bcrypt.hash(newPassword, 10) } });
    res.json({ result: true });
  } catch (error) {
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

// Conserve l'ancienne route pour compatibilité
router.post("/post/modify", authenticate, async (req, res) => {
  req.body.lastPassword = req.body.lastPassword;
  req.body.newPassword = req.body.newPassword;
  return res.redirect(307, "/users/me/password");
});

// =============================================================================
// GESTION DES UTILISATEURS (admin/superadmin)
// =============================================================================

/**
 * GET /users/all
 * Liste tous les utilisateurs. Superadmin voit tout, admin voit user/admin seulement.
 */
router.get("/all", authenticate, adminOnly, async (req, res) => {
  try {
    const filter = req.user.role === "superadmin" ? {} : { role: { $ne: "superadmin" } };
    const users = await User.find(filter, { email: 1, role: 1 }).sort({ email: 1 });
    res.json({ result: true, users });
  } catch (error) {
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * PUT /users/:id/role
 * Change le rôle d'un utilisateur.
 * - Admin ne peut pas attribuer superadmin ni modifier un superadmin
 * - Personne ne peut modifier son propre rôle
 */
router.put("/:id/role", authenticate, adminOnly, async (req, res) => {
  try {
    const { role } = req.body;
    const validRoles = req.user.role === "superadmin" ? ["superadmin", "admin", "user"] : ["admin", "user"];

    if (!validRoles.includes(role)) {
      return res.status(400).json({ result: false, message: "Rôle invalide" });
    }
    if (req.params.id === req.user.userId) {
      return res.status(403).json({ result: false, message: "Vous ne pouvez pas modifier votre propre rôle" });
    }

    // Admin ne peut pas modifier un superadmin
    const target = await User.findById(req.params.id);
    if (!target) return res.status(404).json({ result: false, message: "Utilisateur introuvable" });
    if (target.role === "superadmin" && req.user.role !== "superadmin") {
      return res.status(403).json({ result: false, message: "Action non autorisée" });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { role } },
      { new: true, select: "email role" }
    );

    res.json({ result: true, user });
  } catch (error) {
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * DELETE /users/:id
 * Supprime un utilisateur.
 * Admin ne peut pas supprimer un superadmin.
 */
router.delete("/:id", authenticate, adminOnly, async (req, res) => {
  try {
    if (req.params.id === req.user.userId) {
      return res.status(403).json({ result: false, message: "Vous ne pouvez pas supprimer votre propre compte" });
    }

    const target = await User.findById(req.params.id);
    if (!target) return res.status(404).json({ result: false, message: "Utilisateur introuvable" });
    if (target.role === "superadmin" && req.user.role !== "superadmin") {
      return res.status(403).json({ result: false, message: "Action non autorisée" });
    }

    await User.findByIdAndDelete(req.params.id);
    res.json({ result: true });
  } catch (error) {
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

module.exports = router;
