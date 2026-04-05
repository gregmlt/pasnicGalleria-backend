var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const User = require("../models/users");

// =============================================================================
// RATE LIMITING
// Limite les tentatives de connexion à 10 par IP par tranche de 15 minutes.
// Protège contre les attaques par force brute sur l'endpoint de login.
// =============================================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,  // Expose les headers RateLimit-*
  legacyHeaders: false,
  message: {
    result: false,
    message: "Trop de tentatives de connexion. Réessayez dans 15 minutes.",
  },
});

// =============================================================================
// MIDDLEWARE D'AUTHENTIFICATION JWT
// Vérifie la signature du token et attache le payload à req.user.
// Ne fait pas d'appel base de données — le rôle est encodé dans le token.
// =============================================================================

/**
 * Vérifie le token JWT dans le header Authorization: Bearer <token>.
 * @param {object} req.user - Payload décodé : { userId, role, iat, exp }
 */
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ result: false, message: "Non autorisé" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ result: false, message: "Token invalide ou expiré" });
  }
};

/**
 * Vérifie que l'utilisateur connecté possède le rôle "admin".
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

/**
 * Regex de validation du mot de passe.
 * Exige : 8+ caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial.
 */
const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

const PASSWORD_ERROR_MSG =
  "Le mot de passe doit contenir au moins 8 caractères, une majuscule, un chiffre et un caractère spécial (@$!%*?&).";

/**
 * Valide email + complexité du mot de passe.
 * Utilisé à la création de compte et au changement de mot de passe.
 */
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

/**
 * Valide uniquement la présence des champs email et password (sans vérifier la complexité).
 * Utilisé à la connexion car le mot de passe stocké est hashé.
 */
const validateSignIn = (req, res, next) => {
  const { email, password } = req.body;

  const validationError = new User({ email, password }).validateSync();
  if (validationError) {
    return res.status(400).json({ result: false, message: validationError.errors });
  }

  next();
};

// =============================================================================
// ROUTES
// =============================================================================

/**
 * POST /users/create
 * Crée un nouveau compte utilisateur.
 * Réservé aux admins connectés — le premier compte doit être créé
 * directement en base de données (mongosh) ou via un script de seed.
 *
 * Body : { email, password, role? }
 * Le rôle est "user" par défaut. Passer role: "admin" pour créer un admin.
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
 * Authentifie un utilisateur et retourne un JWT signé (valide 7 jours) + son rôle.
 * Protégé par rate limiting contre les attaques par force brute.
 *
 * Body : { email, password }
 * Réponse : { result: true, token: "<jwt>", role: "admin"|"user" }
 */
router.post("/get/token", loginLimiter, validateSignIn, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    // Message générique pour ne pas révéler si l'email existe en base
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ result: false, message: "Email ou mot de passe incorrect" });
    }

    // Signe un JWT avec userId + role — expire dans 7 jours
    const token = jwt.sign(
      { userId: user._id.toString(), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ result: true, token, role: user.role });
  } catch (error) {
    console.error("Erreur connexion:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * POST /users/post/modify
 * Permet à un utilisateur connecté de changer son mot de passe.
 * Vérifie l'ancien mot de passe avant d'appliquer le changement.
 * Nécessite d'être authentifié (token JWT valide).
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

    // Récupère l'utilisateur via l'ID encodé dans le JWT (pas d'email en clair dans le body)
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ result: false, message: "Utilisateur introuvable" });
    }

    if (!bcrypt.compareSync(lastPassword, user.password)) {
      return res.status(401).json({ result: false, message: "L'ancien mot de passe est incorrect" });
    }

    await User.updateOne(
      { _id: user._id },
      { $set: { password: await bcrypt.hash(newPassword, 10) } }
    );

    res.json({ result: true });
  } catch (error) {
    console.error("Erreur modification mot de passe:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

module.exports = router;
