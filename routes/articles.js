var express = require("express");
var router = express.Router();
const mongoose = require("mongoose");
const cloudinary = require("cloudinary").v2;
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const Oeuvre = require("../models/oeuvres");
const Artiste = require("../models/artistes");

// =============================================================================
// MIDDLEWARE D'AUTHENTIFICATION JWT
// Vérifie la signature du token — pas d'appel base de données.
// Le rôle est encodé directement dans le payload JWT.
// =============================================================================

/**
 * Vérifie le token JWT dans Authorization: Bearer <token>.
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
 * Vérifie que l'utilisateur connecté a le rôle "admin".
 * À utiliser après authenticate.
 */
const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      result: false,
      message: "Accès réservé aux administrateurs",
    });
  }
  next();
};

// =============================================================================
// VALIDATION DES FICHIERS
// =============================================================================

const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 Mo

/**
 * Vérifie qu'un fichier uploadé est une image autorisée (JPEG, PNG, WebP)
 * et ne dépasse pas 5 Mo.
 * @throws {Error} Si le fichier ne satisfait pas les contraintes
 */
const validateImageFile = (file) => {
  if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
    throw new Error("Format non autorisé. Utilisez JPEG, PNG ou WebP.");
  }
  if (file.size > MAX_FILE_SIZE) {
    throw new Error("Fichier trop volumineux. Maximum 5 Mo.");
  }
};

// =============================================================================
// FONCTIONS UTILITAIRES
// =============================================================================

/**
 * Construit la requête MongoDB pour retrouver une oeuvre par son identifiant.
 * Accepte soit l'ID lisible (ex: "ALLI_0001") soit un ObjectId MongoDB.
 *
 * @param {string} param - Valeur de req.params.id
 * @returns {object} Filtre Mongoose
 */
const buildQuery = (param) => {
  return mongoose.Types.ObjectId.isValid(param)
    ? { $or: [{ ID: param }, { _id: param }] }
    : { ID: param };
};

/**
 * Génère un ID unique lisible pour une oeuvre au format "PRENOM_0001".
 * Le préfixe est basé sur les 4 premières lettres du nom de l'artiste.
 * Le numéro est séquentiel par artiste.
 *
 * @param {string} artisteNom - Nom de l'artiste
 * @returns {Promise<string>} Identifiant unique (ex: "ALLI_0003")
 */
const generateUniqueID = async (artisteNom) => {
  const prefix = artisteNom.slice(0, 4).toUpperCase();
  const artiste = await Artiste.findOne({ nom: artisteNom.toLowerCase() }).populate("oeuvres");
  const count = artiste ? artiste.oeuvres.length : 0;
  const number = (count + 1).toString().padStart(4, "0");
  return `${prefix}_${number}`;
};

/**
 * Téléverse un fichier image sur Cloudinary via un fichier temporaire local.
 * - Utilise crypto.randomBytes pour un nom de fichier temporaire imprévisible
 * - Le fichier temporaire est supprimé dans un bloc finally (même en cas d'erreur)
 *
 * @param {object} file - Fichier reçu via express-fileupload
 * @returns {Promise<object>} Résultat Cloudinary (contient secure_url, public_id, etc.)
 */
const uploadToCloudinary = async (file) => {
  const tmpDir = path.join(__dirname, "../tmp");
  if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir, { recursive: true });
  }

  // Extension selon le type MIME réel (pas basée sur le nom du fichier client)
  const extMap = { "image/png": ".png", "image/webp": ".webp", "image/jpeg": ".jpg" };
  const ext = extMap[file.mimetype] ?? ".jpg";

  // Nom aléatoire cryptographiquement sûr pour éviter tout conflit ou prédiction
  const tmpPath = path.join(tmpDir, `upload_${crypto.randomBytes(16).toString("hex")}${ext}`);

  await file.mv(tmpPath);

  try {
    const result = await cloudinary.uploader.upload(tmpPath);
    return result;
  } finally {
    // Nettoyage garanti même si l'upload Cloudinary échoue
    fs.unlink(tmpPath, () => {});
  }
};

/**
 * Supprime une image de Cloudinary à partir de son URL.
 * Les erreurs sont loguées mais ne font pas planter l'opération principale.
 *
 * @param {string|null} imageUrl - URL Cloudinary de l'image à supprimer
 */
const deleteFromCloudinary = async (imageUrl) => {
  if (!imageUrl) return;
  try {
    const parts = imageUrl.split("/");
    const publicId = parts[parts.length - 1].split(".")[0];
    await cloudinary.uploader.destroy(publicId);
  } catch (err) {
    console.error("Erreur suppression Cloudinary:", err);
  }
};

// =============================================================================
// ROUTES
// =============================================================================

/**
 * GET /articles/get/all
 * Retourne toutes les oeuvres avec l'artiste populé.
 * Accessible à tous les utilisateurs connectés (admin + user).
 */
router.get("/get/all", authenticate, async (req, res) => {
  try {
    const oeuvres = await Oeuvre.find().populate("artiste").sort({ createdAt: -1 });
    res.json({ result: true, oeuvres });
  } catch (error) {
    console.error("Erreur GET all:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * GET /articles/get/:id
 * Retourne une oeuvre par son ID lisible (ex: "ALLI_0001") ou son ObjectId MongoDB.
 * Accessible à tous les utilisateurs connectés.
 */
router.get("/get/:id", authenticate, async (req, res) => {
  try {
    const oeuvre = await Oeuvre.findOne(buildQuery(req.params.id)).populate("artiste");
    if (!oeuvre) {
      return res.status(404).json({ result: false, message: "Oeuvre non trouvée" });
    }
    res.json({ result: true, oeuvre });
  } catch (error) {
    console.error("Erreur GET one:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

/**
 * POST /articles/post/newarticle
 * Crée une nouvelle oeuvre.
 * - Valide et uploade l'image sur Cloudinary (optionnel)
 * - Crée l'artiste s'il n'existe pas encore
 * - Génère un ID lisible unique (ex: "ALLI_0004")
 * Réservé aux admins.
 */
router.post("/post/newarticle/", authenticate, adminOnly, async (req, res) => {
  try {
    // Validation et upload de l'image si fournie
    let image = null;
    if (req.files?.image) {
      validateImageFile(req.files.image); // Lève une erreur si invalide
      const cloudResult = await uploadToCloudinary(req.files.image);
      image = cloudResult.secure_url;
    }

    const { artiste, titre, edition, dimension, prix, notes, statut, year } = req.body;

    // Créer l'artiste si inexistant (nom stocké en minuscules pour normalisation)
    let artisteDoc = await Artiste.findOne({ nom: artiste.toLowerCase() });
    if (!artisteDoc) {
      artisteDoc = await new Artiste({ nom: artiste.toLowerCase() }).save();
    }

    const newOeuvre = await new Oeuvre({
      artiste: artisteDoc._id,
      ID: await generateUniqueID(artiste),
      titre,
      edition,
      dimension,
      prix,
      notes,
      statut,
      year: year ? parseInt(year) : undefined,
      image,
    }).save();

    // Lier l'oeuvre au document artiste
    await Artiste.updateOne(
      { _id: artisteDoc._id },
      { $push: { oeuvres: newOeuvre._id } }
    );

    const populated = await Oeuvre.findById(newOeuvre._id).populate("artiste");
    res.status(201).json({ result: true, oeuvre: populated });
  } catch (error) {
    // Erreur de validation fichier → 400, sinon 500
    const status = error.message?.includes("Format") || error.message?.includes("volumineux") ? 400 : 500;
    console.error("Erreur création oeuvre:", error);
    res.status(status).json({ result: false, message: error.message || "Erreur serveur" });
  }
});

/**
 * PUT /articles/put/:id
 * Met à jour les champs d'une oeuvre existante.
 * Si une nouvelle image est fournie, l'ancienne est supprimée de Cloudinary.
 * L'artiste et l'ID lisible ne sont pas modifiables.
 * Réservé aux admins.
 */
router.put("/put/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const query = buildQuery(req.params.id);
    const oeuvre = await Oeuvre.findOne(query);
    if (!oeuvre) {
      return res.status(404).json({ result: false, message: "Oeuvre non trouvée" });
    }

    // Remplacer l'image si une nouvelle est fournie
    let image = oeuvre.image;
    if (req.files?.image) {
      validateImageFile(req.files.image); // Valide avant de supprimer l'ancienne
      await deleteFromCloudinary(oeuvre.image);
      image = (await uploadToCloudinary(req.files.image)).secure_url;
    }

    const { titre, edition, dimension, prix, notes, statut, year } = req.body;

    const updated = await Oeuvre.findOneAndUpdate(
      query,
      { titre, edition, dimension, prix, notes, statut, image, year: year ? parseInt(year) : undefined },
      { new: true }
    ).populate("artiste");

    res.json({ result: true, oeuvre: updated });
  } catch (error) {
    const status = error.message?.includes("Format") || error.message?.includes("volumineux") ? 400 : 500;
    console.error("Erreur modification oeuvre:", error);
    res.status(status).json({ result: false, message: error.message || "Erreur serveur" });
  }
});

/**
 * DELETE /articles/delete/:id
 * Supprime une oeuvre et son image Cloudinary associée.
 * Retire également la référence dans le document Artiste.
 * Réservé aux admins.
 */
router.delete("/delete/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const query = buildQuery(req.params.id);
    const oeuvre = await Oeuvre.findOne(query);
    if (!oeuvre) {
      return res.status(404).json({ result: false, message: "Oeuvre non trouvée" });
    }

    await deleteFromCloudinary(oeuvre.image);

    // Retirer l'oeuvre de la liste de l'artiste
    await Artiste.updateOne(
      { _id: oeuvre.artiste },
      { $pull: { oeuvres: oeuvre._id } }
    );

    await Oeuvre.deleteOne(query);
    res.json({ result: true });
  } catch (error) {
    console.error("Erreur suppression oeuvre:", error);
    res.status(500).json({ result: false, message: "Erreur serveur" });
  }
});

module.exports = router;
