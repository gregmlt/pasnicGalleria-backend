const mongoose = require("mongoose");

/**
 * Schéma d'une oeuvre d'art
 * - ID : identifiant lisible généré automatiquement (ex: "ALLI_0001")
 * - artiste : référence vers le document Artiste (populate disponible)
 * - image : URL Cloudinary de la photo
 * - year : année de création (nombre entier)
 * - statut : état de l'oeuvre parmi les valeurs définies en front
 */
const oeuvreSchema = mongoose.Schema({
  ID: String,
  artiste: { type: mongoose.Schema.Types.ObjectId, ref: "artistes" },
  image: String,
  titre: String,
  edition: String,
  dimension: String,
  prix: String,
  notes: String,
  statut: String,
  year: Number,
});

const Oeuvre = mongoose.model("oeuvres", oeuvreSchema);

module.exports = Oeuvre;
