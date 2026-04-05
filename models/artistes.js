const mongoose = require("mongoose");

/**
 * Schéma d'un artiste
 * - nom : stocké en minuscules pour les comparaisons insensibles à la casse
 * - oeuvres : liste des ObjectId des oeuvres associées (référence bidirectionnelle)
 */
const artisteSchema = mongoose.Schema({
  nom: String,
  oeuvres: [{ type: mongoose.Schema.Types.ObjectId, ref: "oeuvres" }],
});

const Artiste = mongoose.model("artistes", artisteSchema);

module.exports = Artiste;
