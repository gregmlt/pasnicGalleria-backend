const mongoose = require("mongoose");

const artisteSchema = mongoose.Schema({
  oeuvres: [{ type: mongoose.Schema.Types.ObjectId, ref: "oeuvres" }],
  prenom: String,
  nom: String,
});

const Artiste = mongoose.model("artistes", artisteSchema);

module.exports = Artiste;
