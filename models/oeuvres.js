const mongoose = require("mongoose");

const oeuvreSchema = mongoose.Schema({
  image: String,
  ID: String,
  artiste: { type: mongoose.Schema.Types.ObjectId, ref: "artistes" },
  titre: String,
  edition: String,
  dimension: String,
  prix: String,
  notes: String,
  statut: String,
  year: Date,
});

const Oeuvre = mongoose.model("oeuvres", oeuvreSchema);

module.exports = Oeuvre;
