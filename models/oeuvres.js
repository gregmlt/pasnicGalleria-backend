const mongoose = require("mongoose");

const oeuvreSchema = mongoose.Schema({
  uniqId: String,
  artiste: { type: mongoose.Schema.Types.ObjectId, ref: "artistes" },
  editions: String,
  dimension: String,
  prix: Number,
  notes: String,
  statut: String,
  year: Date,
});

const Oeuvre = mongoose.model("oeuvres", oeuvreSchema);

module.exports = Oeuvre;
