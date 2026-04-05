const mongoose = require("mongoose");

/**
 * Schéma utilisateur
 * - email : adresse unique, validée par regex
 * - password : stocké hashé (bcrypt) — jamais en clair
 * - token : généré à la connexion (uid2), utilisé pour authentifier les requêtes API
 * - role : "admin" peut tout faire, "user" peut seulement consulter
 */
const userSchema = mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    match: [
      /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      "Veuillez entrer une adresse email valide.",
    ],
  },
  password: {
    type: String,
    required: true,
    trim: true,
  },
  token: {
    type: String,
  },
  role: {
    type: String,
    enum: ["admin", "user"],
    default: "user", // Les nouveaux comptes sont "user" par défaut — passer "admin" explicitement si besoin
  },
});

const User = mongoose.model("users", userSchema);

module.exports = User;
