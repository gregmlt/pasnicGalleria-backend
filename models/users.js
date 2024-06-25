const mongoose = require("mongoose");

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

  token: { type: String },
});

const User = mongoose.model("users", userSchema);

module.exports = User;
