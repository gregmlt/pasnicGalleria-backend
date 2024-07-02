var express = require("express");
var router = express.Router();
const Oeuvre = require("../models/oeuvres");
const Artiste = require("../models/artistes");

const cloudinary = require("cloudinary").v2;
const fs = require("fs");

// ! FONCTIONS

// ********** Générer un uniqID pour chaque oeuvre

const generateUniqueID = async (artisteNom) => {
  // Extraire les 4 premières lettres du nom de l'artiste et convertir en majuscules
  const artistePrefix = artisteNom.slice(0, 4).toUpperCase();

  // Récupérer l'artiste avec ses œuvres
  const artiste = await Artiste.findOne({
    nom: artisteNom.toLowerCase(),
  }).populate("oeuvres");

  // Si l'artiste n'existe pas ou n'a pas d'œuvres, on initialise à 0
  const oeuvresCount = artiste ? artiste.oeuvres.length : 0;

  // Trouver le numéro basé sur le nombre d'œuvres existantes
  const newNumber = (oeuvresCount + 1).toString().padStart(4, "0"); // Convertir en chaîne et compléter avec des zéros

  // Combiner le préfixe de l'artiste et le nouveau numéro pour former l'ID unique
  const uniqueID = `${artistePrefix}_${newNumber}`;

  return uniqueID;
};

// ! ROUTES
router.post("/post/newarticle/", async (req, res) => {
  try {
    const photoPath = `./tmp/photo.jpg`;
    const resultMove = await req.files.image.mv(photoPath);

    // Si l'image a bien été dupliquée dans un fichier temporaire
    if (!resultMove) {
      // uploader l'image dans cloudinary
      const resultCloudinary = await cloudinary.uploader.upload(photoPath);
      fs.unlinkSync(photoPath);
      const image = resultCloudinary.secure_url;
      const { artiste, titre, edition, dimension, prix, notes, statut, year } =
        req.body;

      const ID = await generateUniqueID(artiste);

      // Chercher si l'artiste existe
      let artisteFinded = await Artiste.findOne({ nom: artiste.toLowerCase() });

      if (!artisteFinded) {
        // Si l'artiste n'existe pas alors on le crée
        const newArtiste = new Artiste({ nom: artiste.toLowerCase() });
        await newArtiste.save();
        artisteFinded = newArtiste;
      }

      const artiste_ID = artisteFinded._id;

      const newOeuvre = new Oeuvre({
        artiste: artiste_ID,
        ID,
        titre,
        edition,
        dimension,
        prix,
        notes,
        statut,
        year,
        image,
      });

      await newOeuvre.save();

      await Artiste.updateOne(
        { _id: artiste_ID },
        { $push: { oeuvres: newOeuvre._id } }
      );

      res.json({ result: true });
    } else {
      res.json({ result: false, error: resultMove });
    }
  } catch (error) {
    console.error("Error creating new article:", error);
    res.status(500).json({ result: false, message: "Internal server error" });
  }
});

module.exports = router;
