var express = require("express");
var router = express.Router();
const User = require("../models/users");
const uid2 = require("uid2");
const bcrypt = require("bcrypt");

// ! MIDDLEWARES

// ******* Verification création user

function verificationSignUpMiddleware(req, res, next) {
  const newUser = new User({
    email: req.body.email,
    password: req.body.password,
  });

  const validationError = newUser.validateSync();

  if (validationError) {
    return res
      .status(400)
      .json({ result: false, message: validationError.errors });
  } else if (
    !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(
      newUser.password
    )
  ) {
    return res.status(400).json({
      result: false,
      message:
        "Le mot de passe n'est pas un mot de passe valide! Le mot de passe doit contenir au moins 8 caractères, une majuscule et un caractère spécial et un chiffre.",
    });
  }
  next();
}

// ******* Verification connexion user
function verificationSignInMiddleware(req, res, next) {
  const newUser = new User({
    email: req.body.email,
    password: req.body.password,
  });

  const validationError = newUser.validateSync();

  if (validationError) {
    return res
      .status(400)
      .json({ result: false, message: validationError.errors });
  }
  next();
}

// ******* Verification changement de mot de passe
function verificationModfiyPasswordMiddleware(req, res, next) {
  const { newPassword, lastPassword } = req.body;

  if (newPassword === lastPassword) {
    res.json({
      result: false,
      message:
        "Le mot de passe actuel et le nouveau mot de passe doivent être différents",
    });
  } else {
    const newUser = new User({
      email: req.body.email,
      password: newPassword,
    });

    const validationError = newUser.validateSync();

    if (validationError) {
      return res
        .status(400)
        .json({ result: false, message: validationError.errors });
    } else if (
      !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(
        newUser.password
      )
    ) {
      return res.status(400).json({
        result: false,
        message:
          "Le mot de passe n'est pas un mot de passe valide! Le mot de passe doit contenir au moins 8 caractères, une majuscule et un caractère spécial et un chiffre.",
      });
    }

    next();
  }
}

// ! ROUTES

// ******* Sign-up -- Pas dispo en front

router.post("/create", verificationSignUpMiddleware, async (req, res) => {
  try {
    const { email, password } = req.body;

    const hash = bcrypt.hashSync(password, 10);
    const token = uid2(32);

    const existingUser = await User.findOne({ email: req.body.email });

    if (existingUser) {
      return res.json({ result: false, error: "User already exists" });
    }
    const newUser = new User({
      email,
      password: hash,
      token,
    });

    const create = await newUser.save();

    if (create) {
      res.json({
        result: true,
        token,
      });
    } else {
      res.json({ result: false, error: "A problem occured when user saved" });
    }
  } catch (error) {
    console.error("Error creating user:", error);
    return res
      .status(500)
      .json({ result: false, message: "Internal server error" });
  }
});

// ******* Sign-in

router.get(
  "/get/token",
  verificationSignInMiddleware,
  async (req, res, next) => {
    try {
      const { email } = req.body;
      const { password } = req.body;

      const result = await User.findOne({ email });

      if (result && bcrypt.compareSync(password, result.password)) {
        res.json({ result: true, token: result.token });
      } else if (result && !bcrypt.compareSync(password, result.password)) {
        res.json({
          result: false,
          message: "Le mot de passe ne correspond pas avec l'email saisi",
        });
      } else {
        res.json({
          result: false,
          message: "L'utilisateur correspondant à cet email n'existe pas",
        });
      }
    } catch (error) {
      console.error("Error login user:", error);
      return res
        .status(500)
        .json({ result: false, message: "Internal server error" });
    }
  }
);

// ******* Modification de mot de passe
router.post(
  "/post/modify",
  verificationModfiyPasswordMiddleware,
  async (req, res) => {
    try {
      const { email, lastPassword, newPassword } = req.body;

      const searchedUser = await User.findOne({ email });

      if (!searchedUser) {
        return res.json({
          result: false,
          message: "L'utilisateur n'existe pas",
        });
      }

      const isMatch = await bcrypt.compareSync(
        lastPassword,
        searchedUser.password
      );
      if (!isMatch) {
        return res.json({
          result: false,
          message: "L'ancien mot de passe ne correspond pas",
        });
      }

      const hash = await bcrypt.hash(newPassword, 10);

      const updatedUser = await User.updateOne(
        { email },
        { $set: { password: hash } }
      );

      res.json({ result: updatedUser });
    } catch (error) {
      console.error("Error modifying user password:", error);
      res.status(500).json({ result: false, message: "Internal server error" });
    }
  }
);

// ******* Avoir l'email de l'utilisateur via son token
router.get("/get/email/:token", async (req, res) => {
  try {
    const { token } = req.params;

    const searchedUser = await User.findOne({ token });

    if (searchedUser) {
      res.json({ result: true, email: searchedUser.email });
    } else {
      res.json({ result: false, message: "L'utilisateur n'a pas été trouvé" });
    }
  } catch (error) {
    console.error("Error searching user via token:", error);
    res.status(500).json({ result: false, message: "Internal server error" });
  }
});

module.exports = router;
