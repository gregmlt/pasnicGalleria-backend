require("dotenv").config();
require("./models/connection");

const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const logger = require("morgan");
const cors = require("cors");
const fileUpload = require("express-fileupload");
const helmet = require("helmet");

const indexRouter = require("./routes/index");
const usersRouter = require("./routes/users");
const articlesRouter = require("./routes/articles");

const app = express();

// =============================================================================
// SÉCURITÉ — Headers HTTP
// Helmet positionne automatiquement une douzaine d'en-têtes de sécurité
// (Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options…)
// et désactive X-Powered-By pour ne pas révéler le stack technique.
// =============================================================================
app.use(helmet());

// =============================================================================
// CORS
// En production, seules les origines listées dans ALLOWED_ORIGINS sont autorisées.
// Les requêtes sans Origin (Origin: null, ex: fichiers locaux ouverts directement)
// sont rejetées en production pour bloquer les attaques CSRF par fichiers locaux.
// =============================================================================
const isProduction = process.env.NODE_ENV === "production";
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim())
  : ["http://localhost:3001"];

app.use(cors({
  origin: (origin, callback) => {
    // Développement : autorise les requêtes sans Origin (curl, Postman, etc.)
    if (!isProduction && !origin) {
      return callback(null, true);
    }
    // Production : uniquement les origines explicitement listées
    if (origin && allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error("Not allowed by CORS"));
  },
  allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"],
  methods: ["GET", "POST", "PUT", "DELETE"],
}));

// =============================================================================
// MIDDLEWARES GLOBAUX
// =============================================================================

// Logs des requêtes HTTP uniquement en développement
if (!isProduction) {
  app.use(logger("dev"));
}

// Limites de taille pour prévenir les attaques par payload surdimensionné
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(cookieParser());

// Upload de fichiers — limite à 5 Mo par fichier
app.use(fileUpload({ limits: { fileSize: 5 * 1024 * 1024 } }));
app.use(express.static(path.join(__dirname, "public")));

// =============================================================================
// ROUTES
// =============================================================================
app.use("/", indexRouter);
app.use("/users", usersRouter);
app.use("/articles", articlesRouter);

module.exports = app;
