console.log("BOOT START");

// 🔥 Manejo global de errores (mantener)
process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err.message, err.stack);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("UNHANDLED REJECTION:", reason);
  process.exit(1);
});

process.on("exit", (code) => {
  console.log("PROCESS EXIT with code:", code);
});

// 🔍 Validación de entorno (muy buen punto, se queda)
console.log("ENV CHECK:", {
  SQL_USER:             !!process.env.SQL_USER,
  DB_NAME:              !!process.env.DB_NAME,
  INSTANCE_CONNECTION:  !!process.env.INSTANCE_CONNECTION,
  SMTP_HOST:            !!process.env.SMTP_HOST,
  JWT_SECRET:           !!process.env.JWT_SECRET,
  JWT_EXPIRES_IN:       !!process.env.JWT_EXPIRES_IN,
});

const express = require("express");
const cors = require("cors");

// 🔌 Infraestructura
console.log("loading db");
const pool = require("./src/db/pool");
console.log("db loaded OK");

// 🎯 Controllers
const authController = require("./src/controllers/auth.controller");
const portalController = require("./src/controllers/portal.controller");

const app = express();

// 🌐 Middlewares base
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// ❤️ Health checks
app.get("/health", (req, res) => {
  res.json({ status: "ok", ts: new Date().toISOString() });
});

app.get("/", (req, res) => {
  res.send("OK");
});

// 🔐 AUTH
app.post("/auth/login/alumno", authController.loginAlumno);
app.post("/auth/login/usuario", authController.loginUsuario);
app.post("/auth/sync-identidad", authController.syncIdentidad);
app.post("/auth/reset-password", authController.resetPassword);
app.post("/auth/set-password", authController.setPassword);
app.post("/auth/check-identidad", authController.checkIdentidad);

// 📊 PORTAL
app.get("/portalReadApi/:viewName", portalController.read);

// 🚨 Error handler central
app.use((err, req, res, next) => {
  console.error("API ERROR:", err.message);
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.status(500).json({ ok: false, error: err.message });
});

// 🚀 Start server
console.log("before listen");
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log("auth-api running on port", PORT);
});