console.log("BOOT START");

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

// Variables críticas (sin exponer valores)
console.log("ENV CHECK:", {
  SQL_USER:             !!process.env.SQL_USER,
  DB_NAME:              !!process.env.DB_NAME,
  INSTANCE_CONNECTION:  !!process.env.INSTANCE_CONNECTION,
  SMTP_HOST:            !!process.env.SMTP_HOST,
  JWT_SECRET:           !!process.env.JWT_SECRET,
  JWT_EXPIRES_IN:       !!process.env.JWT_EXPIRES_IN,
});

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cors = require("cors");

console.log("loading db");
const pool = require("./db");
console.log("db loaded OK");

console.log("loading auth");
const { login } = require("./auth");
console.log("auth loaded OK");

console.log("loading mailer");
const { sendSetPasswordEmail } = require("./mailer");
console.log("mailer loaded OK");

const app = express();

// 1️⃣ CORS - primero siempre
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// 2️⃣ Body parser - segundo
app.use(express.json());

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", ts: new Date().toISOString() });
});

app.get("/", (req, res) => {
  res.send("OK");
});

// 3️⃣ RUTAS
app.post("/auth/login/alumno", async (req, res) => {
  try {
    const { correo, password } = req.body;
    if (!correo || !password) return res.json({ ok: false });
    const token = await login(correo, password, "ALUMNO");
    return res.json({ ok: true, token });
  } catch {
    return res.json({ ok: false });
  }
});

app.post("/auth/login/usuario", async (req, res) => {
  try {
    const { correo, password } = req.body;
    if (!correo || !password) return res.json({ ok: false });
    const token = await login(correo, password, "USUARIO");
    return res.json({ ok: true, token });
  } catch {
    return res.json({ ok: false });
  }
});

app.post("/auth/sync-identidad", async (req, res) => {
  const { correo, tipoEntidad, idEntidad } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query(
      `SELECT IdAuth FROM AUTH_IDENTIDADES WHERE TipoEntidad = ? AND IdEntidad = ?`,
      [tipoEntidad, idEntidad]
    );
    if (rows.length === 0) {
      const idAuth = crypto.randomUUID();
      await conn.query(
        `INSERT INTO AUTH_IDENTIDADES (IdAuth, Correo, TipoEntidad, IdEntidad) VALUES (?, ?, ?, ?)`,
        [idAuth, correo, tipoEntidad, idEntidad]
      );
    } else {
      await conn.query(
        `UPDATE AUTH_IDENTIDADES SET Correo = ? WHERE IdAuth = ?`,
        [correo, rows[0].IdAuth]
      );
    }
    await conn.commit();
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

app.post("/auth/reset-password", async (req, res) => {
  console.log("🔥 reset-password START");
  try {
    const { correo, tipoEntidad } = req.body;
    console.log("BODY:", { correo, tipoEntidad });

    if (!correo || !tipoEntidad) return res.json({ ok: false });

    console.log("DB QUERY START");
    const [rows] = await pool.query(
      `SELECT IdAuth, TipoEntidad, IdEntidad FROM AUTH_IDENTIDADES WHERE Correo = ? AND TipoEntidad = ? AND Status = 'ACTIVO' LIMIT 1`,
      [correo, tipoEntidad]
    );
    console.log("DB QUERY RESULT:", rows);

    if (rows.length > 0) {
      const identity = rows[0];

      console.log("JWT PAYLOAD:", identity);
      console.log("JWT CONFIG:", {
        hasSecret: !!process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN
      });

      const token = jwt.sign(
        { sub: identity.IdAuth, tipoEntidad: identity.TipoEntidad, idEntidad: identity.IdEntidad },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );
      console.log("JWT GENERATED OK");

      console.log("EMAIL SEND START");
      try {
        await sendSetPasswordEmail(correo, token);
        console.log("EMAIL SENT OK");
      } catch (mailErr) {
        console.error("💥 MAIL ERROR:", mailErr);
      }
    }

    return res.json({ ok: true });

  } catch (err) {
    console.error("💥 RESET PASSWORD FATAL:", err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/auth/set-password", async (req, res) => {
  console.log("🔥 SET PASSWORD START");
  console.log("BODY RAW:", req.body);

  const { token, password } = req.body;

  console.log("TOKEN:", token);
  console.log("PASSWORD LENGTH:", password ? password.length : null);

  if (!token) {
    console.log("❌ TOKEN MISSING");
    return res.status(400).json({ error: "TOKEN MISSING" });
  }

  console.log("VERIFYING TOKEN...");
  console.log("JWT SECRET EXISTS:", !!process.env.JWT_SECRET);

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
    console.log("✅ TOKEN VALID:", payload);
  } catch (err) {
    console.error("💥 JWT ERROR:", err.message);
    return res.status(400).json({ error: "INVALID TOKEN", detail: err.message });
  }

  try {
    console.log("HASHING PASSWORD...");
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO AUTH_CREDENCIALES (IdAuth, PasswordHash) VALUES (?, ?) ON DUPLICATE KEY UPDATE PasswordHash = VALUES(PasswordHash)`,
      [payload.sub, hash]
    );
    console.log("PASSWORD SAVED OK");

    res.json({ ok: true });
  } catch (e) {
    console.error("💥 SET PASSWORD FATAL:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/auth/check-identidad", async (req, res) => {
  try {
    const { correo, tipoEntidad } = req.body;
    if (!correo || !tipoEntidad) {
      return res.status(400).json({ error: "correo y tipoEntidad requeridos" });
    }
    const [rows] = await pool.query(
      `SELECT c.IdAuth AS HasPassword FROM AUTH_IDENTIDADES i LEFT JOIN AUTH_CREDENCIALES c ON c.IdAuth = i.IdAuth WHERE i.Correo = ? AND i.TipoEntidad = ? AND i.Status = 'ACTIVO' LIMIT 1`,
      [correo, tipoEntidad]
    );
    if (rows.length > 0 && rows[0].HasPassword) {
      return res.json({ nextStep: "PASSWORD" });
    }
    return res.json({ nextStep: "SET_PASSWORD" });
  } catch (e) {
    return res.json({ nextStep: "SET_PASSWORD" });
  }
});

// 4️⃣ ERROR HANDLER - siempre al final
app.use((err, req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.status(500).json({ ok: false, error: err.message });
});

console.log("before listen");
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log("auth-api running on port", PORT));
