const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cors = require("cors");
const app = express();

const pool = require("./db");
const { login } = require("./auth");
const { sendSetPasswordEmail } = require("./mailer");

// 1️⃣ CORS - primero siempre v2
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(200).end();
  next();
});

// 2️⃣ Body parser - segundo
app.use(express.json());

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
  try {
    const { correo, tipoEntidad } = req.body;
    if (!correo || !tipoEntidad) return res.json({ ok: false });
    const [rows] = await pool.query(
      `SELECT IdAuth, TipoEntidad, IdEntidad FROM AUTH_IDENTIDADES WHERE Correo = ? AND TipoEntidad = ? AND Status = 'ACTIVO' LIMIT 1`,
      [correo, tipoEntidad]
    );
    if (rows.length > 0) {
      const identity = rows[0];
      const token = jwt.sign(
        { sub: identity.IdAuth, tipoEntidad: identity.TipoEntidad, idEntidad: identity.IdEntidad },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );
      await sendSetPasswordEmail(correo, token);
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error("reset-password technical error:", err);
    return res.status(500).json({ ok: false });
  }
});

app.post("/auth/set-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO AUTH_CREDENCIALES (IdAuth, PasswordHash) VALUES (?, ?) ON DUPLICATE KEY UPDATE PasswordHash = VALUES(PasswordHash)`,
      [payload.sub, hash]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "Token inválido o expirado" });
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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log("auth-api running on port", PORT));
