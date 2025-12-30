const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const pool = require("./db");
const { login } = require("./auth");

const app = express();
app.use(express.json());

/**
 * LOGIN ALUMNO
 */
app.post("/auth/login/alumno", async (req, res) => {
  try {
    const { correo, password } = req.body;
    const token = await login(correo, password, "ALUMNO");
    res.json({ token });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

/**
 * LOGIN USUARIO
 */
app.post("/auth/login/usuario", async (req, res) => {
  try {
    const { correo, password } = req.body;
    const token = await login(correo, password, "USUARIO");
    res.json({ token });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

/**
 * SYNC IDENTIDAD (AppSheet Bot)
 */
app.post("/auth/sync-identidad", async (req, res) => {
  const { correo, tipoEntidad, idEntidad } = req.body;
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const [rows] = await conn.query(
      `
      SELECT IdAuth
      FROM AUTH_IDENTIDADES
      WHERE TipoEntidad = ?
        AND IdEntidad = ?
      `,
      [tipoEntidad, idEntidad]
    );

    if (rows.length === 0) {
      const idAuth = crypto.randomUUID();
      await conn.query(
        `
        INSERT INTO AUTH_IDENTIDADES
        (IdAuth, Correo, TipoEntidad, IdEntidad)
        VALUES (?, ?, ?, ?)
        `,
        [idAuth, correo, tipoEntidad, idEntidad]
      );
    } else {
      await conn.query(
        `
        UPDATE AUTH_IDENTIDADES
        SET Correo = ?
        WHERE IdAuth = ?
        `,
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

/**
 * SET / RESET PASSWORD
 */
app.post("/auth/set-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      `
      INSERT INTO AUTH_CREDENCIALES (IdAuth, PasswordHash)
      VALUES (?, ?)
      ON DUPLICATE KEY UPDATE PasswordHash = VALUES(PasswordHash)
      `,
      [payload.sub, hash]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "Token inválido o expirado" });
  }
});

/**
 * ENTRY POINT CLOUD RUN (OBLIGATORIO)
 */
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("auth-api running on port", PORT);
});
