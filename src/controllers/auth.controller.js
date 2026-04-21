const pool = require("../db/pool");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const { login } = require("../services/auth.service");
const { sendSetPasswordEmail } = require("../mailers/mailer");

async function loginAlumno(req, res) {
  try {
    const { correo, password } = req.body;
    if (!correo || !password) return res.json({ ok: false });

    const token = await login(correo, password, "ALUMNO");
    return res.json({ ok: true, token });
  } catch {
    return res.json({ ok: false });
  }
}

async function loginUsuario(req, res) {
  try {
    const { correo, password } = req.body;
    if (!correo || !password) return res.json({ ok: false });

    const token = await login(correo, password, "USUARIO");
    return res.json({ ok: true, token });
  } catch {
    return res.json({ ok: false });
  }
}

async function syncIdentidad(req, res) {
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
}

async function resetPassword(req, res) {
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
    return res.status(500).json({ ok: false, error: err.message });
  }
}

async function setPassword(req, res) {
  const { token, password } = req.body;

  if (!token) {
    return res.status(400).json({ error: "TOKEN MISSING" });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(400).json({ error: "INVALID TOKEN" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO AUTH_CREDENCIALES (IdAuth, PasswordHash)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE PasswordHash = VALUES(PasswordHash)`,
      [payload.sub, hash]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

async function checkIdentidad(req, res) {
  try {
    const { correo, tipoEntidad } = req.body;

    const [rows] = await pool.query(
      `SELECT c.IdAuth AS HasPassword
       FROM AUTH_IDENTIDADES i
       LEFT JOIN AUTH_CREDENCIALES c ON c.IdAuth = i.IdAuth
       WHERE i.Correo = ? AND i.TipoEntidad = ? AND i.Status = 'ACTIVO' LIMIT 1`,
      [correo, tipoEntidad]
    );

    if (rows.length > 0 && rows[0].HasPassword) {
      return res.json({ nextStep: "PASSWORD" });
    }

    return res.json({ nextStep: "SET_PASSWORD" });

  } catch {
    return res.json({ nextStep: "SET_PASSWORD" });
  }
}

module.exports = {
  loginAlumno,
  loginUsuario,
  syncIdentidad,
  resetPassword,
  setPassword,
  checkIdentidad
};