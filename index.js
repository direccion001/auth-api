const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cors = require("cors");

const pool = require("./db");
const { login } = require("./auth");
const { sendSetPasswordEmail } = require("./mailer"); // ✅ IMPORTANTE

const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

/**
 * LOGIN ALUMNO
 */
app.post("/auth/login/alumno", async (req, res) => {
  try {
    const { correo, password } = req.body;

    if (!correo || !password) {
      return res.json({ ok: false });
    }

    const token = await login(correo, password, "ALUMNO");
    return res.json({ ok: true, token });

  } catch {
    return res.json({ ok: false });
  }
});


/**
 * LOGIN USUARIO
 */
app.post("/auth/login/usuario", async (req, res) => {
  try {
    const { correo, password } = req.body;

    if (!correo || !password) {
      return res.json({ ok: false });
    }

    const token = await login(correo, password, "USUARIO");
    return res.json({ ok: true, token });

  } catch {
    return res.json({ ok: false });
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
 * RESET PASSWORD (envia link al correo)
 * - 200 ok:true → procesado (exista o no el correo)
 * - 200 ok:false → request inválido
 * - 500 ok:false → error técnico real
 */
app.post("/auth/reset-password", async (req, res) => {
  try {
    const { correo, tipoEntidad } = req.body;

    // ❗ Error de UX (no técnico)
    if (!correo || !tipoEntidad) {
      return res.json({ ok: false });
    }

    const [rows] = await pool.query(
      `
      SELECT IdAuth, TipoEntidad, IdEntidad
      FROM AUTH_IDENTIDADES
      WHERE Correo = ?
        AND TipoEntidad = ?
        AND Status = 'ACTIVO'
      LIMIT 1
      `,
      [correo, tipoEntidad]
    );

    // 🔐 No revelar existencia
    if (rows.length > 0) {
      const identity = rows[0];

      const token = jwt.sign(
        {
          sub: identity.IdAuth,
          tipoEntidad: identity.TipoEntidad,
          idEntidad: identity.IdEntidad
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      await sendSetPasswordEmail(correo, token);
    }

    // ✅ Siempre OK si el sistema funcionó
    return res.json({ ok: true });

  } catch (err) {
    // ❌ Error técnico real
    console.error("reset-password technical error:", err);
    return res.status(500).json({ ok: false });
  }
});

/**
 * SET PASSWORD
 * Usa el token para guardar la contraseña
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
 * CHECK IDENTIDAD (Pre-login WeWeb)
 * Contrato seguro: no revela existencia
 */
app.post("/auth/check-identidad", async (req, res) => {
  try {
    const { correo, tipoEntidad } = req.body;

    if (!correo || !tipoEntidad) {
      return res.status(400).json({
        error: "correo y tipoEntidad requeridos"
      });
    }

    const [rows] = await pool.query(
      `
      SELECT c.IdAuth AS HasPassword
      FROM AUTH_IDENTIDADES i
      LEFT JOIN AUTH_CREDENCIALES c ON c.IdAuth = i.IdAuth
      WHERE i.Correo = ?
        AND i.TipoEntidad = ?
        AND i.Status = 'ACTIVO'
      LIMIT 1
      `,
      [correo, tipoEntidad]
    );

    // 🔐 Contrato cerrado: solo dos respuestas posibles
    if (rows.length > 0 && rows[0].HasPassword) {
      return res.json({ nextStep: "PASSWORD" });
    }

    return res.json({ nextStep: "SET_PASSWORD" });

  } catch (e) {
    // Respuesta segura por defecto
    return res.json({ nextStep: "SET_PASSWORD" });
  }
});

/**
 * ENTRY POINT CLOUD RUN
 */
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("auth-api running on port", PORT);
});


