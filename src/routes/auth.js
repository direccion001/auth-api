const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const pool = require("../db/pool");
const { sendEmail } = require("../mail/mailer");

const router = express.Router();

const SALT_ROUNDS = 10;
const TOKEN_EXPIRATION_MINUTES = 30;
const JWT_EXPIRATION = "12h";

const requireAuth = require("../middleware/requireAuth");


// ======================================================
// Helpers
// ======================================================

function normalizarCorreo(correo) {
  return String(correo || "").trim().toLowerCase();
}

function generarTokenTemporal() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function fechaExpiracionToken() {
  return new Date(Date.now() + TOKEN_EXPIRATION_MINUTES * 60 * 1000);
}

function validarPassword(password) {
  return typeof password === "string" && password.length >= 6;
}

function respuestaError(res, status, message, code = "AUTH_ERROR") {
  return res.status(status).json({
    ok: false,
    code,
    message
  });
}

function logInfo(evento, data = {}) {
  console.log(`[AUTH] ${evento}`, data);
}

function logError(evento, error, data = {}) {
  console.error(`[AUTH ERROR] ${evento}`, {
    ...data,
    message: error?.message,
    code: error?.code
  });
}

function crearJWT(usuario) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET no está configurado.");
  }

  const payload =
    usuario.tipo_usuario === "PLANTEL"
      ? {
          tipo_usuario: "PLANTEL",
          id_auth: usuario.id_auth,
          id_plantel: usuario.id_plantel,
          correo: usuario.correo
        }
      : {
          tipo_usuario: "INTERNO",
          id_usuario: usuario.id_usuario,
          rol: usuario.rol,
          correo: usuario.correo
        };

  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: JWT_EXPIRATION
  });
}


// ======================================================
// Buscar cuenta autorizada por correo
// ======================================================

async function buscarCuentaPorCorreo(correo) {

  // Primero: cliente / plantel
  const [planteles] = await pool.query(
    `
    SELECT
      p.IdPlantel,
      p.CorreoCliente,
      a.id_auth,
      a.password_hash
    FROM PLANTELES p
    LEFT JOIN auth_planteles a
      ON a.id_plantel = p.IdPlantel
    WHERE LOWER(TRIM(p.CorreoCliente)) = ?
    LIMIT 1
    `,
    [correo]
  );

  if (planteles.length) {
    return {
      tipo_usuario: "PLANTEL",
      id_plantel: planteles[0].IdPlantel,
      id_auth: planteles[0].id_auth,
      correo,
      password_hash: planteles[0].password_hash
    };
  }

  // Después: usuario interno
  const [usuarios] = await pool.query(
    `
    SELECT
      \`ID Usuario\` AS id_usuario,
      Correo AS correo,
      Rol AS rol,
      Status AS status,
      password_hash
    FROM USUARIOS
    WHERE LOWER(TRIM(Correo)) = ?
      AND Rol IN ('Administrador', 'Directivo')
      AND Status = 'Activo'
    LIMIT 1
    `,
    [correo]
  );

  if (usuarios.length) {
    return {
      tipo_usuario: "INTERNO",
      ...usuarios[0]
    };
  }

  return null;
}


// ======================================================
// POST /auth/email-establecer
// ======================================================

router.post("/email-establecer", async (req, res) => {

  const correo = normalizarCorreo(req.body?.correo);

  if (!correo) {
    return respuestaError(
      res,
      400,
      "Ingresa tu correo electrónico.",
      "CORREO_REQUERIDO"
    );
  }

  try {

    const cuenta = await buscarCuentaPorCorreo(correo);

    if (!cuenta) {
      return res.json({
        ok: true,
        message:
          "Si el correo está registrado, recibirás un enlace para establecer tu contraseña."
      });
    }

    if (cuenta.password_hash) {
      return respuestaError(
        res,
        409,
        "Esta cuenta ya tiene una contraseña. Utiliza restablecer contraseña.",
        "CUENTA_YA_ACTIVADA"
      );
    }

    const token = generarTokenTemporal();
    const tokenHash = hashToken(token);
    const expira = fechaExpiracionToken();

    if (cuenta.tipo_usuario === "PLANTEL") {

      if (!cuenta.id_auth) {
        await pool.query(
          `
          INSERT INTO auth_planteles (
            id_plantel,
            correo,
            token_temporal_hash,
            token_tipo,
            token_expira,
            activo
          )
          VALUES (?, ?, ?, 'ACTIVACION', ?, 1)
          `,
          [
            cuenta.id_plantel,
            correo,
            tokenHash,
            expira
          ]
        );
      } else {
        await pool.query(
          `
          UPDATE auth_planteles
          SET
            token_temporal_hash = ?,
            token_tipo = 'ACTIVACION',
            token_expira = ?
          WHERE id_auth = ?
          `,
          [
            tokenHash,
            expira,
            cuenta.id_auth
          ]
        );
      }

    } else {

      await pool.query(
        `
        UPDATE USUARIOS
        SET
          token_temporal_hash = ?,
          token_tipo = 'ACTIVACION',
          token_expira = ?
        WHERE \`ID Usuario\` = ?
        `,
        [
          tokenHash,
          expira,
          cuenta.id_usuario
        ]
      );
    }

    const frontendUrl = process.env.FRONTEND_URL;

    if (!frontendUrl) {
      throw new Error("FRONTEND_URL no está configurado.");
    }

    const link =
      `${frontendUrl.replace(/\/$/, "")}` +
      `/establecer-password?token=${encodeURIComponent(token)}`;

    await sendEmail({
      to: correo,
      subject: "Crea tu contraseña",
      templateName: "set-password.html",
      variables: { LINK: link }
    });

    logInfo("Correo de activación enviado", {
      correo,
      tipo_usuario: cuenta.tipo_usuario
    });

    return res.json({
      ok: true,
      message:
        "Te enviamos un enlace a tu correo para crear tu contraseña."
    });

  } catch (error) {

    logError("Falló email-establecer", error, { correo });

    return respuestaError(
      res,
      500,
      "No pudimos enviar el correo en este momento.",
      "ERROR_ENVIANDO_CORREO"
    );
  }
});


// ======================================================
// POST /auth/establecer-password
// ======================================================

router.post("/establecer-password", async (req, res) => {

  const token = String(req.body?.token || "").trim();
  const password = req.body?.password;

  if (!token) {
    return respuestaError(res, 400, "El enlace no es válido.", "TOKEN_REQUERIDO");
  }

  if (!validarPassword(password)) {
    return respuestaError(
      res,
      400,
      "La contraseña debe tener al menos 6 caracteres.",
      "PASSWORD_INVALIDO"
    );
  }

  try {

    const tokenHash = hashToken(token);

    const [planteles] = await pool.query(
      `
      SELECT id_auth, token_expira, activo
      FROM auth_planteles
      WHERE token_temporal_hash = ?
        AND token_tipo = 'ACTIVACION'
      LIMIT 1
      `,
      [tokenHash]
    );

    let tipo = null;
    let cuenta = null;

    if (planteles.length) {
      tipo = "PLANTEL";
      cuenta = planteles[0];
    } else {

      const [usuarios] = await pool.query(
        `
        SELECT
          \`ID Usuario\` AS id_usuario,
          token_expira
        FROM USUARIOS
        WHERE token_temporal_hash = ?
          AND token_tipo = 'ACTIVACION'
          AND Rol IN ('Administrador', 'Directivo')
          AND Status = 'Activo'
        LIMIT 1
        `,
        [tokenHash]
      );

      if (usuarios.length) {
        tipo = "INTERNO";
        cuenta = usuarios[0];
      }
    }

    if (!cuenta) {
      return respuestaError(
        res,
        400,
        "Este enlace no es válido o ya fue utilizado.",
        "TOKEN_INVALIDO"
      );
    }

    if (
      !cuenta.token_expira ||
      new Date(cuenta.token_expira).getTime() < Date.now()
    ) {
      return respuestaError(
        res,
        400,
        "Este enlace ya expiró. Solicita uno nuevo.",
        "TOKEN_EXPIRADO"
      );
    }

    if (tipo === "PLANTEL" && !cuenta.activo) {
      return respuestaError(
        res,
        403,
        "Esta cuenta no está activa.",
        "CUENTA_INACTIVA"
      );
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    if (tipo === "PLANTEL") {

      await pool.query(
        `
        UPDATE auth_planteles
        SET
          password_hash = ?,
          token_temporal_hash = NULL,
          token_tipo = NULL,
          token_expira = NULL
        WHERE id_auth = ?
        `,
        [passwordHash, cuenta.id_auth]
      );

    } else {

      await pool.query(
        `
        UPDATE USUARIOS
        SET
          password_hash = ?,
          token_temporal_hash = NULL,
          token_tipo = NULL,
          token_expira = NULL
        WHERE \`ID Usuario\` = ?
        `,
        [passwordHash, cuenta.id_usuario]
      );
    }

    return res.json({
      ok: true,
      message:
        "Tu contraseña fue creada correctamente. Ya puedes iniciar sesión."
    });

  } catch (error) {

    logError("Falló establecer-password", error);

    return respuestaError(
      res,
      500,
      "No pudimos guardar tu contraseña.",
      "ERROR_ESTABLECIENDO_PASSWORD"
    );
  }
});


// ======================================================
// POST /auth/login
// ======================================================

router.post("/login", async (req, res) => {

  const correo = normalizarCorreo(req.body?.correo);
  const password = req.body?.password;

  if (!correo || !password) {
    return respuestaError(
      res,
      400,
      "Ingresa tu correo y contraseña.",
      "CREDENCIALES_REQUERIDAS"
    );
  }

  try {

    const cuenta = await buscarCuentaPorCorreo(correo);

    if (!cuenta || !cuenta.password_hash) {
      return respuestaError(
        res,
        401,
        "El correo o la contraseña no son correctos.",
        "CREDENCIALES_INVALIDAS"
      );
    }

    const coincide = await bcrypt.compare(
      password,
      cuenta.password_hash
    );

    if (!coincide) {
      return respuestaError(
        res,
        401,
        "El correo o la contraseña no son correctos.",
        "CREDENCIALES_INVALIDAS"
      );
    }

    const token = crearJWT(cuenta);

    logInfo("Login correcto", {
      correo,
      tipo_usuario: cuenta.tipo_usuario
    });

    return res.json({
      ok: true,
      message: "Sesión iniciada correctamente.",
      token,
      usuario: {
        tipo_usuario: cuenta.tipo_usuario,
        correo: cuenta.correo,
        id_plantel:
          cuenta.tipo_usuario === "PLANTEL"
            ? cuenta.id_plantel
            : null,
        rol:
          cuenta.tipo_usuario === "INTERNO"
            ? cuenta.rol
            : null
      }
    });

  } catch (error) {

    logError("Falló login", error, { correo });

    return respuestaError(
      res,
      500,
      "No pudimos iniciar sesión en este momento.",
      "ERROR_LOGIN"
    );
  }
});


// ======================================================
// POST /auth/email-restablecer
// ======================================================

router.post("/email-restablecer", async (req, res) => {

  const correo = normalizarCorreo(req.body?.correo);

  if (!correo) {
    return respuestaError(
      res,
      400,
      "Ingresa tu correo electrónico.",
      "CORREO_REQUERIDO"
    );
  }

  try {

    const cuenta = await buscarCuentaPorCorreo(correo);

    const respuestaGenerica = {
      ok: true,
      message:
        "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña."
    };

    if (!cuenta || !cuenta.password_hash) {
      return res.json(respuestaGenerica);
    }

    const token = generarTokenTemporal();
    const tokenHash = hashToken(token);
    const expira = fechaExpiracionToken();

    if (cuenta.tipo_usuario === "PLANTEL") {

      await pool.query(
        `
        UPDATE auth_planteles
        SET
          token_temporal_hash = ?,
          token_tipo = 'RESET',
          token_expira = ?
        WHERE id_auth = ?
        `,
        [tokenHash, expira, cuenta.id_auth]
      );

    } else {

      await pool.query(
        `
        UPDATE USUARIOS
        SET
          token_temporal_hash = ?,
          token_tipo = 'RESET',
          token_expira = ?
        WHERE \`ID Usuario\` = ?
        `,
        [tokenHash, expira, cuenta.id_usuario]
      );
    }

    const frontendUrl = process.env.FRONTEND_URL;

    if (!frontendUrl) {
      throw new Error("FRONTEND_URL no está configurado.");
    }

    const link =
      `${frontendUrl.replace(/\/$/, "")}` +
      `/restablecer-password?token=${encodeURIComponent(token)}`;

    await sendEmail({
      to: correo,
      subject: "Restablece tu contraseña",
      templateName: "reset-password.html",
      variables: { LINK: link }
    });

    return res.json(respuestaGenerica);

  } catch (error) {

    logError("Falló email-restablecer", error, { correo });

    return respuestaError(
      res,
      500,
      "No pudimos procesar la solicitud.",
      "ERROR_RESTABLECIENDO"
    );
  }
});


// ======================================================
// POST /auth/restablecer-password
// ======================================================

router.post("/restablecer-password", async (req, res) => {

  const token = String(req.body?.token || "").trim();
  const password = req.body?.password;

  if (!token) {
    return respuestaError(res, 400, "El enlace no es válido.", "TOKEN_REQUERIDO");
  }

  if (!validarPassword(password)) {
    return respuestaError(
      res,
      400,
      "La contraseña debe tener al menos 6 caracteres.",
      "PASSWORD_INVALIDO"
    );
  }

  try {

    const tokenHash = hashToken(token);

    const [planteles] = await pool.query(
      `
      SELECT id_auth, token_expira, activo
      FROM auth_planteles
      WHERE token_temporal_hash = ?
        AND token_tipo = 'RESET'
      LIMIT 1
      `,
      [tokenHash]
    );

    let tipo = null;
    let cuenta = null;

    if (planteles.length) {
      tipo = "PLANTEL";
      cuenta = planteles[0];
    } else {

      const [usuarios] = await pool.query(
        `
        SELECT
          \`ID Usuario\` AS id_usuario,
          token_expira
        FROM USUARIOS
        WHERE token_temporal_hash = ?
          AND token_tipo = 'RESET'
          AND Rol IN ('Administrador', 'Directivo')
          AND Status = 'Activo'
        LIMIT 1
        `,
        [tokenHash]
      );

      if (usuarios.length) {
        tipo = "INTERNO";
        cuenta = usuarios[0];
      }
    }

    if (!cuenta) {
      return respuestaError(
        res,
        400,
        "Este enlace no es válido o ya fue utilizado.",
        "TOKEN_INVALIDO"
      );
    }

    if (
      !cuenta.token_expira ||
      new Date(cuenta.token_expira).getTime() < Date.now()
    ) {
      return respuestaError(
        res,
        400,
        "Este enlace ya expiró. Solicita uno nuevo.",
        "TOKEN_EXPIRADO"
      );
    }

    if (tipo === "PLANTEL" && !cuenta.activo) {
      return respuestaError(
        res,
        403,
        "Esta cuenta no está activa.",
        "CUENTA_INACTIVA"
      );
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    if (tipo === "PLANTEL") {

      await pool.query(
        `
        UPDATE auth_planteles
        SET
          password_hash = ?,
          token_temporal_hash = NULL,
          token_tipo = NULL,
          token_expira = NULL
        WHERE id_auth = ?
        `,
        [passwordHash, cuenta.id_auth]
      );

    } else {

      await pool.query(
        `
        UPDATE USUARIOS
        SET
          password_hash = ?,
          token_temporal_hash = NULL,
          token_tipo = NULL,
          token_expira = NULL
        WHERE \`ID Usuario\` = ?
        `,
        [passwordHash, cuenta.id_usuario]
      );
    }

    return res.json({
      ok: true,
      message:
        "Tu contraseña se actualizó correctamente. Ya puedes iniciar sesión."
    });

  } catch (error) {

    logError("Falló restablecer-password", error);

    return respuestaError(
      res,
      500,
      "No pudimos actualizar tu contraseña.",
      "ERROR_CAMBIANDO_PASSWORD"
    );
  }
});

// ======================================================
// GET /auth/me
// ======================================================

router.get("/me", requireAuth, async (req, res) => {
  return res.json({
    ok: true,
    usuario: {
      tipo_usuario: req.auth.tipo_usuario,
      id_plantel: req.auth.id_plantel || null,
      id_usuario: req.auth.id_usuario || null,
      rol: req.auth.rol || null,
      acceso_global: req.auth.acceso_global,
      modulos: req.auth.modulos
    }
  });
});


module.exports = router;