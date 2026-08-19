const jwt = require("jsonwebtoken");
const pool = require("../db/pool");
const PERMISOS = require("../config/permisos");

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        code: "TOKEN_REQUERIDO",
        message: "Inicia sesión para continuar."
      });
    }

    const token = header.slice(7);
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // CLIENTE / PLANTEL
    if (payload.tipo_usuario === "PLANTEL") {
      const [rows] = await pool.query(
        `
        SELECT a.id_auth, a.id_plantel, a.correo
        FROM auth_planteles a
        INNER JOIN PLANTELES p
          ON p.IdPlantel = a.id_plantel
        WHERE a.id_auth = ?
          AND a.activo = 1
          AND p.Status = 'Activo'
          AND LOWER(TRIM(p.CorreoCliente)) = a.correo
        LIMIT 1
        `,
        [payload.id_auth]
      );

      if (!rows.length) {
        throw new Error("CUENTA_INVALIDA");
      }

      req.auth = {
        tipo_usuario: "PLANTEL",
        id_plantel: rows[0].id_plantel,
        acceso_global: false,
        modulos: PERMISOS.PLANTEL
      };

      return next();
    }

    // USUARIO INTERNO
    if (payload.tipo_usuario === "INTERNO") {
      const [rows] = await pool.query(
        `
        SELECT
          \`ID Usuario\` AS id_usuario,
          Rol AS rol
        FROM USUARIOS
        WHERE \`ID Usuario\` = ?
          AND Status = 'Activo'
          AND Rol IN ('Administrador', 'Directivo')
        LIMIT 1
        `,
        [payload.id_usuario]
      );

      if (!rows.length) {
        throw new Error("CUENTA_INVALIDA");
      }

      const usuario = rows[0];

      req.auth = {
        tipo_usuario: "INTERNO",
        id_usuario: usuario.id_usuario,
        rol: usuario.rol,
        acceso_global: true,
        modulos: PERMISOS[usuario.rol] || []
      };

      return next();
    }

    throw new Error("TIPO_INVALIDO");

  } catch (error) {
    return res.status(401).json({
      ok: false,
      code: "SESION_INVALIDA",
      message: "Tu sesión no es válida o ha expirado."
    });
  }
}

module.exports = requireAuth;