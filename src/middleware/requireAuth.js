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

      const politica = PERMISOS.obtenerPolitica("PLANTEL");

      if (!politica) {
        throw new Error("POLITICA_INVALIDA");
      }

      // Permisos dinámicos solo para planteles; el catálogo no amplía los roles actuales.
      let modulosPlantel;
      try {
        const [permisosPlantel] = await pool.query(
          `
          SELECT pm.id_modulo
          FROM plantel_modulos pm
          INNER JOIN modulos m ON m.id_modulo = pm.id_modulo
          WHERE pm.id_plantel = ?
            AND pm.habilitado = 1
            AND m.activo = 1
          `,
          [rows[0].id_plantel]
        );

        const habilitados = new Set(permisosPlantel.map((permiso) => permiso.id_modulo));
        modulosPlantel = politica.modulos.filter((modulo) => habilitados.has(modulo));
      } catch (error) {
        console.error("[AUTH] Error consultando permisos del plantel", {
          id_plantel: rows[0].id_plantel,
          code: error?.code,
          message: error?.message
        });

        // No convertir una falla de SQL en 401: el frontend cerraría la sesión.
        return res.status(503).json({
          ok: false,
          code: "PERMISOS_NO_DISPONIBLES",
          message: "No pudimos validar tus permisos en este momento."
        });
      }

      req.auth = {
        tipo_usuario: "PLANTEL",
        id_plantel: rows[0].id_plantel,
        alcance: politica.alcance,
        acceso_global: politica.acceso_global,
        modulos: modulosPlantel,
        capacidades: politica.capacidades
      };

      return next();
    }

    // USUARIO INTERNO
    if (payload.tipo_usuario === "INTERNO") {
      const [rows] = await pool.query(
        `
        SELECT
          \`ID Usuario\` AS id_usuario,
          Rol AS rol,
          Correo AS correo
        FROM USUARIOS
        WHERE \`ID Usuario\` = ?
          AND Status = 'Activo'
          AND Rol IN ('Admin', 'Directivo', 'Maestro')
        LIMIT 1
        `,
        [payload.id_usuario]
      );

      if (!rows.length) {
        throw new Error("CUENTA_INVALIDA");
      }

      const usuario = rows[0];
      const politica = PERMISOS.obtenerPolitica(usuario.rol);

      if (!politica) {
        throw new Error("POLITICA_INVALIDA");
      }

      req.auth = {
        tipo_usuario: "INTERNO",
        id_usuario: usuario.id_usuario,
        correo: usuario.correo,
        rol: usuario.rol,
        alcance: politica.alcance,
        acceso_global: politica.acceso_global,
        modulos: politica.modulos,
        capacidades: politica.capacidades
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
