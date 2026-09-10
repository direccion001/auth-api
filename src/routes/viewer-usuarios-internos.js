const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");
const requireInterno = require("../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

router.get("/", async (req, res) => {
  try {
    const params = [];

    let sql = `
      SELECT
        \`ID Usuario\` AS IdUsuario,
        CONCAT_WS(' ', Nombre, Apellidos) AS Nombre,
        Rol
      FROM USUARIOS
      WHERE Status = 'Activo'
        AND Rol IN ('Admin', 'Directivo')
    `;

    const rol = String(req.query?.rol || "").trim();

    if (rol) {
      if (!['Admin', 'Directivo'].includes(rol)) {
        return res.status(400).json({
          ok: false,
          code: "ROL_NO_PERMITIDO",
          message: "Solo pueden seleccionarse Admin o Directivo."
        });
      }

      sql += " AND Rol = ?";
      params.push(rol);
    }

    sql += " ORDER BY Nombre ASC, Apellidos ASC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows
    });
  } catch (error) {
    console.error("[VIEWER USUARIOS INTERNOS] Error consultando", {
      id_usuario: req.auth?.id_usuario,
      rol: req.query?.rol || null,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_USUARIOS_INTERNOS",
      message: "No pudimos consultar los usuarios internos disponibles."
    });
  }
});

module.exports = router;
