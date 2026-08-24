const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");
const requireInterno = require("../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

router.get("/", async (req, res) => {
  if (!req.auth.modulos.includes("seguimientos")) {
    return res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de seguimientos."
    });
  }

  try {
    const [rows] = await pool.query(
      `
      SELECT
        \`ID Usuario\` AS IdUsuario,
        CONCAT_WS(' ', Nombre, Apellidos) AS Nombre,
        Rol
      FROM USUARIOS
      WHERE Status = 'Activo'
        AND Rol IN ('Administrador', 'Directivo')
      ORDER BY Nombre ASC, Apellidos ASC
      `
    );

    return res.json({
      ok: true,
      data: rows
    });
  } catch (error) {
    console.error("[VIEWER USUARIOS INTERNOS] Error consultando", {
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_USUARIOS_INTERNOS",
      message: "No pudimos consultar los responsables disponibles."
    });
  }
});

module.exports = router;
