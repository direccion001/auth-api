const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");
const requireInterno = require("../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

function permitirGraduaciones(req, res) {
  if (!req.auth.modulos.includes("graduaciones")) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de graduaciones."
    });
    return false;
  }
  return true;
}

router.get("/opciones", async (req, res) => {
  if (!permitirGraduaciones(req, res)) return;

  try {
    const [grupos, cursos, maestros, administrativos] = await Promise.all([
      pool.query(`
        SELECT
          g.IdGrupo,
          g.NombreGrupo AS Grupo,
          g.IdPlantel,
          p.NombrePlantel AS Plantel,
          g.IdMaestroTitular,
          CONCAT_WS(' ', u.Nombre, u.Apellidos) AS MaestroTitular,
          g.Modalidad,
          g.\`DíasClase\` AS DiasClase,
          g.HoraInicio,
          g.HoraFin
        FROM GRUPOS g
        LEFT JOIN PLANTELES p ON p.IdPlantel = g.IdPlantel
        LEFT JOIN USUARIOS u ON u.\`ID Usuario\` = g.IdMaestroTitular
        WHERE g.Status = 'Activo'
        ORDER BY p.NombrePlantel ASC, g.NombreGrupo ASC
      `),
      pool.query(`
        SELECT
          \`ID CURSO\` AS IdCurso,
          Nombre AS Curso,
          Color AS ColorCurso
        FROM CURSOS
        WHERE Status = 'Activo'
        ORDER BY Nombre ASC
      `),
      pool.query(`
        SELECT
          \`ID Usuario\` AS IdUsuario,
          CONCAT_WS(' ', Nombre, Apellidos) AS Nombre
        FROM USUARIOS
        WHERE Status = 'Activo'
          AND Rol = 'Maestro'
        ORDER BY Nombre ASC, Apellidos ASC
      `),
      pool.query(`
        SELECT
          \`ID Usuario\` AS IdUsuario,
          CONCAT_WS(' ', Nombre, Apellidos) AS Nombre,
          Rol
        FROM USUARIOS
        WHERE Status = 'Activo'
          AND Rol IN ('Admin', 'Administrador', 'Directivo')
        ORDER BY Nombre ASC, Apellidos ASC
      `)
    ]);

    return res.json({
      ok: true,
      data: {
        grupos: grupos[0],
        cursos: cursos[0],
        maestros: maestros[0],
        administrativos: administrativos[0],
        calidades: ["Baja", "Buena", "Muy buena"]
      }
    });
  } catch (error) {
    console.error("[VIEWER GRADUACIONES] Error consultando opciones", {
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_OPCIONES_GRADUACIONES",
      message: "No pudimos consultar las opciones de graduaciones."
    });
  }
});

module.exports = router;
