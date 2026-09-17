const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

function permitirCalificaciones(req, res) {
  const permitido =
    req.auth.modulos.includes("alumnos") ||
    req.auth.modulos.includes("calificaciones");

  if (!permitido) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al historial de calificaciones."
    });
    return false;
  }
  return true;
}

function texto(value) {
  const normalized = String(value ?? "").trim();
  return normalized || null;
}

router.get("/:id_alumno/calificaciones", async (req, res) => {
  if (!permitirCalificaciones(req, res)) return;

  const idAlumno = texto(req.params.id_alumno);
  if (!idAlumno) {
    return res.status(400).json({
      ok: false,
      code: "ALUMNO_REQUERIDO",
      message: "El alumno indicado no es válido."
    });
  }

  try {
    const params = [idAlumno];
    let scope = "";
    if (!req.auth.acceso_global) {
      scope = " AND c.IdPlantel = ?";
      params.push(req.auth.id_plantel);
    }

    const [rows] = await pool.query(
      `
      SELECT c.*
      FROM vw_company_viewer_calificaciones c
      WHERE c.IdAlumno = ?
        ${scope}
        AND c.Calificacion IS NOT NULL
        AND c.IdCurso IS NOT NULL
      ORDER BY c.FechaCalificacion ASC, c.IdCurso ASC, c.Modulo ASC
      `,
      params
    );

    return res.json({ ok: true, data: rows });
  } catch (error) {
    console.error("[VIEWER ALUMNOS] Error consultando calificaciones", {
      id_alumno: idAlumno,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_CALIFICACIONES_ALUMNO",
      message: "No pudimos consultar las calificaciones de este alumno."
    });
  }
});

module.exports = router;
