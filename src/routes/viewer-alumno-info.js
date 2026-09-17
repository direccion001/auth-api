const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

function puedeConsultarAlumno(req, res) {
  const permitidos = ["alumnos", "asistencias", "calificaciones"];
  if (!permitidos.some((modulo) => req.auth.modulos.includes(modulo))) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso a la ficha de alumnos."
    });
    return false;
  }
  return true;
}

router.get("/:id_alumno/info", async (req, res) => {
  if (!puedeConsultarAlumno(req, res)) return;

  const idAlumno = String(req.params.id_alumno || "").trim();
  if (!idAlumno) {
    return res.status(400).json({
      ok: false,
      code: "ALUMNO_REQUERIDO",
      message: "El alumno indicado no es válido."
    });
  }

  try {
    const params = [idAlumno];
    let sql = `
      SELECT
        a.IdAlumno,
        a.NombreAlumno,
        a.ApellidosAlumno,
        a.NombreCompleto,
        a.StatusAlumno,
        a.FechaRegistroAlumno,
        a.FechaBajaAlumno,
        a.FechaNacimiento,
        a.Edad,
        a.Telefono1,
        a.Correo,
        a.IdPlantel,
        a.Plantel,
        a.IdGrupo,
        a.Grupo,
        a.IdMaestroTitular,
        a.MaestroTitular,
        a.CursoActual,
        a.StatusPagos,
        a.SaludAsistencia
      FROM vw_company_viewer_alumnos a
      WHERE a.IdAlumno = ?
    `;

    if (!req.auth.acceso_global) {
      sql += " AND a.IdPlantel = ?";
      params.push(req.auth.id_plantel);
    }

    sql += " LIMIT 1";

    const [rows] = await pool.query(sql, params);
    if (!rows.length) {
      return res.status(404).json({
        ok: false,
        code: "ALUMNO_NO_ENCONTRADO",
        message: "No encontramos ese alumno dentro de tu alcance."
      });
    }

    return res.json({ ok: true, data: rows[0] });
  } catch (error) {
    console.error("[VIEWER ALUMNO INFO] Error consultando ficha", {
      id_usuario: req.auth?.id_usuario,
      id_alumno: idAlumno,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_ALUMNO",
      message: "No pudimos consultar la ficha del alumno."
    });
  }
});

module.exports = router;
