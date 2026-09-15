const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");
const requireInterno = require("../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

function permitirAlumnos(req, res) {
  if (!req.auth.modulos.includes("alumnos")) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de alumnos."
    });
    return false;
  }
  return true;
}

function texto(value) {
  const normalized = String(value ?? "").trim();
  return normalized || null;
}

function enteroPaginacion(value, fallback, min, max) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

router.get("/:id_alumno/asistencias", async (req, res) => {
  if (!permitirAlumnos(req, res)) return;

  const idAlumno = texto(req.params.id_alumno);
  if (!idAlumno) {
    return res.status(400).json({
      ok: false,
      code: "ALUMNO_REQUERIDO",
      message: "El alumno indicado no es válido."
    });
  }

  const limit = enteroPaginacion(req.query.limit, 20, 1, 100);
  const offset = enteroPaginacion(req.query.offset, 0, 0, 1000000);

  try {
    // Pedimos una fila extra para saber si hay siguiente página sin ejecutar COUNT(*).
    const [rows] = await pool.query(
      `
      SELECT
        v.IdDetalle,
        v.IdAsistenciaInterno,
        v.IdAsistencia,
        v.IdAlumno,
        v.Fecha,
        v.Presente,
        v.Justificada,
        v.ComentarioAlumno,
        (
          SELECT d.TituloComentario
          FROM DETALLE_ASISTENCIAS d
          WHERE d.IdDetalle = v.IdDetalle
          LIMIT 1
        ) AS TituloComentario,
        v.IdGrupo,
        v.Grupo,
        v.IdPlantel,
        v.Plantel,
        v.IdMaestroQueDioClase,
        v.Maestro,
        v.IdMaestroTitular,
        v.Titular,
        v.IdCurso,
        v.Curso,
        v.ColorCurso,
        v.Cap,
        v.Pagina
      FROM vw_company_viewer_asistencias v
      WHERE v.IdAlumno = ?
      ORDER BY v.Fecha DESC, v.IdDetalle DESC
      LIMIT ? OFFSET ?
      `,
      [idAlumno, limit + 1, offset]
    );

    const hasMore = rows.length > limit;
    const data = hasMore ? rows.slice(0, limit) : rows;

    return res.json({
      ok: true,
      data,
      pagination: {
        limit,
        offset,
        next_offset: hasMore ? offset + data.length : null,
        has_more: hasMore
      }
    });
  } catch (error) {
    console.error("[VIEWER ALUMNOS] Error consultando asistencias paginadas", {
      id_alumno: idAlumno,
      limit,
      offset,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_ASISTENCIAS_ALUMNO",
      message: "No pudimos consultar las asistencias de este alumno."
    });
  }
});

module.exports = router;
