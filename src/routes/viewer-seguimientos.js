const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

function permitirSeguimientos(req, res) {
  if (!req.auth.modulos.includes("seguimientos")) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de seguimientos."
    });
    return false;
  }

  return true;
}

function agregarSeguimientoPropio(row, req) {
  return {
    ...row,
    SeguimientoPropio:
      req.auth.tipo_usuario === "INTERNO" &&
      row.IdUsuarioResponsable != null &&
      String(row.IdUsuarioResponsable) === String(req.auth.id_usuario)
  };
}

function alcancePlantel(req, alias, params) {
  if (req.auth.acceso_global) return "";

  params.push(req.auth.id_plantel);
  return ` AND ${alias}.IdPlantel = ?`;
}

// ======================================================
// GET /viewer/seguimientos
// Todos los tickets permitidos por el alcance del usuario.
// Por ahora solo INTERNO tiene el permiso "seguimientos".
// ======================================================

router.get("/", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  try {
    const params = [];

    let sql = `
      SELECT *
      FROM vw_company_viewer_alumnos_seguimiento s
      WHERE 1 = 1
    `;

    // No es un filtro del frontend: es el alcance de seguridad preparado
    // para el día que PLANTEL pueda consultar este módulo.
    sql += alcancePlantel(req, "s", params);
    sql += " ORDER BY s.FechaApertura DESC, s.id_seguimiento DESC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows.map((row) => agregarSeguimientoPropio(row, req))
    });
  } catch (error) {
    console.error("[VIEWER SEGUIMIENTOS] Error consultando", {
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_SEGUIMIENTOS",
      message: "No pudimos consultar los seguimientos."
    });
  }
});

// ======================================================
// GET /viewer/seguimientos/alumno/:id_alumno
// Cabeceras/tickets del alumno. No descarga timelines.
// ======================================================

router.get("/alumno/:id_alumno", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

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
      SELECT *
      FROM vw_company_viewer_alumnos_seguimiento s
      WHERE s.IdAlumno = ?
    `;

    sql += alcancePlantel(req, "s", params);
    sql += " ORDER BY s.FechaApertura DESC, s.id_seguimiento DESC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows.map((row) => agregarSeguimientoPropio(row, req))
    });
  } catch (error) {
    console.error("[VIEWER SEGUIMIENTOS] Error consultando alumno", {
      id_alumno: idAlumno,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_SEGUIMIENTOS_ALUMNO",
      message: "No pudimos consultar los seguimientos de este alumno."
    });
  }
});

// ======================================================
// GET /viewer/seguimientos/:id_seguimiento/detalles
// Timeline de un ticket específico.
// ======================================================

router.get("/:id_seguimiento/detalles", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  const idSeguimiento = String(req.params.id_seguimiento || "").trim();

  if (!idSeguimiento) {
    return res.status(400).json({
      ok: false,
      code: "SEGUIMIENTO_REQUERIDO",
      message: "El seguimiento indicado no es válido."
    });
  }

  try {
    const accesoParams = [idSeguimiento];

    let accesoSql = `
      SELECT s.id_seguimiento
      FROM vw_company_viewer_alumnos_seguimiento s
      WHERE s.id_seguimiento = ?
    `;

    accesoSql += alcancePlantel(req, "s", accesoParams);
    accesoSql += " LIMIT 1";

    const [seguimientos] = await pool.query(accesoSql, accesoParams);

    if (!seguimientos.length) {
      return res.status(404).json({
        ok: false,
        code: "SEGUIMIENTO_NO_ENCONTRADO",
        message: "No encontramos ese seguimiento."
      });
    }

    const [rows] = await pool.query(
      `
      SELECT *
      FROM vw_company_viewer_alumnos_seguimiento_detalle
      WHERE id_seguimiento = ?
      ORDER BY FechaRegistro DESC, id_detalle DESC
      `,
      [idSeguimiento]
    );

    return res.json({
      ok: true,
      data: rows
    });
  } catch (error) {
    console.error("[VIEWER SEGUIMIENTOS] Error consultando detalles", {
      id_seguimiento: idSeguimiento,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_DETALLES_SEGUIMIENTO",
      message: "No pudimos consultar el historial de este seguimiento."
    });
  }
});

module.exports = router;
