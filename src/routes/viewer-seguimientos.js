const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

function tieneModuloSeguimientos(req) {
  return req.auth.modulos.includes("seguimientos");
}

function permitirSeguimientos(req, res) {
  if (!tieneModuloSeguimientos(req)) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de seguimientos."
    });
    return false;
  }
  return true;
}

function permitirFichaAlumno(req, res) {
  const permitidos = ["alumnos", "asistencias", "calificaciones", "seguimientos"];
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

function visibilidadSeguimiento(req, aliasCabecera = "sh") {
  return req.auth.tipo_usuario === "PLANTEL"
    ? ` AND COALESCE(${aliasCabecera}.VisiblePlantel, 1) = 1`
    : "";
}

router.get("/", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  try {
    const params = [];
    let sql = `
      SELECT s.*, sh.VisiblePlantel
      FROM vw_company_viewer_alumnos_seguimiento s
      INNER JOIN alumnos_seguimientos sh
        ON sh.id_seguimiento = s.id_seguimiento
      WHERE 1 = 1
    `;

    sql += alcancePlantel(req, "s", params);
    sql += visibilidadSeguimiento(req, "sh");
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

// Devuelve la misma ficha base que consume el drawer unificado.
// No exige el módulo seguimientos: si el usuario puede consultar al alumno
// pero no tiene seguimientos, simplemente devuelve seguimientos: [].
router.get("/alumno/:id_alumno", async (req, res) => {
  if (!permitirFichaAlumno(req, res)) return;

  const idAlumno = String(req.params.id_alumno || "").trim();
  if (!idAlumno) {
    return res.status(400).json({
      ok: false,
      code: "ALUMNO_REQUERIDO",
      message: "El alumno indicado no es válido."
    });
  }

  try {
    const alumnoParams = [idAlumno];
    let alumnoSql = `
      SELECT *
      FROM vw_company_viewer_alumnos a
      WHERE a.IdAlumno = ?
    `;
    alumnoSql += alcancePlantel(req, "a", alumnoParams);
    alumnoSql += " LIMIT 1";

    const [alumnos] = await pool.query(alumnoSql, alumnoParams);
    if (!alumnos.length) {
      return res.status(404).json({
        ok: false,
        code: "ALUMNO_NO_ENCONTRADO",
        message: "No encontramos ese alumno."
      });
    }

    let seguimientos = [];
    if (tieneModuloSeguimientos(req)) {
      const seguimientoParams = [idAlumno];
      let seguimientoSql = `
        SELECT s.*, sh.VisiblePlantel
        FROM vw_company_viewer_alumnos_seguimiento s
        INNER JOIN alumnos_seguimientos sh
          ON sh.id_seguimiento = s.id_seguimiento
        WHERE s.IdAlumno = ?
      `;
      seguimientoSql += alcancePlantel(req, "s", seguimientoParams);
      seguimientoSql += visibilidadSeguimiento(req, "sh");
      seguimientoSql += " ORDER BY s.FechaApertura DESC, s.id_seguimiento DESC";

      const [rows] = await pool.query(seguimientoSql, seguimientoParams);
      seguimientos = rows.map((row) => agregarSeguimientoPropio(row, req));
    }

    return res.json({
      ok: true,
      data: {
        alumno: alumnos[0],
        seguimientos
      }
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
      message: "No pudimos consultar la ficha de este alumno."
    });
  }
});

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
      INNER JOIN alumnos_seguimientos sh
        ON sh.id_seguimiento = s.id_seguimiento
      WHERE s.id_seguimiento = ?
    `;
    accesoSql += alcancePlantel(req, "s", accesoParams);
    accesoSql += visibilidadSeguimiento(req, "sh");
    accesoSql += " LIMIT 1";

    const [seguimientos] = await pool.query(accesoSql, accesoParams);
    if (!seguimientos.length) {
      return res.status(404).json({
        ok: false,
        code: "SEGUIMIENTO_NO_ENCONTRADO",
        message: "No encontramos ese seguimiento."
      });
    }

    const detalleParams = [idSeguimiento];
    let detalleSql = `
      SELECT *
      FROM vw_company_viewer_alumnos_seguimiento_detalle
      WHERE id_seguimiento = ?
    `;

    if (req.auth.tipo_usuario === "PLANTEL") {
      detalleSql += " AND COALESCE(VisibleCliente, 1) = 1";
    }

    detalleSql += " ORDER BY FechaRegistro DESC, id_detalle DESC";

    const [rows] = await pool.query(detalleSql, detalleParams);

    return res.json({ ok: true, data: rows });
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
