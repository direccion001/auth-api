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

function mismoUsuario(value, req) {
  return value != null && String(value) === String(req.auth.id_usuario);
}

function fechaComparable(value) {
  return value ? String(value).slice(0, 10) : null;
}

function compararSeguimientos(a, b, req) {
  const fechaA = fechaComparable(a.FechaProximoSeguimiento) || "9999-12-31";
  const fechaB = fechaComparable(b.FechaProximoSeguimiento) || "9999-12-31";

  if (fechaA !== fechaB) return fechaA.localeCompare(fechaB);

  // En empate de fecha, la fila visible prioriza un seguimiento cuyo responsable sea el usuario actual.
  const mioA = mismoUsuario(a.IdUsuarioResponsable, req) ? 1 : 0;
  const mioB = mismoUsuario(b.IdUsuarioResponsable, req) ? 1 : 0;
  if (mioA !== mioB) return mioB - mioA;

  // Si ninguno gana por responsabilidad, prevalece la actividad más reciente.
  const ultimoA = String(a.FechaUltimoRegistro || a.FechaApertura || "");
  const ultimoB = String(b.FechaUltimoRegistro || b.FechaApertura || "");
  return ultimoB.localeCompare(ultimoA);
}

function estadoSeguimiento(row, activos, req) {
  const tieneHistorial = Number(row.TieneHistorialSeguimiento || 0) === 1;
  if (!tieneHistorial) return "sin_seguimiento";

  if (!activos.length) return "seguimientos_inactivos";

  if (activos.some((item) => mismoUsuario(item.IdUsuarioResponsable, req))) {
    return "mis_seguimientos";
  }

  return "en_seguimiento";
}

function seguimientoPersonalizado(row, activos, req) {
  const candidatos = activos
    .filter((item) => item.FechaProximoSeguimiento)
    .sort((a, b) => compararSeguimientos(a, b, req));

  // "Mi seguimiento" siempre se define por el responsable de la cabecera/ticket.
  // El usuario que registró el último detalle es solo autor histórico del contacto.
  const mios = activos
    .filter((item) => mismoUsuario(item.IdUsuarioResponsable, req))
    .sort((a, b) => compararSeguimientos(a, b, req));

  const miosConProximo = mios.filter((item) => item.FechaProximoSeguimiento);
  const relevante = candidatos[0] || null;
  const mio = miosConProximo[0] || mios[0] || null;

  return {
    ...row,
    EstadoSeguimiento: estadoSeguimiento(row, activos, req),
    TieneMiSeguimientoActivo: mios.length > 0,
    CantidadMisSeguimientosActivos: mios.length,
    CantidadMisProximosSeguimientos: miosConProximo.length,

    IdSeguimientoRelevante: relevante?.id_seguimiento ?? null,
    IdDetalleProximoSeguimientoRelevante: relevante?.IdUltimoDetalle ?? null,
    FechaProximoSeguimientoRelevante: relevante?.FechaProximoSeguimiento ?? null,
    ProximaAccionRelevante: relevante?.ProximaAccion ?? null,
    IdUsuarioResponsableRelevante: relevante?.IdUsuarioResponsable ?? null,
    ResponsableSeguimientoRelevante: relevante?.UsuarioResponsable ?? null,
    SeguimientoRelevanteEsMio: relevante
      ? mismoUsuario(relevante.IdUsuarioResponsable, req)
      : false,

    MiIdSeguimiento: mio?.id_seguimiento ?? null,
    MiIdDetalleProximoSeguimiento: mio?.IdUltimoDetalle ?? null,
    MiFechaProximoSeguimiento: mio?.FechaProximoSeguimiento ?? null,
    MiProximaAccion: mio?.ProximaAccion ?? null,
    MiIdUsuarioResponsable: mio?.IdUsuarioResponsable ?? null,
    MiResponsableSeguimiento: mio?.UsuarioResponsable ?? null
  };
}

function filtrarPorSeguimiento(rows, value) {
  const filtro = texto(value)?.toLowerCase();
  if (!filtro) return rows;

  const aliases = {
    mios: "mis_seguimientos",
    "mis-seguimientos": "mis_seguimientos",
    mis_seguimientos: "mis_seguimientos",
    activos: "en_seguimiento",
    "en-seguimiento": "en_seguimiento",
    en_seguimiento: "en_seguimiento",
    inactivos: "seguimientos_inactivos",
    "seguimientos-inactivos": "seguimientos_inactivos",
    seguimientos_inactivos: "seguimientos_inactivos",
    ninguno: "sin_seguimiento",
    "sin-seguimiento": "sin_seguimiento",
    sin_seguimiento: "sin_seguimiento"
  };

  const esperado = aliases[filtro] || filtro;
  return rows.filter((row) => row.EstadoSeguimiento === esperado);
}

async function consultarSeguimientosActivos(filtros = {}) {
  const params = [];
  let sql = `
    SELECT *
    FROM vw_company_viewer_alumnos_seguimiento s
    WHERE s.StatusSeguimiento = 'Abierto'
  `;

  if (filtros.idPlantel) {
    sql += " AND s.IdPlantel = ?";
    params.push(filtros.idPlantel);
  }

  if (filtros.idGrupo) {
    sql += " AND s.IdGrupo = ?";
    params.push(filtros.idGrupo);
  }

  if (filtros.idMaestro) {
    sql += " AND s.IdMaestroTitular = ?";
    params.push(filtros.idMaestro);
  }

  const [rows] = await pool.query(sql, params);
  return rows;
}

router.get("/", async (req, res) => {
  if (!permitirAlumnos(req, res)) return;

  try {
    const idPlantel = texto(req.query.id_plantel);
    const idGrupo = texto(req.query.id_grupo);
    const idMaestro = texto(req.query.id_maestro);
    const status = texto(req.query.status);

    const params = [];
    let sql = `
      SELECT *
      FROM vw_company_viewer_alumnos a
      WHERE 1 = 1
    `;

    if (idPlantel) {
      sql += " AND a.IdPlantel = ?";
      params.push(idPlantel);
    }

    if (idGrupo) {
      sql += " AND a.IdGrupo = ?";
      params.push(idGrupo);
    }

    if (idMaestro) {
      sql += " AND a.IdMaestroTitular = ?";
      params.push(idMaestro);
    }

    if (status) {
      sql += " AND LOWER(TRIM(a.StatusAlumno)) = LOWER(TRIM(?))";
      params.push(status);
    }

    sql += " ORDER BY a.NombreCompleto ASC, a.IdAlumno ASC";

    const [alumnos] = await pool.query(sql, params);
    const seguimientos = await consultarSeguimientosActivos({
      idPlantel,
      idGrupo,
      idMaestro
    });

    const porAlumno = new Map();
    for (const seguimiento of seguimientos) {
      const key = String(seguimiento.IdAlumno);
      if (!porAlumno.has(key)) porAlumno.set(key, []);
      porAlumno.get(key).push(seguimiento);
    }

    let data = alumnos.map((row) =>
      seguimientoPersonalizado(row, porAlumno.get(String(row.IdAlumno)) || [], req)
    );

    data = filtrarPorSeguimiento(data, req.query.seguimiento);

    return res.json({
      ok: true,
      data
    });
  } catch (error) {
    console.error("[VIEWER ALUMNOS] Error consultando catálogo", {
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONSULTANDO_ALUMNOS",
      message: "No pudimos consultar el catálogo de alumnos."
    });
  }
});

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

  try {
    const [rows] = await pool.query(
      `
      SELECT
        IdDetalle,
        IdAsistenciaInterno,
        IdAsistencia,
        IdAlumno,
        Fecha,
        Presente,
        Justificada,
        ComentarioAlumno,
        TituloComentario,
        IdGrupo,
        Grupo,
        IdPlantel,
        Plantel,
        IdMaestroQueDioClase,
        Maestro,
        IdMaestroTitular,
        Titular,
        IdCurso,
        Curso,
        ColorCurso,
        Cap,
        Pagina
      FROM vw_company_viewer_asistencias
      WHERE IdAlumno = ?
      ORDER BY Fecha DESC, IdDetalle DESC
      LIMIT 120
      `,
      [idAlumno]
    );

    return res.json({ ok: true, data: rows });
  } catch (error) {
    console.error("[VIEWER ALUMNOS] Error consultando asistencias", {
      id_alumno: idAlumno,
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

router.get("/:id_alumno/calificaciones", async (req, res) => {
  if (!permitirAlumnos(req, res)) return;

  const idAlumno = texto(req.params.id_alumno);
  if (!idAlumno) {
    return res.status(400).json({
      ok: false,
      code: "ALUMNO_REQUERIDO",
      message: "El alumno indicado no es válido."
    });
  }

  try {
    const [rows] = await pool.query(
      `
      SELECT *
      FROM vw_company_viewer_calificaciones
      WHERE IdAlumno = ?
        AND Calificacion IS NOT NULL
        AND IdCurso IS NOT NULL
      ORDER BY FechaCalificacion ASC, IdCurso ASC, Modulo ASC
      `,
      [idAlumno]
    );

    return res.json({ ok: true, data: rows });
  } catch (error) {
    console.error("[VIEWER ALUMNOS] Error consultando calificaciones", {
      id_alumno: idAlumno,
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
