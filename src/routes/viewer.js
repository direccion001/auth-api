const express = require("express");
const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

function permitir(req, res, modulo) {
  if (!req.auth.modulos.includes(modulo)) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso a este módulo."
    });
    return false;
  }

  return true;
}

function filtroPlantel(req, sql, params) {
  if (!req.auth.acceso_global) {
    sql += " AND IdPlantel = ?";
    params.push(req.auth.id_plantel);
  } else if (req.query.id_plantel) {
    sql += " AND IdPlantel = ?";
    params.push(req.query.id_plantel);
  }

  return sql;
}


// ======================================================
// ASISTENCIAS
// ======================================================

router.get("/asistencias", async (req, res) => {
  if (!permitir(req, res, "asistencias")) return;

  try {
    const params = [];

    const comentarioClaseSelect = req.auth.acceso_global
  ? "ComentarioClase"
  : "NULL AS ComentarioClase";

let sql = `
  SELECT
    IdDetalle,
    IdAsistenciaInterno,
    IdAsistencia,
    IdAlumno,
    Fecha,
    UsuarioApp,
    Sustitucion,
    ${comentarioClaseSelect},
    ComentarioAlumno,
    Nombre,
    NombreAlumno,
    ApellidosAlumno,
    StatusAlumno,
    FechaRegistroAlumno,
    FechaBajaAlumno,
    Presente,
    Justificada,
    IdGrupo,
    IdPlantel,
    Grupo,
    StatusGrupo,
    Modalidad,
    TipoGrupo,
    ClasePrivada,
    DiasClase,
    HoraInicio,
    HoraFin,
    IdMaestroTitular,
    Titular,
    IdMaestroQueDioClase,
    Maestro,
    IdCurso,
    Curso,
    ColorCurso,
    Cap,
    Pagina,
    Duracion,
    Plantel,
    CorreoCliente,
    LogoUrl
  FROM vw_detalle_asistencias_completo_renovado
  WHERE 1 = 1
`;

    sql = filtroPlantel(req, sql, params);

    if (req.query.desde) {
      sql += " AND Fecha >= ?";
      params.push(req.query.desde);
    }

    if (req.query.hasta) {
      sql += " AND Fecha <= ?";
      params.push(req.query.hasta);
    }

    if (req.query.status) {
      sql += " AND StatusAlumno = ?";
      params.push(req.query.status);
    }

    const [rows] = await pool.query(sql, params);

    res.json({ ok: true, data: rows });

  } catch (error) {
    console.error("[VIEWER] asistencias", error);

    res.status(500).json({
      ok: false,
      message: "No pudimos consultar las asistencias."
    });
  }
});


// ======================================================
// CALIFICACIONES
// ======================================================

router.get("/calificaciones", async (req, res) => {
  if (!permitir(req, res, "calificaciones")) return;

  try {
    const params = [];

    let sql = `
      SELECT *
      FROM vw_company_viewer_calificaciones
      WHERE 1 = 1
    `;

    sql = filtroPlantel(req, sql, params);

    if (req.query.status) {
      sql += " AND StatusAlumno = ?";
      params.push(req.query.status);
    }

    const [rows] = await pool.query(sql, params);

    res.json({ ok: true, data: rows });

  } catch (error) {
    console.error("[VIEWER] calificaciones", error);

    res.status(500).json({
      ok: false,
      message: "No pudimos consultar las calificaciones."
    });
  }
});


// ======================================================
// PROSPECTOS
// ======================================================

router.get("/prospectos", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const params = [];

    let sql = `
      SELECT *
      FROM vw_company_viewer_prospectos
      WHERE 1 = 1
    `;

    if (!req.auth.acceso_global) {
      sql += " AND id_plantel = ?";
      params.push(req.auth.id_plantel);
    } else if (req.query.id_plantel) {
      sql += " AND id_plantel = ?";
      params.push(req.query.id_plantel);
    }

    const [rows] = await pool.query(sql, params);

    res.json({ ok: true, data: rows });

  } catch (error) {
    console.error("[VIEWER] prospectos", error);

    res.status(500).json({
      ok: false,
      message: "No pudimos consultar los prospectos."
    });
  }
});

// ======================================================
// CONTACTOS DE PROSPECTO
// ======================================================

router.get("/prospectos/:id_evaluacion/contactos", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const idEvaluacion = Number(req.params.id_evaluacion);

    if (!Number.isInteger(idEvaluacion) || idEvaluacion <= 0) {
      return res.status(400).json({
        ok: false,
        code: "PROSPECTO_INVALIDO",
        message: "El prospecto indicado no es válido."
      });
    }

    const params = [idEvaluacion];

    let sql = `
      SELECT
        c.id_contacto,
        c.id_evaluacion,
        c.id_usuario,
        c.fecha_hora_contacto,
        c.forma_contacto,
        c.resultado_contacto,
        c.descripcion,
        c.fecha_proximo_seguimiento,

        CONCAT_WS(' ', u.Nombre, u.Apellidos) AS usuario_nombre

      FROM contactos_examenes_evaluacion c

      INNER JOIN Examenes_Evaluacion e
        ON e.id_evaluacion = c.id_evaluacion

      LEFT JOIN USUARIOS u
        ON u.\`ID Usuario\` = c.id_usuario

      WHERE c.id_evaluacion = ?
    `;

    if (!req.auth.acceso_global) {
      sql += " AND e.id_plantel = ?";
      params.push(req.auth.id_plantel);
    }

    sql += " ORDER BY c.fecha_hora_contacto DESC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows
    });

  } catch (error) {
    console.error("[VIEWER] contactos prospecto", error);

    return res.status(500).json({
      ok: false,
      code: "ERROR_CONTACTOS",
      message: "No pudimos consultar los contactos del prospecto."
    });
  }
});

// ======================================================
// GRUPOS
// ======================================================

router.get("/grupos", async (req, res) => {
  try {
    const params = [];

    let sql = `
      SELECT *
      FROM vw_company_viewer_grupos
      WHERE 1 = 1
    `;

    // PLANTEL: únicamente sus grupos
    if (!req.auth.acceso_global) {
      sql += " AND IdPlantel = ?";
      params.push(req.auth.id_plantel);

    // INTERNO: puede elegir plantel
    } else if (req.query.id_plantel) {
      sql += " AND IdPlantel = ?";
      params.push(req.query.id_plantel);
    }

    // Filtro opcional de status de grupo
    if (req.query.status) {
      sql += " AND StatusGrupo = ?";
      params.push(req.query.status);
    }

    sql += " ORDER BY Grupo ASC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows
    });

  } catch (error) {
    console.error("[VIEWER] grupos", error);

    return res.status(500).json({
      ok: false,
      code: "ERROR_GRUPOS",
      message: "No pudimos consultar los grupos."
    });
  }
});

// ======================================================
// PLANTELES
// ======================================================

router.get("/planteles", async (req, res) => {
  try {
    const params = [];

    let sql = `
      SELECT *
      FROM vw_company_viewer_planteles
      WHERE 1 = 1
    `;

    // PLANTEL: únicamente puede consultar su propio plantel
    if (!req.auth.acceso_global) {
      sql += " AND IdPlantel = ?";
      params.push(req.auth.id_plantel);

    // INTERNO: puede consultar uno específico o todos
    } else if (req.query.id_plantel) {
      sql += " AND IdPlantel = ?";
      params.push(req.query.id_plantel);
    }

    if (req.query.status) {
      sql += " AND StatusPlantel = ?";
      params.push(req.query.status);
    }

    sql += " ORDER BY Plantel ASC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows
    });

  } catch (error) {
    console.error("[VIEWER] planteles", error);

    return res.status(500).json({
      ok: false,
      code: "ERROR_PLANTELES",
      message: "No pudimos consultar los planteles."
    });
  }
});



module.exports = router;