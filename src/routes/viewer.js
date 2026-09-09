const express = require("express");
const { Storage } = require("@google-cloud/storage");
const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();
const storage = new Storage();
const AUDIO_URL_TTL_MS = 10 * 60 * 1000;

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

function idAppsheetValido(value) {
  const idAppsheet = String(value || "").trim();
  return idAppsheet && idAppsheet.length <= 40 ? idAppsheet : null;
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
        (
          SELECT d.TituloComentario
          FROM DETALLE_ASISTENCIAS d
          WHERE d.IdDetalle = v.IdDetalle
          LIMIT 1
        ) AS TituloComentario,
        Nombre,
        NombreAlumno,
        ApellidosAlumno,
        StatusAlumno,
        FechaRegistroAlumno,
        FechaBajaAlumno,
        AsistenciaAlumno,
        EnSeguimiento,
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
      FROM vw_detalle_asistencias_completo_renovado v
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

    const data = rows.map((row) => ({
      ...row,
      promedio_total:
        row.promedio_total !== null && Number(row.promedio_total) === 0
          ? null
          : row.promedio_total
    }));

    res.json({ ok: true, data });

  } catch (error) {
    console.error("[VIEWER] prospectos", error);

    res.status(500).json({
      ok: false,
      message: "No pudimos consultar los prospectos."
    });
  }
});

// ======================================================
// AUDIO DE PROSPECTO
// Devuelve una URL firmada temporal, nunca expone credenciales.
// ======================================================

router.get("/prospectos/:id_appsheet/audio-url", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const idAppsheet = idAppsheetValido(req.params.id_appsheet);

    if (!idAppsheet) {
      return res.status(400).json({
        ok: false,
        code: "PROSPECTO_INVALIDO",
        message: "El prospecto indicado no es válido."
      });
    }

    const bucketName = String(process.env.GCS_BUCKET || "").trim();

    if (!bucketName) {
      console.error("[VIEWER] GCS_BUCKET no está configurado");
      return res.status(500).json({
        ok: false,
        code: "STORAGE_NO_CONFIGURADO",
        message: "El almacenamiento de audios no está configurado."
      });
    }

    const params = [idAppsheet];
    let sql = `
      SELECT
        id_appsheet,
        id_plantel,
        audio_url
      FROM Examenes_Evaluacion
      WHERE id_appsheet = ?
    `;

    if (!req.auth.acceso_global) {
      sql += " AND id_plantel = ?";
      params.push(req.auth.id_plantel);
    }

    sql += " LIMIT 1";

    const [rows] = await pool.query(sql, params);

    if (!rows.length) {
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto solicitado."
      });
    }

    const objectPath = String(rows[0].audio_url || "").trim().replace(/^\/+/, "");

    if (!objectPath) {
      return res.status(404).json({
        ok: false,
        code: "AUDIO_NO_DISPONIBLE",
        message: "Este prospecto todavía no tiene audio oral."
      });
    }

    const expiresAt = Date.now() + AUDIO_URL_TTL_MS;
    const [url] = await storage
      .bucket(bucketName)
      .file(objectPath)
      .getSignedUrl({
        version: "v4",
        action: "read",
        expires: expiresAt
      });

    return res.json({
      ok: true,
      url,
      expires_at: new Date(expiresAt).toISOString(),
      expires_in: Math.floor(AUDIO_URL_TTL_MS / 1000)
    });

  } catch (error) {
    console.error("[VIEWER] audio prospecto", error);

    return res.status(500).json({
      ok: false,
      code: "ERROR_AUDIO_PROSPECTO",
      message: "No pudimos preparar el audio del prospecto."
    });
  }
});

// ======================================================
// CONTACTOS DE PROSPECTO
// Relación oficial: Examenes_Evaluacion.id_appsheet
//                    contactos_examenes_evaluacion.id_appsheet
// ======================================================

router.get("/prospectos/:id_appsheet/contactos", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();

    if (!idAppsheet || idAppsheet.length > 40) {
      return res.status(400).json({
        ok: false,
        code: "PROSPECTO_INVALIDO",
        message: "El prospecto indicado no es válido."
      });
    }

    const params = [idAppsheet];

    let sql = `
      SELECT
        c.id_contacto,
        c.id_appsheet,
        c.id_evaluacion,
        c.id_usuario,
        c.es_plantel,
        c.fecha_hora_contacto,
        c.forma_contacto,
        c.resultado_contacto,
        c.descripcion,
        c.fecha_proximo_seguimiento,

        CONCAT_WS(' ', u.Nombre, u.Apellidos) AS usuario_nombre

      FROM contactos_examenes_evaluacion c

      INNER JOIN Examenes_Evaluacion e
        ON e.id_appsheet = c.id_appsheet

      LEFT JOIN USUARIOS u
        ON u.`ID Usuario` = c.id_usuario

      WHERE c.id_appsheet = ?
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

    if (!req.auth.acceso_global) {
      sql += " AND IdPlantel = ?";
      params.push(req.auth.id_plantel);
    } else if (req.query.id_plantel) {
      sql += " AND IdPlantel = ?";
      params.push(req.query.id_plantel);
    }

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

    if (!req.auth.acceso_global) {
      sql += " AND IdPlantel = ?";
      params.push(req.auth.id_plantel);
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

// ======================================================
// CURSOS
// Catálogo reutilizable para formularios del viewer.
// ======================================================

router.get("/cursos", async (req, res) => {
  try {
    const params = [];
    const status = String(req.query.status || "Activo").trim();

    let sql = `
      SELECT
        `ID CURSO` AS IdCurso,
        Nombre AS Curso,
        Color AS ColorCurso,
        Status AS StatusCurso
      FROM CURSOS
      WHERE 1 = 1
    `;

    if (status) {
      sql += " AND Status = ?";
      params.push(status);
    }

    sql += " ORDER BY Nombre ASC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows
    });
  } catch (error) {
    console.error("[VIEWER] cursos", error);

    return res.status(500).json({
      ok: false,
      code: "ERROR_CURSOS",
      message: "No pudimos consultar los cursos."
    });
  }
});

// ======================================================
// GRADUACIONES
// ======================================================

router.get("/graduaciones", async (req, res) => {
  if (!permitir(req, res, "graduaciones")) return;

  try {
    const params = [];

    let sql = `
      SELECT *
      FROM vw_company_viewer_graduaciones
      WHERE 1 = 1
    `;

    sql = filtroPlantel(req, sql, params);

    if (req.query.id_grupo) {
      sql += " AND IdGrupo = ?";
      params.push(req.query.id_grupo);
    }

    if (req.query.status) {
      sql += " AND StatusGraduacion = ?";
      params.push(req.query.status);
    }

    if (req.query.status_curso) {
      sql += " AND StatusCurso = ?";
      params.push(req.query.status_curso);
    }

    sql += " ORDER BY FechaCursoFinProgramada ASC, Grupo ASC";

    const [rows] = await pool.query(sql, params);

    return res.json({
      ok: true,
      data: rows
    });
  } catch (error) {
    console.error("[VIEWER] graduaciones", error);

    return res.status(500).json({
      ok: false,
      code: "ERROR_GRADUACIONES",
      message: "No pudimos consultar las graduaciones."
    });
  }
});

module.exports = router;
