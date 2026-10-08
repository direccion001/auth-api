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

function puedeVerFinanzas(req) {
  return req.auth.capacidades?.ver_finanzas === true;
}

function aplicarAlcance(req, sql, params, opciones = {}) {
  const columnaPlantel = opciones.columnaPlantel || "IdPlantel";
  const columnaIdGrupo = opciones.columnaIdGrupo || null;

  if (req.auth.alcance === "PLANTEL") {
    sql += ` AND ${columnaPlantel} = ?`;
    params.push(req.auth.id_plantel);
    return sql;
  }

  if (req.auth.alcance === "MAESTRO") {
    if (!columnaIdGrupo) {
      throw new Error("ALCANCE_MAESTRO_NO_SOPORTADO");
    }

    // Titularidad vigente: un maestro anterior pierde acceso al cambiar el titular.
    sql += ` AND EXISTS (SELECT 1 FROM GRUPOS gscope WHERE gscope.IdGrupo = ${columnaIdGrupo} AND gscope.IdMaestroTitular = ?)`;
    params.push(req.auth.id_usuario);
    return sql;
  }

  if (req.auth.alcance === "GLOBAL") {
    if (req.query.id_plantel) {
      sql += ` AND ${columnaPlantel} = ?`;
      params.push(req.query.id_plantel);
    }
    return sql;
  }

  throw new Error("ALCANCE_INVALIDO");
}

function filtroPlantel(req, sql, params) {
  return aplicarAlcance(req, sql, params);
}

function numero(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

async function aplicarSeguimientoVisiblePlantel(req, rows) {
  if (req.auth.tipo_usuario !== "PLANTEL" || !Array.isArray(rows) || rows.length === 0) {
    return rows;
  }

  const idsAlumno = [...new Set(
    rows
      .map((row) => String(row.IdAlumno ?? "").trim())
      .filter(Boolean)
  )];

  if (!idsAlumno.length) return rows;

  const placeholders = idsAlumno.map(() => "?").join(", ");
  const [visibles] = await pool.query(
    `
    SELECT DISTINCT s.IdAlumno
    FROM alumnos_seguimientos s
    INNER JOIN ALUMNOS a
      ON a.IdAlumno = s.IdAlumno
    WHERE s.Status = 'Abierto'
      AND COALESCE(s.VisiblePlantel, 1) = 1
      AND a.IdPlantel = ?
      AND s.IdAlumno IN (${placeholders})
    `,
    [req.auth.id_plantel, ...idsAlumno]
  );

  const conSeguimientoVisible = new Set(
    visibles.map((row) => String(row.IdAlumno))
  );

  return rows.map((row) => ({
    ...row,
    EnSeguimiento: conSeguimientoVisible.has(String(row.IdAlumno)) ? 1 : 0
  }));
}

function nuevaSumaFinanciera(idPlantel = null, idGrupo = null) {
  return {
    ...(idPlantel ? { id_plantel: idPlantel } : {}),
    ...(idGrupo ? { id_grupo: idGrupo } : {}),
    cuota_mensual: 0,
    cuota_mensual_con_descuento: 0,
    pago_maestros: 0,
    asistencias_sin_pago: 0
  };
}

function construirResumenFinanciero(rows, pagosRows) {
  const totales = nuevaSumaFinanciera();
  const porGrupo = new Map();
  const porPlantel = new Map();

  const alumnosGlobales = new Set();
  const alumnosPorGrupo = new Set();
  const alumnosPorPlantel = new Set();

  for (const row of rows) {
    const idAlumno = String(row.IdAlumno || "").trim();
    const idGrupo = String(row.IdGrupo || "").trim();
    const idPlantel = String(row.IdPlantel || "").trim();

    if (!idAlumno) continue;

    const cuota = numero(row.CuotaMensual);
    const cuotaDescuento = numero(row.CuotaMensualConDescuento);

    if (!alumnosGlobales.has(idAlumno)) {
      alumnosGlobales.add(idAlumno);
      totales.cuota_mensual += cuota;
      totales.cuota_mensual_con_descuento += cuotaDescuento;
    }

    if (idGrupo) {
      const llaveGrupoAlumno = `${idGrupo}:${idAlumno}`;
      if (!alumnosPorGrupo.has(llaveGrupoAlumno)) {
        alumnosPorGrupo.add(llaveGrupoAlumno);
        if (!porGrupo.has(idGrupo)) {
          porGrupo.set(idGrupo, nuevaSumaFinanciera(idPlantel || null, idGrupo));
        }
        const resumenGrupo = porGrupo.get(idGrupo);
        resumenGrupo.cuota_mensual += cuota;
        resumenGrupo.cuota_mensual_con_descuento += cuotaDescuento;
      }
    }

    if (idPlantel) {
      const llavePlantelAlumno = `${idPlantel}:${idAlumno}`;
      if (!alumnosPorPlantel.has(llavePlantelAlumno)) {
        alumnosPorPlantel.add(llavePlantelAlumno);
        if (!porPlantel.has(idPlantel)) {
          porPlantel.set(idPlantel, nuevaSumaFinanciera(idPlantel));
        }
        const resumenPlantel = porPlantel.get(idPlantel);
        resumenPlantel.cuota_mensual += cuota;
        resumenPlantel.cuota_mensual_con_descuento += cuotaDescuento;
      }
    }
  }

  for (const pago of pagosRows) {
    const idGrupo = String(pago.IdGrupo || "").trim();
    const idPlantel = String(pago.IdPlantel || "").trim();
    const totalPago = numero(pago.TotalPagoMaestros);
    const sinPago = numero(pago.AsistenciasSinPago);

    totales.pago_maestros += totalPago;
    totales.asistencias_sin_pago += sinPago;

    if (idGrupo) {
      if (!porGrupo.has(idGrupo)) {
        porGrupo.set(idGrupo, nuevaSumaFinanciera(idPlantel || null, idGrupo));
      }
      const resumenGrupo = porGrupo.get(idGrupo);
      resumenGrupo.pago_maestros += totalPago;
      resumenGrupo.asistencias_sin_pago += sinPago;
    }

    if (idPlantel) {
      if (!porPlantel.has(idPlantel)) {
        porPlantel.set(idPlantel, nuevaSumaFinanciera(idPlantel));
      }
      const resumenPlantel = porPlantel.get(idPlantel);
      resumenPlantel.pago_maestros += totalPago;
      resumenPlantel.asistencias_sin_pago += sinPago;
    }
  }

  return {
    totales,
    por_grupo: Array.from(porGrupo.values()),
    por_plantel: Array.from(porPlantel.values())
  };
}

async function consultarPagosMaestros(req) {
  const params = [];

  let sql = `
    SELECT
      IdPlantel,
      IdGrupo,
      COALESCE(SUM(Pago), 0) AS TotalPagoMaestros,
      SUM(CASE WHEN Pago IS NULL THEN 1 ELSE 0 END) AS AsistenciasSinPago
    FROM ASISTENCIAS
    WHERE 1 = 1
  `;

  sql = aplicarAlcance(req, sql, params, {
    columnaPlantel: "IdPlantel",
    columnaMaestroTitular: null
  });

  if (req.query.desde) {
    sql += " AND FechaClase >= ?";
    params.push(req.query.desde);
  }

  if (req.query.hasta) {
    sql += " AND FechaClase <= ?";
    params.push(req.query.hasta);
  }

  sql += " GROUP BY IdPlantel, IdGrupo";

  const [rows] = await pool.query(sql, params);
  return rows;
}


// ======================================================
// ASISTENCIAS
// ======================================================

router.get("/asistencias", async (req, res) => {
  if (!permitir(req, res, "asistencias")) return;

  try {
    const params = req.auth.alcance === "MAESTRO" ? [req.auth.id_usuario] : [];
    const incluirFinanzas = puedeVerFinanzas(req);
    const historicoMaestro = req.auth.alcance === "MAESTRO"
      ? "AND EXISTS (SELECT 1 FROM GRUPOS hgrupo WHERE hgrupo.IdGrupo = vh.IdGrupo AND hgrupo.IdMaestroTitular = ?)"
      : "";

    const comentarioClaseSelect = req.auth.acceso_global
      ? "ComentarioClase"
      : "NULL AS ComentarioClase";

    const columnasFinancieras = incluirFinanzas
      ? `,
        CuotaMensual,
        CuotaMensualConDescuento,
        PagoMaestro`
      : "";

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
        hist.PrimeraAsistenciaAlumno,
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
        EsExtraHelp,
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
        ${columnasFinancieras}
      FROM vw_company_viewer_asistencias v
      LEFT JOIN (
        SELECT IdAlumno AS IdAlumnoHistorial, MIN(Fecha) AS PrimeraAsistenciaAlumno
        FROM vw_company_viewer_asistencias vh
        WHERE Presente IS NOT NULL
          AND TRIM(CAST(Presente AS CHAR)) <> ''
          ${historicoMaestro}
        GROUP BY IdAlumno
      ) hist ON hist.IdAlumnoHistorial = v.IdAlumno
      WHERE 1 = 1
    `;

    sql = aplicarAlcance(req, sql, params, {
      columnaPlantel: "v.IdPlantel",
      columnaIdGrupo: "v.IdGrupo"
    });

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
    const rowsVisibles = await aplicarSeguimientoVisiblePlantel(req, rows);

    if (!incluirFinanzas) {
      return res.json({ ok: true, data: rowsVisibles });
    }

    const pagosRows = await consultarPagosMaestros(req);
    const financial = construirResumenFinanciero(rowsVisibles, pagosRows);

    return res.json({
      ok: true,
      data: rowsVisibles,
      financial
    });

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
    const params = req.auth.alcance === "MAESTRO" ? [req.auth.id_usuario] : [];
    const historicoMaestro = req.auth.alcance === "MAESTRO"
      ? "AND EXISTS (SELECT 1 FROM GRUPOS hgrupo WHERE hgrupo.IdGrupo = hc.IdGrupo AND hgrupo.IdMaestroTitular = ?)"
      : "";

    let sql = `
      SELECT
        c.*,
        hist.PrimeraCalificacionAlumno
      FROM vw_company_viewer_calificaciones c
      LEFT JOIN (
        SELECT IdAlumno, MIN(FechaCalificacion) AS PrimeraCalificacionAlumno
        FROM vw_company_viewer_calificaciones hc
        WHERE Calificacion IS NOT NULL
          AND Calificacion <> 0
          ${historicoMaestro}
        GROUP BY IdAlumno
      ) hist ON hist.IdAlumno = c.IdAlumno
      WHERE 1 = 1
    `;

    sql = aplicarAlcance(req, sql, params, { columnaPlantel: "c.IdPlantel", columnaIdGrupo: "c.IdGrupo" });

    if (req.query.status) {
      sql += " AND StatusAlumno = ?";
      params.push(req.query.status);
    }

    const [rows] = await pool.query(sql, params);
    const rowsVisibles = await aplicarSeguimientoVisiblePlantel(req, rows);

    res.json({ ok: true, data: rowsVisibles });

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
// PDF DE OPCIONES DE GRUPO
// Mantiene el token del servicio de evaluaciones sólo en backend.
// ======================================================

const EVALUACION_WEBHOOK_URL =
  process.env.EVALUACION_WEBHOOK_URL ||
  "https://evaluacion-webhook-900393141805.us-central1.run.app";

function evaluacionWebhookToken(res) {
  const token = String(process.env.EVALUACION_WEBHOOK_TOKEN || "").trim();

  if (!token) {
    res.status(500).json({
      ok: false,
      code: "PDF_OPCIONES_NO_CONFIGURADO",
      message: "El servicio de PDF de opciones no está configurado."
    });
    return null;
  }

  return token;
}

function validarIdEvaluacion(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

router.post("/prospectos/:id_evaluacion/pdf-opciones", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  if (req.auth.tipo_usuario !== "INTERNO") {
    return res.status(403).json({
      ok: false,
      code: "PDF_OPCIONES_NO_AUTORIZADO",
      message: "No tienes permiso para generar este PDF."
    });
  }

  const idEvaluacion = validarIdEvaluacion(req.params.id_evaluacion);
  if (!idEvaluacion) {
    return res.status(400).json({
      ok: false,
      code: "EVALUACION_INVALIDA",
      message: "La evaluación indicada no es válida."
    });
  }

  const token = evaluacionWebhookToken(res);
  if (!token) return;

  try {
    const [rows] = await pool.query(
      "SELECT id_evaluacion FROM Examenes_Evaluacion WHERE id_evaluacion = ? LIMIT 1",
      [idEvaluacion]
    );

    if (!rows.length) {
      return res.status(404).json({
        ok: false,
        code: "EVALUACION_NO_ENCONTRADA",
        message: "No encontramos esta evaluación."
      });
    }

    const response = await fetch(`${EVALUACION_WEBHOOK_URL}/generar-pdf-opciones`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({
        token,
        id_evaluacion: idEvaluacion
      })
    });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok || payload.ok === false) {
      console.error("[VIEWER] generar pdf opciones", {
        idEvaluacion,
        status: response.status,
        error: payload.error
      });

      return res.status(response.status >= 400 ? response.status : 502).json({
        ok: false,
        code: "ERROR_GENERANDO_PDF_OPCIONES",
        message: payload.error || "No pudimos generar el PDF de opciones."
      });
    }

    const pdfParams = new URLSearchParams({
      token,
      id_evaluacion: String(idEvaluacion)
    });

    const pdfResponse = await fetch(
      `${EVALUACION_WEBHOOK_URL}/pdf-opciones?${pdfParams.toString()}`,
      { redirect: "manual" }
    );

    const signedUrl = pdfResponse.headers.get("location");
    if (!signedUrl) {
      console.error("[VIEWER] pdf opciones sin redirect firmado", {
        idEvaluacion,
        status: pdfResponse.status
      });

      return res.status(502).json({
        ok: false,
        code: "PDF_OPCIONES_SIN_URL",
        message: "El PDF se generó, pero no pudimos preparar el enlace de apertura."
      });
    }

    return res.json({
      ok: true,
      data: {
        ruta: payload.ruta || null,
        url: signedUrl
      }
    });
  } catch (error) {
    console.error("[VIEWER] generar pdf opciones", error);
    return res.status(502).json({
      ok: false,
      code: "ERROR_GENERANDO_PDF_OPCIONES",
      message: "No pudimos conectar con el servicio de PDF."
    });
  }
});

router.get("/prospectos/:id_evaluacion/pdf-opciones", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  if (req.auth.tipo_usuario !== "INTERNO") {
    return res.status(403).json({
      ok: false,
      code: "PDF_OPCIONES_NO_AUTORIZADO",
      message: "No tienes permiso para consultar este PDF."
    });
  }

  const idEvaluacion = validarIdEvaluacion(req.params.id_evaluacion);
  if (!idEvaluacion) {
    return res.status(400).json({
      ok: false,
      code: "EVALUACION_INVALIDA",
      message: "La evaluación indicada no es válida."
    });
  }

  const token = evaluacionWebhookToken(res);
  if (!token) return;

  try {
    const params = new URLSearchParams({
      token,
      id_evaluacion: String(idEvaluacion)
    });

    const response = await fetch(
      `${EVALUACION_WEBHOOK_URL}/pdf-opciones?${params.toString()}`
    );

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      return res.status(response.status).json({
        ok: false,
        code: "PDF_OPCIONES_NO_DISPONIBLE",
        message: payload.error || "El PDF todavía no está disponible."
      });
    }

    const contentType = response.headers.get("content-type") || "application/pdf";
    const buffer = Buffer.from(await response.arrayBuffer());

    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `inline; filename="opciones_evaluacion_${idEvaluacion}.pdf"`
    );
    res.setHeader("Cache-Control", "no-store");

    return res.send(buffer);
  } catch (error) {
    console.error("[VIEWER] abrir pdf opciones", error);
    return res.status(502).json({
      ok: false,
      code: "ERROR_ABRIENDO_PDF_OPCIONES",
      message: "No pudimos abrir el PDF de opciones."
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
        ON u.\`ID Usuario\` = c.id_usuario

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

    if (req.auth.alcance === "MAESTRO") {
      sql += " AND EXISTS (SELECT 1 FROM GRUPOS g WHERE g.IdGrupo = vw_company_viewer_grupos.IdGrupo AND g.IdMaestroTitular = ?)";
      params.push(req.auth.id_usuario);
    } else if (!req.auth.acceso_global) {
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

    if (req.auth.alcance === "MAESTRO") {
      sql += " AND EXISTS (SELECT 1 FROM GRUPOS g WHERE g.IdPlantel = vw_company_viewer_planteles.IdPlantel AND g.IdMaestroTitular = ?)";
      params.push(req.auth.id_usuario);
    } else if (!req.auth.acceso_global) {
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
        \`ID CURSO\` AS IdCurso,
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
