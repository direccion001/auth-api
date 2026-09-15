const express = require("express");
const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const prospectosResponsableRouter = require("./prospectos-responsable");
const prospectosComentariosRouter = require("./prospectos-comentarios");
const prospectosEvaluacionRouter = require("./prospectos-evaluacion");
const prospectosCalificacionesRouter = require("./prospectos-calificaciones");
const prospectosContactosFechaRouter = require("./prospectos-contactos-fecha");
const prospectosInscripcionRouter = require("./prospectos-inscripcion");
const prospectosOperacionRouter = require("./prospectos-operacion");
const prospectosRouter = require("./prospectos");
const detalleAsistenciasRouter = require("./detalle-asistencias");
const seguimientosEstadoRouter = require("./seguimientos-estado");
const seguimientosLimitesRouter = require("./seguimientos-limites");
const seguimientosRouter = require("./seguimientos");
const detallesSeguimientosEdicionRouter = require("./detalles-seguimientos-edicion");
const detallesSeguimientosRouter = require("./detalles-seguimientos");
const graduacionesRouter = require("./graduaciones");

const router = express.Router();

function tiene(obj, campo) {
  return Object.prototype.hasOwnProperty.call(obj || {}, campo);
}

function normalizarTexto(valor) {
  if (valor === null || valor === undefined) return null;
  const texto = String(valor).trim();
  return texto || null;
}

function tieneResultadoEscrito(prospecto) {
  return [
    prospecto.score_principiante,
    prospecto.score_intermedio,
    prospecto.score_avanzado,
    prospecto.promedio_total
  ].some((valor) => {
    const numero = Number(valor);
    return Number.isFinite(numero) && numero > 0;
  });
}

function statusSinNivel(prospecto) {
  if (normalizarTexto(prospecto.audio_url)) return "3 Listo para evaluar";
  if (tieneResultadoEscrito(prospecto)) return "2 Falta examen oral";
  return "1 Falta examen escrito";
}

// Regla general del módulo Prospectos: Admin y Directivo modifican todo.
// Excepciones operativas de plantel: crear prospectos y crear/editar sus propios contactos.
router.use("/prospectos", requireAuth, (req, res, next) => {
  if (!["POST", "PATCH", "PUT", "DELETE"].includes(req.method)) return next();

  const rol = String(req.auth?.rol || "").trim().toLowerCase();
  if (["admin", "administrador", "directivo"].includes(rol)) return next();

  const path = req.path || "/";
  const esAltaProspecto = req.method === "POST" && path === "/";
  const esContactoPlantel = ["POST", "PATCH"].includes(req.method)
    && /^\/[^/]+\/contactos(?:\/[^/]+)?$/.test(path);

  if (!req.auth?.acceso_global && (esAltaProspecto || esContactoPlantel)) return next();

  return res.status(403).json({
    ok: false,
    code: "PROSPECTOS_SOLO_ADMIN_DIRECTIVO",
    message: "Solo Admin y Directivo pueden realizar esta modificación en Prospectos."
  });
});

// Invariante de negocio: una vez inscrito, el status de contacto es terminal.
// El resto de campos del prospecto continúa siendo editable para roles autorizados.
router.patch("/prospectos/:id_appsheet", requireAuth, async (req, res, next) => {
  if (!Object.prototype.hasOwnProperty.call(req.body || {}, "status_contacto")) {
    return next();
  }

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const statusSolicitado = String(req.body?.status_contacto || "").trim();
    const params = [idAppsheet];

    let sql = `
      SELECT status_contacto
      FROM Examenes_Evaluacion
      WHERE id_appsheet = ?
    `;

    if (!req.auth.acceso_global) {
      sql += " AND id_plantel = ?";
      params.push(req.auth.id_plantel);
    }

    sql += " LIMIT 1";

    const [rows] = await pool.query(sql, params);
    const statusActual = rows[0]?.status_contacto
      ? String(rows[0].status_contacto).trim()
      : null;

    if (statusActual === "2 Inscrito" && statusSolicitado !== "2 Inscrito") {
      return res.status(409).json({
        ok: false,
        code: "STATUS_CONTACTO_INSCRITO_BLOQUEADO",
        message: "Este prospecto ya fue inscrito. Su status de contacto no puede cambiarse desde Company Viewer."
      });
    }

    return next();
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error validando status de inscrito", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_VALIDANDO_STATUS_INSCRITO",
      message: "No pudimos validar el status del prospecto."
    });
  }
});

// Grupo propuesto y nivel quedan sellados al inscribir.
// Si se elimina el último nivel antes de inscripción, el status académico se deriva de la evidencia disponible.
router.patch("/prospectos/:id_appsheet", requireAuth, async (req, res, next) => {
  const body = req.body || {};
  const tocaGrupo = tiene(body, "id_grupo_propuesto");
  const tocaNivel = tiene(body, "nivel_sugerido");
  if (!tocaGrupo && !tocaNivel) return next();

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const params = [idAppsheet];
    let sql = `
      SELECT status_contacto, status, nivel_sugerido, audio_url,
             score_principiante, score_intermedio, score_avanzado, promedio_total
      FROM Examenes_Evaluacion
      WHERE id_appsheet = ?
    `;

    if (!req.auth.acceso_global) {
      sql += " AND id_plantel = ?";
      params.push(req.auth.id_plantel);
    }
    sql += " LIMIT 1";

    const [rows] = await pool.query(sql, params);
    const prospecto = rows[0];
    if (!prospecto) {
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto indicado."
      });
    }

    if (String(prospecto.status_contacto || "").trim() === "2 Inscrito") {
      return res.status(409).json({
        ok: false,
        code: "PROSPECTO_INSCRITO_CAMPOS_SELLADOS",
        message: "Grupo propuesto y nivel asignado quedan sellados una vez inscrito el prospecto."
      });
    }

    const nivelSolicitado = tocaNivel ? normalizarTexto(body.nivel_sugerido) : undefined;
    const soloQuitaNivel = tocaNivel
      && nivelSolicitado === null
      && Object.keys(body).every((campo) => campo === "nivel_sugerido");

    if (!soloQuitaNivel) return next();

    const statusActual = String(prospecto.status || "").trim();
    const statusPermitidos = new Set([
      "0 No aplica",
      "2 Falta examen oral",
      "3 Listo para evaluar",
      "4 Nivel Asignado"
    ]);

    if (!statusPermitidos.has(statusActual)) {
      return res.status(409).json({
        ok: false,
        code: "NIVEL_NO_EDITABLE",
        message: "El nivel no puede modificarse en el status académico actual."
      });
    }

    const statusDerivado = statusSinNivel(prospecto);
    await pool.query(
      `UPDATE Examenes_Evaluacion SET nivel_sugerido = NULL, status = ? WHERE id_appsheet = ?`,
      [statusDerivado, idAppsheet]
    );

    const [vista] = await pool.query(
      `SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1`,
      [idAppsheet]
    );

    return res.json({
      ok: true,
      message: "Nivel eliminado y status académico recalculado correctamente.",
      data: vista[0] || null
    });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error aplicando reglas de grupo/nivel", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_REGLAS_PROSPECTO",
      message: "No pudimos aplicar las reglas académicas del prospecto."
    });
  }
});

router.use("/prospectos", prospectosResponsableRouter);
router.use("/prospectos", prospectosComentariosRouter);
router.use("/prospectos", prospectosEvaluacionRouter);
router.use("/prospectos", prospectosCalificacionesRouter);
router.use("/prospectos", prospectosContactosFechaRouter);
router.use("/prospectos", prospectosInscripcionRouter);
router.use("/prospectos", prospectosOperacionRouter);
router.use("/prospectos", prospectosRouter);
router.use("/detalle-asistencias", detalleAsistenciasRouter);
router.use("/seguimientos", seguimientosEstadoRouter);
router.use("/seguimientos", seguimientosLimitesRouter);
router.use("/seguimientos", seguimientosRouter);
router.use("/detalles-seguimientos", detallesSeguimientosEdicionRouter);
router.use("/detalles-seguimientos", detallesSeguimientosRouter);
router.use("/graduaciones", graduacionesRouter);

module.exports = router;
