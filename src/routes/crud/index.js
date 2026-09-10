const express = require("express");
const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const prospectosResponsableRouter = require("./prospectos-responsable");
const prospectosComentariosRouter = require("./prospectos-comentarios");
const prospectosEvaluacionRouter = require("./prospectos-evaluacion");
const prospectosRouter = require("./prospectos");
const detalleAsistenciasRouter = require("./detalle-asistencias");
const seguimientosEstadoRouter = require("./seguimientos-estado");
const seguimientosRouter = require("./seguimientos");
const detallesSeguimientosRouter = require("./detalles-seguimientos");
const graduacionesRouter = require("./graduaciones");

const router = express.Router();

// Invariante de negocio: una vez inscrito, el status de contacto es terminal.
// El resto de campos del prospecto continúa siendo editable.
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

router.use("/prospectos", prospectosResponsableRouter);
router.use("/prospectos", prospectosComentariosRouter);
router.use("/prospectos", prospectosEvaluacionRouter);
router.use("/prospectos", prospectosRouter);
router.use("/detalle-asistencias", detalleAsistenciasRouter);
router.use("/seguimientos", seguimientosEstadoRouter);
router.use("/seguimientos", seguimientosRouter);
router.use("/detalles-seguimientos", detallesSeguimientosRouter);
router.use("/graduaciones", graduacionesRouter);

module.exports = router;
