const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

function tiene(obj, campo) {
  return Object.prototype.hasOwnProperty.call(obj || {}, campo);
}

function esInterno(req) {
  return String(req.auth?.tipo_usuario || "").toUpperCase() === "INTERNO";
}

function normalizarTexto(valor) {
  if (valor === null || valor === undefined) return null;
  const texto = String(valor).trim();
  return texto || null;
}

async function validarResponsable(idUsuario) {
  if (!idUsuario) return true;
  const [rows] = await pool.query(
    `SELECT \`ID Usuario\` FROM USUARIOS
     WHERE \`ID Usuario\` = ?
       AND Status = 'Activo'
       AND Rol IN ('Administrador', 'Directivo')
     LIMIT 1`,
    [idUsuario]
  );
  return rows.length > 0;
}

router.post("/", async (req, res, next) => {
  if (!tiene(req.body, "id_usuario_responsable")) return next();

  if (!esInterno(req)) {
    return res.status(403).json({
      ok: false,
      code: "RESPONSABLE_SOLO_INTERNOS",
      message: "Solo los usuarios internos pueden asignar un responsable."
    });
  }

  const responsable = normalizarTexto(req.body.id_usuario_responsable);
  if (!(await validarResponsable(responsable))) {
    return res.status(400).json({
      ok: false,
      code: "RESPONSABLE_INVALIDO",
      message: "El responsable debe ser un Administrador o Directivo activo."
    });
  }

  delete req.body.id_usuario_responsable;
  const originalJson = res.json.bind(res);

  res.json = async (payload) => {
    try {
      if (res.statusCode < 300 && payload?.data && responsable) {
        const idEvaluacion = payload.data.id_evaluacion ?? payload.data.IdEvaluacion;
        const idAppsheet = payload.data.id_appsheet ?? payload.data.IdAppsheet;
        if (idEvaluacion || idAppsheet) {
          await pool.query(
            idEvaluacion
              ? "UPDATE Examenes_Evaluacion SET id_usuario_responsable = ? WHERE id_evaluacion = ?"
              : "UPDATE Examenes_Evaluacion SET id_usuario_responsable = ? WHERE id_appsheet = ?",
            [responsable, idEvaluacion || idAppsheet]
          );
          payload.data = {
            ...payload.data,
            id_usuario_responsable: responsable
          };
        }
      }
      return originalJson(payload);
    } catch (error) {
      console.error("[CRUD PROSPECTOS] Error asignando responsable al crear", error);
      return originalJson({
        ok: false,
        code: "ERROR_ASIGNANDO_RESPONSABLE",
        message: "El prospecto se creó, pero no pudimos asignar el responsable."
      });
    }
  };

  return next();
});

module.exports = router;
