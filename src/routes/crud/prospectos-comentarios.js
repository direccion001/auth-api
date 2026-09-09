const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

function tiene(obj, campo) {
  return Object.prototype.hasOwnProperty.call(obj || {}, campo);
}

function normalizarTexto(valor) {
  if (valor === null || valor === undefined) return null;
  const texto = String(valor).trim();
  return texto || null;
}

async function buscarPorIdAppsheet(idAppsheet, req) {
  const params = [idAppsheet];
  let sql = `
    SELECT id_evaluacion, id_appsheet, id_plantel
    FROM Examenes_Evaluacion
    WHERE id_appsheet = ?
  `;

  if (!req.auth.acceso_global) {
    sql += " AND id_plantel = ?";
    params.push(req.auth.id_plantel);
  }

  sql += " LIMIT 1";
  const [rows] = await pool.query(sql, params);
  return rows[0] || null;
}

function negarComentariosPlantel(res) {
  return res.status(403).json({
    ok: false,
    code: "COMENTARIOS_SOLO_INTERNOS",
    message: "Los comentarios del prospecto solo pueden ser consultados o modificados por usuarios internos."
  });
}

// POST /crud/prospectos
// El CRUD base crea el registro. Si un interno envía comentarios, interceptamos
// la respuesta exitosa para persistirlos antes de devolver el prospecto creado.
router.post("/", async (req, res, next) => {
  if (!tiene(req.body, "comentarios")) return next();
  if (!req.auth.acceso_global) return negarComentariosPlantel(res);

  const comentarios = normalizarTexto(req.body.comentarios);
  delete req.body.comentarios;

  const originalJson = res.json.bind(res);
  res.json = async (payload) => {
    try {
      if (res.statusCode < 300 && payload?.data) {
        const idEvaluacion = payload.data.id_evaluacion ?? payload.data.IdEvaluacion;
        const idAppsheet = payload.data.id_appsheet ?? payload.data.IdAppsheet;

        if (idEvaluacion || idAppsheet) {
          if (idEvaluacion) {
            await pool.query(
              "UPDATE Examenes_Evaluacion SET comentarios = ? WHERE id_evaluacion = ?",
              [comentarios, idEvaluacion]
            );
          } else {
            await pool.query(
              "UPDATE Examenes_Evaluacion SET comentarios = ? WHERE id_appsheet = ?",
              [comentarios, idAppsheet]
            );
          }

          const [rows] = await pool.query(
            idEvaluacion
              ? "SELECT * FROM vw_company_viewer_prospectos WHERE id_evaluacion = ? LIMIT 1"
              : "SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1",
            [idEvaluacion || idAppsheet]
          );
          if (rows[0]) payload.data = rows[0];
        }
      }
    } catch (error) {
      console.error("[CRUD PROSPECTOS] Error guardando comentarios al crear", error);
      return originalJson({
        ok: false,
        code: "ERROR_GUARDANDO_COMENTARIOS",
        message: "El prospecto se creó, pero no pudimos guardar los comentarios."
      });
    }

    return originalJson(payload);
  };

  return next();
});

// PATCH /crud/prospectos/:id_appsheet
router.patch("/:id_appsheet", async (req, res, next) => {
  if (!tiene(req.body, "comentarios")) return next();
  if (!req.auth.acceso_global) return negarComentariosPlantel(res);

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const actual = await buscarPorIdAppsheet(idAppsheet, req);
    if (!actual) return next();

    const comentarios = normalizarTexto(req.body.comentarios);
    delete req.body.comentarios;

    await pool.query(
      "UPDATE Examenes_Evaluacion SET comentarios = ? WHERE id_appsheet = ?",
      [comentarios, idAppsheet]
    );

    if (Object.keys(req.body || {}).length > 0) return next();

    const [rows] = await pool.query(
      "SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1",
      [idAppsheet]
    );

    return res.json({
      ok: true,
      message: "Comentarios actualizados correctamente.",
      data: rows[0] || null
    });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error actualizando comentarios", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_ACTUALIZANDO_COMENTARIOS",
      message: "No pudimos actualizar los comentarios del prospecto."
    });
  }
});

module.exports = router;
