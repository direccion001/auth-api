const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

const STATUS_NO_APLICA = "0 No aplica";
const STATUS_FALTA_EXAMEN_ESCRITO = "1 Falta examen escrito";
const STATUS_NIVEL_ASIGNADO_CANONICO = "4 Nivel Asignado";

function statusCode(value) {
  const match = String(value ?? "").trim().match(/^(\d+)/);
  return match ? Number(match[1]) : null;
}

function tiene(objeto, campo) {
  return Object.prototype.hasOwnProperty.call(objeto || {}, campo);
}

async function buscarProspecto(idAppsheet, req) {
  const params = [idAppsheet];
  let sql = `
    SELECT id_evaluacion, id_plantel, status
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

async function responderProspecto(idAppsheet, res) {
  const [rows] = await pool.query(
    "SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1",
    [idAppsheet]
  );

  return res.json({
    ok: true,
    message: "Status de evaluación actualizado correctamente.",
    data: rows[0] || null
  });
}

router.patch("/:id_appsheet", async (req, res, next) => {
  const body = req.body || {};
  const solicitaNivel = tiene(body, "nivel_sugerido");
  const solicitaStatus = tiene(body, "status");

  if (!solicitaNivel && !solicitaStatus) return next();
  if (!req.auth.modulos.includes("prospectos")) return next();
  if (!req.auth.acceso_global) return next();

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const actual = await buscarProspecto(idAppsheet, req);
    if (!actual) return next();

    const codigoActual = statusCode(actual.status);

    // Compatibilidad con datos históricos: el CRUD mergeado compara el texto
    // completo de status 4. Canonicalizamos al editar nivel para que cualquier
    // variante de "4 Nivel asignado" continúe siendo editable.
    if (solicitaNivel && codigoActual === 4 && actual.status !== STATUS_NIVEL_ASIGNADO_CANONICO) {
      await pool.query(
        "UPDATE Examenes_Evaluacion SET status = ? WHERE id_appsheet = ?",
        [STATUS_NIVEL_ASIGNADO_CANONICO, idAppsheet]
      );
    }

    // Nueva transición manual permitida: No aplica -> Falta examen escrito.
    // Si el PATCH trae otros campos (por ejemplo desde el editor completo),
    // aplicamos primero la transición y dejamos que el CRUD existente procese
    // el resto del body sin volver a validar este status.
    if (solicitaStatus && String(body.status || "").trim() === STATUS_FALTA_EXAMEN_ESCRITO) {
      if (codigoActual !== 0) {
        return res.status(409).json({
          ok: false,
          code: "TRANSICION_STATUS_ACADEMICO_NO_PERMITIDA",
          message: `Solo puede regresar a ${STATUS_FALTA_EXAMEN_ESCRITO} desde ${STATUS_NO_APLICA}.`
        });
      }

      await pool.query(
        "UPDATE Examenes_Evaluacion SET status = ? WHERE id_appsheet = ?",
        [STATUS_FALTA_EXAMEN_ESCRITO, idAppsheet]
      );

      delete body.status;

      if (Object.keys(body).length === 0) {
        return responderProspecto(idAppsheet, res);
      }
    }

    return next();
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error en compatibilidad de status académico", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_STATUS_ACADEMICO",
      message: "No pudimos actualizar el status académico del prospecto."
    });
  }
});

module.exports = router;
