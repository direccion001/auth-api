const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

const STATUS_NO_APLICA = "0 No aplica";
const STATUS_FALTA_EXAMEN_ESCRITO = "1 Falta examen escrito";
const STATUS_FALTA_EXAMEN_ORAL = "2 Falta examen oral";
const STATUS_NIVEL_ASIGNADO_CANONICO = "4 Nivel asignado";
const STATUS_NIVEL_ASIGNADO_COMPAT = "4 Nivel Asignado";

function statusCode(value) {
  const match = String(value ?? "").trim().match(/^(\d+)/);
  return match ? Number(match[1]) : null;
}

function tiene(objeto, campo) {
  return Object.prototype.hasOwnProperty.call(objeto || {}, campo);
}

function tieneExamenEscritoAplicado(prospecto) {
  const tieneFecha = prospecto?.fecha_hora_evaluacion != null;
  const tieneResultado = [
    prospecto?.promedio_total,
    prospecto?.score_principiante,
    prospecto?.score_intermedio,
    prospecto?.score_avanzado
  ].some((valor) => valor != null);

  return tieneFecha && tieneResultado;
}

async function buscarProspecto(idAppsheet, req) {
  const params = [idAppsheet];
  let sql = `
    SELECT
      id_evaluacion,
      id_plantel,
      status,
      fecha_hora_evaluacion,
      promedio_total,
      score_principiante,
      score_intermedio,
      score_avanzado
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

    // El CRUD ya mergeado compara literalmente contra "4 Nivel Asignado".
    // Usamos esa variante solo como compatibilidad interna antes de delegar.
    // El valor persistido final debe seguir siendo el histórico/canónico:
    // "4 Nivel asignado".
    if (solicitaNivel && codigoActual === 4 && actual.status !== STATUS_NIVEL_ASIGNADO_COMPAT) {
      await pool.query(
        "UPDATE Examenes_Evaluacion SET status = ? WHERE id_appsheet = ?",
        [STATUS_NIVEL_ASIGNADO_COMPAT, idAppsheet]
      );
    }

    if (solicitaNivel) {
      const originalJson = res.json.bind(res);
      res.json = async (payload) => {
        try {
          if (res.statusCode < 300 && payload?.data) {
            const statusResultado = payload.data.status_evaluacion ?? payload.data.status;
            if (statusCode(statusResultado) === 4) {
              await pool.query(
                "UPDATE Examenes_Evaluacion SET status = ? WHERE id_appsheet = ?",
                [STATUS_NIVEL_ASIGNADO_CANONICO, idAppsheet]
              );

              if (Object.prototype.hasOwnProperty.call(payload.data, "status_evaluacion")) {
                payload.data.status_evaluacion = STATUS_NIVEL_ASIGNADO_CANONICO;
              }
              if (Object.prototype.hasOwnProperty.call(payload.data, "status")) {
                payload.data.status = STATUS_NIVEL_ASIGNADO_CANONICO;
              }
            }
          }
        } catch (error) {
          console.error("[CRUD PROSPECTOS] Error restaurando status canónico de nivel", error);
          return originalJson({
            ok: false,
            code: "ERROR_STATUS_NIVEL_CANONICO",
            message: "El nivel se actualizó, pero no pudimos normalizar su status."
          });
        }

        return originalJson(payload);
      };
    }

    if (solicitaStatus) {
      const statusSolicitado = String(body.status || "").trim();
      const esReapertura = [
        STATUS_FALTA_EXAMEN_ESCRITO,
        STATUS_FALTA_EXAMEN_ORAL
      ].includes(statusSolicitado);

      if (esReapertura) {
        if (codigoActual !== 0) {
          return res.status(409).json({
            ok: false,
            code: "TRANSICION_STATUS_ACADEMICO_NO_PERMITIDA",
            message: `Solo puede reabrirse la evaluación desde ${STATUS_NO_APLICA}.`
          });
        }

        const statusEsperado = tieneExamenEscritoAplicado(actual)
          ? STATUS_FALTA_EXAMEN_ORAL
          : STATUS_FALTA_EXAMEN_ESCRITO;

        if (statusSolicitado !== statusEsperado) {
          return res.status(409).json({
            ok: false,
            code: "STATUS_REAPERTURA_NO_CORRESPONDE",
            message:
              statusEsperado === STATUS_FALTA_EXAMEN_ORAL
                ? `El examen escrito ya tiene fecha de aplicación y resultados. La evaluación debe continuar en ${STATUS_FALTA_EXAMEN_ORAL}.`
                : `No existe evidencia completa de examen escrito aplicado. La evaluación debe continuar en ${STATUS_FALTA_EXAMEN_ESCRITO}.`,
            status_permitido: statusEsperado
          });
        }

        await pool.query(
          "UPDATE Examenes_Evaluacion SET status = ? WHERE id_appsheet = ?",
          [statusEsperado, idAppsheet]
        );

        delete body.status;

        if (Object.keys(body).length === 0) {
          return responderProspecto(idAppsheet, res);
        }
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
