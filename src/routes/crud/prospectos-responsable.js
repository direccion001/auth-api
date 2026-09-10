const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

function tiene(obj, campo) {
  return Object.prototype.hasOwnProperty.call(obj || {}, campo);
}

function esInternoGlobal(req) {
  return String(req.auth?.tipo_usuario || "").toUpperCase() === "INTERNO" && Boolean(req.auth?.acceso_global);
}

function normalizarTexto(valor) {
  if (valor === null || valor === undefined) return null;
  const texto = String(valor).trim();
  return texto || null;
}

async function validarResponsable(idUsuario) {
  if (!idUsuario) return true;
  const [rows] = await pool.query(
    `SELECT \`ID Usuario\`
     FROM USUARIOS
     WHERE \`ID Usuario\` = ?
       AND Status = 'Activo'
       AND Rol IN ('Admin', 'Directivo')
     LIMIT 1`,
    [idUsuario]
  );
  return rows.length > 0;
}

function negarResponsable(res) {
  return res.status(403).json({
    ok: false,
    code: "RESPONSABLE_SOLO_INTERNOS",
    message: "Solo usuarios internos con acceso global pueden asignar un responsable."
  });
}

async function validarEntradaResponsable(req, res) {
  if (!esInternoGlobal(req)) {
    negarResponsable(res);
    return { ok: false, responsable: null };
  }

  const responsable = normalizarTexto(req.body.id_usuario_responsable);
  if (!(await validarResponsable(responsable))) {
    res.status(400).json({
      ok: false,
      code: "RESPONSABLE_INVALIDO",
      message: "El responsable debe ser un Admin o Directivo activo."
    });
    return { ok: false, responsable: null };
  }

  return { ok: true, responsable };
}

router.post("/", async (req, res, next) => {
  if (!tiene(req.body, "id_usuario_responsable")) return next();

  try {
    const validacion = await validarEntradaResponsable(req, res);
    if (!validacion.ok) return;

    const responsable = validacion.responsable;
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
            payload.data = { ...payload.data, id_usuario_responsable: responsable };
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
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error validando responsable al crear", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_VALIDANDO_RESPONSABLE",
      message: "No pudimos validar el responsable."
    });
  }
});

router.patch("/:id_appsheet", async (req, res, next) => {
  if (!tiene(req.body, "id_usuario_responsable")) return next();

  try {
    const validacion = await validarEntradaResponsable(req, res);
    if (!validacion.ok) return;

    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const responsable = validacion.responsable;
    delete req.body.id_usuario_responsable;

    const [prospectos] = await pool.query(
      "SELECT id_appsheet FROM Examenes_Evaluacion WHERE id_appsheet = ? LIMIT 1",
      [idAppsheet]
    );

    if (!prospectos.length) {
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto indicado."
      });
    }

    const aplicarResponsable = async () => {
      await pool.query(
        "UPDATE Examenes_Evaluacion SET id_usuario_responsable = ? WHERE id_appsheet = ?",
        [responsable, idAppsheet]
      );
    };

    if (Object.keys(req.body || {}).length === 0) {
      await aplicarResponsable();
      const [rows] = await pool.query(
        "SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1",
        [idAppsheet]
      );
      return res.json({
        ok: true,
        message: "Responsable actualizado correctamente.",
        data: rows[0] ? { ...rows[0], id_usuario_responsable: responsable } : null
      });
    }

    const originalJson = res.json.bind(res);
    res.json = async (payload) => {
      try {
        if (res.statusCode < 300) {
          await aplicarResponsable();
          if (payload?.data) {
            payload.data = { ...payload.data, id_usuario_responsable: responsable };
          }
        }
        return originalJson(payload);
      } catch (error) {
        console.error("[CRUD PROSPECTOS] Error actualizando responsable", error);
        return originalJson({
          ok: false,
          code: "ERROR_ACTUALIZANDO_RESPONSABLE",
          message: "Los demás cambios se guardaron, pero no pudimos actualizar el responsable."
        });
      }
    };

    return next();
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error procesando responsable", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_RESPONSABLE_PROSPECTO",
      message: "No pudimos actualizar el responsable del prospecto."
    });
  }
});

module.exports = router;
