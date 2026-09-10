const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

const SCORE_FIELDS = ["score_principiante", "score_intermedio", "score_avanzado"];

function tiene(obj, campo) {
  return Object.prototype.hasOwnProperty.call(obj || {}, campo);
}

function puedeEditar(req) {
  const rol = String(req.auth?.rol || "").trim().toLowerCase();
  return rol === "admin" || rol === "directivo";
}

function normalizarScore(valor) {
  if (valor === null || valor === undefined || valor === "") return null;
  const numero = Number(valor);
  if (!Number.isFinite(numero) || numero < 0 || numero > 100) return undefined;
  return Math.round(numero);
}

router.patch("/:id_appsheet", async (req, res, next) => {
  const body = req.body || {};
  const solicitados = SCORE_FIELDS.filter((campo) => tiene(body, campo));
  if (!solicitados.length) return next();

  if (!puedeEditar(req)) {
    return res.status(403).json({
      ok: false,
      code: "PROSPECTOS_SOLO_ADMIN_DIRECTIVO",
      message: "Solo Admin y Directivo pueden modificar calificaciones de prospectos."
    });
  }

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const updates = [];
    const params = [];

    for (const campo of solicitados) {
      const valor = normalizarScore(body[campo]);
      if (valor === undefined) {
        return res.status(400).json({
          ok: false,
          code: "CALIFICACION_INVALIDA",
          message: "Las calificaciones deben estar entre 0 y 100 o quedar vacías."
        });
      }
      updates.push(`${campo} = ?`);
      params.push(valor);
      delete body[campo];
    }

    params.push(idAppsheet);
    const [result] = await pool.query(
      `UPDATE Examenes_Evaluacion SET ${updates.join(", ")} WHERE id_appsheet = ?`,
      params
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto indicado."
      });
    }

    if (Object.keys(body).length > 0) return next();

    const [rows] = await pool.query(
      "SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1",
      [idAppsheet]
    );

    return res.json({
      ok: true,
      message: "Calificaciones actualizadas correctamente.",
      data: rows[0] || null
    });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error actualizando calificaciones", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_ACTUALIZANDO_CALIFICACIONES",
      message: "No pudimos actualizar las calificaciones del prospecto."
    });
  }
});

module.exports = router;
