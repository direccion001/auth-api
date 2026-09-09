const express = require("express");
const { Storage } = require("@google-cloud/storage");
const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();
const storage = new Storage();
const AUDIO_URL_TTL_MS = 10 * 60 * 1000;

router.use(requireAuth);

function esInterno(req) {
  return String(req.auth?.tipo_usuario || "").toUpperCase() === "INTERNO";
}

function puedeVerProspectos(req) {
  return Array.isArray(req.auth?.modulos) && req.auth.modulos.includes("prospectos");
}

function quitarComentarios(data) {
  if (Array.isArray(data)) return data.map(quitarComentarios);
  if (!data || typeof data !== "object") return data;
  const { comentarios, ...resto } = data;
  return resto;
}

function normalizarPromedio(data) {
  if (!Array.isArray(data)) return data;

  return data.map((row) => ({
    ...row,
    promedio_total:
      row.promedio_total !== null &&
      row.promedio_total !== undefined &&
      Number(row.promedio_total) === 0
        ? null
        : row.promedio_total
  }));
}

function idAppsheetValido(value) {
  const idAppsheet = String(value || "").trim();
  return idAppsheet && idAppsheet.length <= 40 ? idAppsheet : null;
}

router.get("/prospectos", (req, res, next) => {
  const originalJson = res.json.bind(res);

  res.json = (payload) => {
    if (payload && Object.prototype.hasOwnProperty.call(payload, "data")) {
      let data = normalizarPromedio(payload.data);

      if (!esInterno(req)) {
        data = quitarComentarios(data);
      }

      payload = { ...payload, data };
    }

    return originalJson(payload);
  };

  return next();
});

router.get("/prospectos/:id_appsheet/audio-url", async (req, res) => {
  if (!puedeVerProspectos(req)) {
    return res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso a este módulo."
    });
  }

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

  try {
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

    const objectPath = String(rows[0].audio_url || "")
      .trim()
      .replace(/^\/+/, "");

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

module.exports = router;
