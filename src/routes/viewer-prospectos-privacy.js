const express = require("express");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

function esInterno(req) {
  return String(req.auth?.tipo_usuario || "").toUpperCase() === "INTERNO";
}

function quitarComentarios(data) {
  if (Array.isArray(data)) return data.map(quitarComentarios);
  if (!data || typeof data !== "object") return data;
  const { comentarios, ...resto } = data;
  return resto;
}

router.get("/prospectos", (req, res, next) => {
  if (esInterno(req)) return next();

  const originalJson = res.json.bind(res);
  res.json = (payload) => {
    if (payload && Object.prototype.hasOwnProperty.call(payload, "data")) {
      payload = { ...payload, data: quitarComentarios(payload.data) };
    }
    return originalJson(payload);
  };

  return next();
});

module.exports = router;
