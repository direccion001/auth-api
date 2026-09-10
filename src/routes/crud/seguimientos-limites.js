const express = require("express");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();
router.use(requireAuth, requireInterno);

router.use((req, res, next) => {
  if (!["POST", "PATCH"].includes(req.method)) return next();
  if (!Object.prototype.hasOwnProperty.call(req.body || {}, "comentario_apertura")) return next();
  const value = String(req.body?.comentario_apertura ?? "").trim();
  if (value.length > 40) {
    return res.status(400).json({
      ok: false,
      code: "TITULO_SEGUIMIENTO_DEMASIADO_LARGO",
      message: "El título del seguimiento puede tener máximo 40 caracteres."
    });
  }
  return next();
});

module.exports = router;
