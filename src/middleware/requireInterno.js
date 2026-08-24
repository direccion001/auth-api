function requireInterno(req, res, next) {
  if (req.auth?.tipo_usuario !== "INTERNO") {
    return res.status(403).json({
      ok: false,
      code: "SOLO_INTERNO",
      message: "No tienes permiso para realizar esta acción."
    });
  }

  return next();
}

module.exports = requireInterno;
