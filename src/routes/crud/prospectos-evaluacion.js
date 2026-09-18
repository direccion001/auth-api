const express = require("express");

const router = express.Router();

// Compatibilidad: las reglas académicas de status/nivel viven en prospectos.js.
// Este router se conserva para no alterar el montaje del CRUD.
router.patch("/:id_appsheet", (req, res, next) => next());

module.exports = router;
