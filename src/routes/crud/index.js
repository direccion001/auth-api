const express = require("express");

const prospectosRouter = require("./prospectos");
const detalleAsistenciasRouter = require("./detalle-asistencias");

const router = express.Router();

router.use("/prospectos", prospectosRouter);
router.use("/detalle-asistencias", detalleAsistenciasRouter);

module.exports = router;
