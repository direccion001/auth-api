const express = require("express");

const prospectosRouter = require("./prospectos");
const detalleAsistenciasRouter = require("./detalle-asistencias");
const seguimientosEstadoRouter = require("./seguimientos-estado");
const seguimientosRouter = require("./seguimientos");
const detallesSeguimientosRouter = require("./detalles-seguimientos");
const graduacionesRouter = require("./graduaciones");

const router = express.Router();

router.use("/prospectos", prospectosRouter);
router.use("/detalle-asistencias", detalleAsistenciasRouter);
router.use("/seguimientos", seguimientosEstadoRouter);
router.use("/seguimientos", seguimientosRouter);
router.use("/detalles-seguimientos", detallesSeguimientosRouter);
router.use("/graduaciones", graduacionesRouter);

module.exports = router;
