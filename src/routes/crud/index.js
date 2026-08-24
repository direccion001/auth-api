const express = require("express");

const prospectosRouter = require("./prospectos");
const detalleAsistenciasRouter = require("./detalle-asistencias");
const seguimientosRouter = require("./seguimientos");
const detallesSeguimientosRouter = require("./detalles-seguimientos");

const router = express.Router();

router.use("/prospectos", prospectosRouter);
router.use("/detalle-asistencias", detalleAsistenciasRouter);
router.use("/seguimientos", seguimientosRouter);
router.use("/detalles-seguimientos", detallesSeguimientosRouter);

module.exports = router;
