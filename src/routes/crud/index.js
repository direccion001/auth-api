const express = require("express");

const prospectosRouter = require("./prospectos");

const router = express.Router();

router.use("/prospectos", prospectosRouter);

module.exports = router;