const express = require("express");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();
router.use(requireAuth, requireInterno);

router.use((req, res, next) => next());

module.exports = router;
