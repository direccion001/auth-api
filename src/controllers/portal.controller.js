const pool = require("../db/pool");
const { portalReadHandler } = require("../services/portal.service");

function read(req, res) {
  portalReadHandler(req, res, pool);
}

module.exports = { read };