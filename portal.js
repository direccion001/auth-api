const jwt = require("jsonwebtoken");

function isValidViewName(viewName) {
  return typeof viewName === 'string'
    && viewName.startsWith('S_VW_')
    && /^[A-Z0-9_]+$/.test(viewName);
}

async function portalReadHandler(req, res, pool) {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");
    if (!token) return res.status(401).end();

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(401).end();
    }

    const { idEntidad } = payload;
    if (!idEntidad) return res.status(401).end();

    const viewName = req.params.viewName;

    if (!isValidViewName(viewName)) {
      return res.status(400).end();
    }

    const conn = await pool.getConnection();

    const [rows] = await conn.query(
      `SELECT * FROM ${viewName} WHERE IdEntidad = ?`,
      [idEntidad]
    );

    conn.release();

    const single = req.query.single === "true";
    return res.json(single ? (rows[0] || null) : rows);

  } catch (err) {
    console.error("portalReadApi error:", err);
    return res.status(500).end();
  }
}

module.exports = { portalReadHandler };
