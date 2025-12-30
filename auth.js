const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const pool = require("./db");

function signToken(identity) {
  return jwt.sign(
    {
      sub: identity.IdAuth,
      tipoEntidad: identity.TipoEntidad,
      idEntidad: identity.IdEntidad
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
}

async function login(correo, password, tipoEntidad) {
  const [rows] = await pool.query(
    `
    SELECT i.IdAuth, i.TipoEntidad, i.IdEntidad, c.PasswordHash
    FROM AUTH_IDENTIDADES i
    JOIN AUTH_CREDENCIALES c ON c.IdAuth = i.IdAuth
    WHERE i.Correo = ?
      AND i.TipoEntidad = ?
      AND i.Status = 'ACTIVO'
    `,
    [correo, tipoEntidad]
  );

  if (rows.length === 0) {
    throw new Error("Credenciales inválidas");
  }

  const row = rows[0];
  const ok = await bcrypt.compare(password, row.PasswordHash);
  if (!ok) {
    throw new Error("Credenciales inválidas");
  }

  return signToken(row);
}

module.exports = { login };
