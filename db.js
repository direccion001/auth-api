const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  user: process.env.SQL_USER,
  password: process.env.SQL_PASSWORD,
  database: process.env.DB_NAME,
  socketPath: `/cloudsql/${process.env.INSTANCE_CONNECTION}`,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
