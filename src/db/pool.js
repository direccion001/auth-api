const mysql = require("mysql2/promise");

const MEXICO_TIME_ZONE = "America/Mexico_City";
const MYSQL_TIME_ZONE = process.env.SQL_TIMEZONE || "-06:00";

process.env.TZ = process.env.TZ || MEXICO_TIME_ZONE;

const pool = mysql.createPool({
  user: process.env.SQL_USER,
  password: process.env.SQL_PASSWORD,
  database: process.env.DB_NAME,
  socketPath: `/cloudsql/${process.env.INSTANCE_CONNECTION}`,
  timezone: MYSQL_TIME_ZONE,
  dateStrings: true,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
