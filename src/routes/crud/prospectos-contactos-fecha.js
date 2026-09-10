const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

function permitir(req, res) {
  if (!req.auth.modulos.includes("prospectos")) {
    res.status(403).json({ ok: false, code: "MODULO_NO_AUTORIZADO", message: "No tienes acceso a este módulo." });
    return false;
  }
  return true;
}

function texto(value) {
  const normalized = String(value ?? "").trim();
  return normalized || null;
}

function fechaHoraLocal(value) {
  const raw = String(value ?? "").trim();
  const match = raw.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!match) return null;
  const [, y, m, d, h, min, s = "00"] = match;
  const date = new Date(Date.UTC(Number(y), Number(m) - 1, Number(d), Number(h), Number(min), Number(s)));
  if (date.getUTCFullYear() !== Number(y) || date.getUTCMonth() !== Number(m) - 1 || date.getUTCDate() !== Number(d) || date.getUTCHours() !== Number(h) || date.getUTCMinutes() !== Number(min) || date.getUTCSeconds() !== Number(s)) return null;
  return `${y}-${m}-${d} ${h}:${min}:${s}`;
}

function fechaLocal(value) {
  if (value === null || value === undefined || value === "") return null;
  const raw = String(value).trim();
  const match = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return undefined;
  const [, y, m, d] = match;
  const date = new Date(Date.UTC(Number(y), Number(m) - 1, Number(d)));
  if (date.getUTCFullYear() !== Number(y) || date.getUTCMonth() !== Number(m) - 1 || date.getUTCDate() !== Number(d)) return undefined;
  return raw;
}

function ahoraMexico() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Mexico_City", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23"
  }).formatToParts(new Date());
  const values = Object.fromEntries(parts.filter((part) => part.type !== "literal").map((part) => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day} ${values.hour}:${values.minute}:${values.second}`;
}

async function prospectoVisible(idAppsheet, req) {
  const params = [idAppsheet];
  let sql = "SELECT id_evaluacion, id_appsheet FROM Examenes_Evaluacion WHERE id_appsheet = ?";
  if (!req.auth.acceso_global) { sql += " AND id_plantel = ?"; params.push(req.auth.id_plantel); }
  sql += " LIMIT 1";
  const [rows] = await pool.query(sql, params);
  return rows[0] || null;
}

async function usuarioValido(idUsuario) {
  const [rows] = await pool.query(
    "SELECT `ID Usuario` FROM USUARIOS WHERE `ID Usuario` = ? AND Status = 'Activo' AND LOWER(TRIM(Rol)) IN ('admin','directivo') LIMIT 1",
    [idUsuario]
  );
  return rows.length > 0;
}

async function contactoVisible(idContacto, idAppsheet, req) {
  const params = [idContacto, idAppsheet];
  let sql = `SELECT c.*, e.id_plantel FROM contactos_examenes_evaluacion c INNER JOIN Examenes_Evaluacion e ON e.id_appsheet = c.id_appsheet WHERE c.id_contacto = ? AND c.id_appsheet = ?`;
  if (!req.auth.acceso_global) { sql += " AND e.id_plantel = ?"; params.push(req.auth.id_plantel); }
  sql += " LIMIT 1";
  const [rows] = await pool.query(sql, params);
  return rows[0] || null;
}

async function responderContacto(idContacto, status, res) {
  const [rows] = await pool.query(
    `SELECT c.*, CONCAT_WS(' ', u.Nombre, u.Apellidos) AS usuario_nombre
     FROM contactos_examenes_evaluacion c
     LEFT JOIN USUARIOS u ON u.\`ID Usuario\` = c.id_usuario
     WHERE c.id_contacto = ? LIMIT 1`,
    [idContacto]
  );
  return res.status(status).json({ ok: true, message: status === 201 ? "Contacto registrado correctamente." : "Contacto actualizado correctamente.", data: rows[0] || null });
}

router.post("/:id_appsheet/contactos", async (req, res, next) => {
  if (!Object.prototype.hasOwnProperty.call(req.body || {}, "fecha_hora_contacto")) return next();
  if (!permitir(req, res)) return;
  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const prospecto = await prospectoVisible(idAppsheet, req);
    if (!prospecto) return res.status(404).json({ ok: false, code: "PROSPECTO_NO_ENCONTRADO", message: "No encontramos el prospecto indicado." });

    const forma = texto(req.body?.forma_contacto);
    const resultado = texto(req.body?.resultado_contacto);
    const descripcion = texto(req.body?.descripcion);
    const fechaProximo = fechaLocal(req.body?.fecha_proximo_seguimiento);
    const fechaContacto = req.body?.fecha_hora_contacto ? fechaHoraLocal(req.body.fecha_hora_contacto) : ahoraMexico();
    if (!forma || !resultado || !descripcion) return res.status(400).json({ ok: false, code: "CONTACTO_INCOMPLETO", message: "Forma de contacto, resultado y descripción son obligatorios." });
    if (fechaProximo === undefined) return res.status(400).json({ ok: false, code: "FECHA_PROXIMO_SEGUIMIENTO_INVALIDA", message: "Selecciona una fecha válida para el próximo seguimiento." });
    if (!fechaContacto) return res.status(400).json({ ok: false, code: "FECHA_CONTACTO_INVALIDA", message: "Selecciona una fecha y hora válidas para el contacto." });

    let idUsuario = null;
    let esPlantel = 1;
    if (req.auth.acceso_global) {
      idUsuario = texto(req.body?.id_usuario) || String(req.auth.id_usuario);
      esPlantel = 0;
      if (!(await usuarioValido(idUsuario))) return res.status(400).json({ ok: false, code: "USUARIO_CONTACTO_INVALIDO", message: "El usuario del contacto debe ser un Admin o Directivo activo." });
    }

    const idContacto = crypto.randomUUID().replace(/-/g, "");
    await pool.query(
      `INSERT INTO contactos_examenes_evaluacion
       (id_contacto, id_appsheet, id_evaluacion, id_usuario, es_plantel, forma_contacto, resultado_contacto, descripcion, fecha_hora_contacto, fecha_proximo_seguimiento)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [idContacto, idAppsheet, prospecto.id_evaluacion, idUsuario, esPlantel, forma, resultado, descripcion, fechaContacto, fechaProximo]
    );
    return responderContacto(idContacto, 201, res);
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error creando contacto con fecha", error);
    return res.status(500).json({ ok: false, code: "ERROR_CREANDO_CONTACTO", message: "No pudimos registrar el contacto." });
  }
});

router.patch("/:id_appsheet/contactos/:id_contacto", async (req, res, next) => {
  if (!Object.prototype.hasOwnProperty.call(req.body || {}, "fecha_hora_contacto")) return next();
  if (!permitir(req, res)) return;
  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const idContacto = String(req.params.id_contacto || "").trim();
    const actual = await contactoVisible(idContacto, idAppsheet, req);
    if (!actual) return res.status(404).json({ ok: false, code: "CONTACTO_NO_ENCONTRADO", message: "No encontramos el contacto indicado." });
    if (!req.auth.acceso_global && Number(actual.es_plantel) !== 1) return res.status(403).json({ ok: false, code: "CONTACTO_SOLO_LECTURA", message: "El plantel solo puede editar contactos registrados por el propio plantel." });

    const body = req.body || {};
    const forma = Object.prototype.hasOwnProperty.call(body, "forma_contacto") ? texto(body.forma_contacto) : actual.forma_contacto;
    const resultado = Object.prototype.hasOwnProperty.call(body, "resultado_contacto") ? texto(body.resultado_contacto) : actual.resultado_contacto;
    const descripcion = Object.prototype.hasOwnProperty.call(body, "descripcion") ? texto(body.descripcion) : actual.descripcion;
    const fechaProximo = Object.prototype.hasOwnProperty.call(body, "fecha_proximo_seguimiento") ? fechaLocal(body.fecha_proximo_seguimiento) : actual.fecha_proximo_seguimiento;
    const fechaContacto = fechaHoraLocal(body.fecha_hora_contacto);
    if (!forma || !resultado || !descripcion) return res.status(400).json({ ok: false, code: "CONTACTO_INCOMPLETO", message: "Forma de contacto, resultado y descripción son obligatorios." });
    if (fechaProximo === undefined) return res.status(400).json({ ok: false, code: "FECHA_PROXIMO_SEGUIMIENTO_INVALIDA", message: "Selecciona una fecha válida para el próximo seguimiento." });
    if (!fechaContacto) return res.status(400).json({ ok: false, code: "FECHA_CONTACTO_INVALIDA", message: "Selecciona una fecha y hora válidas para el contacto." });

    let idUsuario = actual.id_usuario;
    if (req.auth.acceso_global && Object.prototype.hasOwnProperty.call(body, "id_usuario")) {
      idUsuario = texto(body.id_usuario) || String(req.auth.id_usuario);
      if (!(await usuarioValido(idUsuario))) return res.status(400).json({ ok: false, code: "USUARIO_CONTACTO_INVALIDO", message: "El usuario del contacto debe ser un Admin o Directivo activo." });
    }

    await pool.query(
      `UPDATE contactos_examenes_evaluacion SET forma_contacto = ?, resultado_contacto = ?, descripcion = ?, fecha_hora_contacto = ?, fecha_proximo_seguimiento = ?, id_usuario = ? WHERE id_contacto = ? AND id_appsheet = ?`,
      [forma, resultado, descripcion, fechaContacto, fechaProximo, idUsuario, idContacto, idAppsheet]
    );
    return responderContacto(idContacto, 200, res);
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error actualizando contacto con fecha", error);
    return res.status(500).json({ ok: false, code: "ERROR_ACTUALIZANDO_CONTACTO", message: "No pudimos actualizar el contacto." });
  }
});

module.exports = router;
