const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();
router.use(requireAuth, requireInterno);

const TIPOS = { nota: "Nota", contacto: "Contacto", reunion: "Reunion" };
const tiene = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);
const texto = (value) => { const v = String(value ?? "").trim(); return v || null; };
const bool = (value) => {
  if ([true, 1, "1", "true"].includes(value)) return true;
  if ([false, 0, "0", "false"].includes(value)) return false;
  return null;
};
const tipo = (value) => TIPOS[String(value ?? "").trim().toLowerCase()] || null;

function fecha(value) {
  if (value === null || value === undefined || value === "") return null;
  const raw = String(value).trim();
  const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return undefined;
  const [, y, mo, d] = m;
  const test = new Date(Date.UTC(+y, +mo - 1, +d));
  return test.getUTCFullYear() === +y && test.getUTCMonth() === +mo - 1 && test.getUTCDate() === +d ? raw : undefined;
}

function fechaHora(value) {
  const raw = String(value ?? "").trim();
  const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  const [, y, mo, d, h, mi, s = "00"] = m;
  const test = new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s));
  if (test.getUTCFullYear() !== +y || test.getUTCMonth() !== +mo - 1 || test.getUTCDate() !== +d || test.getUTCHours() !== +h || test.getUTCMinutes() !== +mi || test.getUTCSeconds() !== +s) return null;
  return `${y}-${mo}-${d} ${h}:${mi}:${s}`;
}

function ahoraMexico() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Mexico_City", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23"
  }).formatToParts(new Date());
  const v = Object.fromEntries(parts.filter((p) => p.type !== "literal").map((p) => [p.type, p.value]));
  return `${v.year}-${v.month}-${v.day} ${v.hour}:${v.minute}:${v.second}`;
}

function permitir(req, res) {
  if (!req.auth.modulos.includes("seguimientos")) {
    res.status(403).json({ ok: false, code: "MODULO_NO_AUTORIZADO", message: "No tienes acceso al módulo de seguimientos." });
    return false;
  }
  return true;
}

async function usuarioValido(idUsuario) {
  const [rows] = await pool.query(
    "SELECT `ID Usuario` FROM USUARIOS WHERE `ID Usuario` = ? AND Status = 'Activo' AND LOWER(TRIM(Rol)) IN ('admin','directivo') LIMIT 1",
    [idUsuario]
  );
  return rows.length > 0;
}

async function auditoria(connection, req, evento, idRegistro, antes, despues) {
  await connection.query(
    `INSERT INTO auditoria_eventos (actor_tipo, actor_id, evento, entidad, id_registro, antes_json, despues_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ["INTERNO", String(req.auth.id_usuario), evento, "alumnos_seguimiento_detalle", idRegistro, antes == null ? null : JSON.stringify(antes), despues == null ? null : JSON.stringify(despues)]
  );
}

async function consultar(connection, idDetalle) {
  const [rows] = await connection.query("SELECT * FROM vw_company_viewer_alumnos_seguimiento_detalle WHERE id_detalle = ? LIMIT 1", [idDetalle]);
  return rows[0] || null;
}

function validarCampos(body, actual = null) {
  const t = tiene(body, "tipo_registro") || !actual ? tipo(body.tipo_registro) : actual.TipoRegistro;
  if (!t) return { error: [400, "TIPO_REGISTRO_INVALIDO", "Selecciona un tipo de registro válido."] };
  const resultado = tiene(body, "resultado_contacto") || !actual ? texto(body.resultado_contacto) : actual.ResultadoContacto;
  if (!resultado) return { error: [400, "RESULTADO_CONTACTO_REQUERIDO", t === "Nota" ? "Escribe un título breve para la nota." : "Escribe el resultado de este seguimiento."] };
  let forma = actual?.FormaContacto ?? null;
  if (t === "Nota") forma = null;
  else {
    forma = tiene(body, "forma_contacto") || !actual ? texto(body.forma_contacto) : actual.FormaContacto;
    if (!forma) return { error: [400, "FORMA_CONTACTO_REQUERIDA", "Selecciona la forma de contacto."] };
  }
  const comentario = tiene(body, "comentario") || !actual ? texto(body.comentario) : actual.Comentario;
  const requiereRaw = tiene(body, "requiere_proximo_seguimiento") ? bool(body.requiere_proximo_seguimiento) : Boolean(actual?.RequiereProximoSeguimiento);
  if (requiereRaw === null) return { error: [400, "PROXIMO_SEGUIMIENTO_INVALIDO", "Indica si este registro requiere un próximo seguimiento."] };
  const fechaProxima = requiereRaw ? (tiene(body, "fecha_proximo_seguimiento") || !actual ? fecha(body.fecha_proximo_seguimiento) : actual.FechaProximoSeguimiento) : null;
  if (requiereRaw && fechaProxima === undefined) return { error: [400, "FECHA_PROXIMO_SEGUIMIENTO_INVALIDA", "Selecciona una fecha válida para el próximo seguimiento."] };
  if (requiereRaw && !fechaProxima) return { error: [400, "FECHA_PROXIMO_SEGUIMIENTO_REQUERIDA", "Selecciona la fecha del próximo seguimiento."] };
  const visibleRaw = tiene(body, "visible_cliente") ? bool(body.visible_cliente) : (actual ? Boolean(actual.VisibleCliente) : true);
  if (visibleRaw === null) return { error: [400, "VISIBLE_CLIENTE_INVALIDO", "Indica si este registro será visible para el plantel."] };
  return { tipo: t, forma, resultado, comentario, requiere: requiereRaw, fechaProxima, visible: visibleRaw };
}

function sendValidation(res, result) {
  if (!result.error) return false;
  const [status, code, message] = result.error;
  res.status(status).json({ ok: false, code, message });
  return true;
}

router.post("/", async (req, res, next) => {
  if (!tiene(req.body, "id_usuario") && !tiene(req.body, "fecha_registro")) return next();
  if (!permitir(req, res)) return;
  const idSeguimiento = texto(req.body?.id_seguimiento);
  if (!idSeguimiento) return res.status(400).json({ ok: false, code: "SEGUIMIENTO_REQUERIDO", message: "Selecciona el seguimiento al que pertenece este registro." });
  const campos = validarCampos(req.body);
  if (sendValidation(res, campos)) return;
  const idUsuario = texto(req.body?.id_usuario) || String(req.auth.id_usuario);
  const fechaRegistro = tiene(req.body, "fecha_registro") ? fechaHora(req.body.fecha_registro) : ahoraMexico();
  if (!fechaRegistro) return res.status(400).json({ ok: false, code: "FECHA_REGISTRO_INVALIDA", message: "Selecciona una fecha y hora válidas para el registro." });
  if (!(await usuarioValido(idUsuario))) return res.status(400).json({ ok: false, code: "USUARIO_REGISTRO_INVALIDO", message: "Selecciona un Admin o Directivo activo." });

  const connection = await pool.getConnection();
  const idDetalle = crypto.randomUUID();
  try {
    await connection.beginTransaction();
    const [seguimientos] = await connection.query("SELECT id_seguimiento, Status FROM alumnos_seguimientos WHERE id_seguimiento = ? LIMIT 1 FOR UPDATE", [idSeguimiento]);
    if (!seguimientos.length) { await connection.rollback(); return res.status(404).json({ ok: false, code: "SEGUIMIENTO_NO_ENCONTRADO", message: "No encontramos ese seguimiento." }); }
    if (seguimientos[0].Status === "Cerrado") { await connection.rollback(); return res.status(409).json({ ok: false, code: "SEGUIMIENTO_CERRADO", message: "No puedes agregar registros a un seguimiento cerrado." }); }
    const despues = { id_detalle: idDetalle, id_seguimiento: idSeguimiento, IdUsuario: idUsuario, FechaRegistro: fechaRegistro, TipoRegistro: campos.tipo, FormaContacto: campos.forma, ResultadoContacto: campos.resultado, Comentario: campos.comentario, RequiereProximoSeguimiento: campos.requiere ? 1 : 0, FechaProximoSeguimiento: campos.fechaProxima, VisibleCliente: campos.visible ? 1 : 0 };
    await connection.query(`INSERT INTO alumnos_seguimiento_detalle (id_detalle, id_seguimiento, IdUsuario, FechaRegistro, TipoRegistro, FormaContacto, ResultadoContacto, Comentario, RequiereProximoSeguimiento, FechaProximoSeguimiento, VisibleCliente) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [despues.id_detalle, despues.id_seguimiento, despues.IdUsuario, despues.FechaRegistro, despues.TipoRegistro, despues.FormaContacto, despues.ResultadoContacto, despues.Comentario, despues.RequiereProximoSeguimiento, despues.FechaProximoSeguimiento, despues.VisibleCliente]);
    await auditoria(connection, req, "SEGUIMIENTO_DETALLE_CREADO", idDetalle, null, despues);
    const creado = await consultar(connection, idDetalle);
    await connection.commit();
    return res.status(201).json({ ok: true, message: "Registro agregado al seguimiento.", data: creado || despues });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD DETALLES SEGUIMIENTOS] Error creando con fecha/usuario", error);
    return res.status(500).json({ ok: false, code: "ERROR_CREANDO_DETALLE_SEGUIMIENTO", message: "No pudimos agregar el registro al seguimiento." });
  } finally { connection.release(); }
});

router.patch("/:id_detalle", async (req, res, next) => {
  if (!tiene(req.body, "id_usuario") && !tiene(req.body, "fecha_registro")) return next();
  if (!permitir(req, res)) return;
  const idDetalle = texto(req.params.id_detalle);
  if (!idDetalle) return res.status(400).json({ ok: false, code: "DETALLE_REQUERIDO", message: "El registro indicado no es válido." });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.query(`SELECT d.*, s.Status AS StatusSeguimiento FROM alumnos_seguimiento_detalle d INNER JOIN alumnos_seguimientos s ON s.id_seguimiento = d.id_seguimiento WHERE d.id_detalle = ? LIMIT 1 FOR UPDATE`, [idDetalle]);
    if (!rows.length) { await connection.rollback(); return res.status(404).json({ ok: false, code: "DETALLE_NO_ENCONTRADO", message: "No encontramos ese registro de seguimiento." }); }
    const actual = rows[0];
    if (actual.StatusSeguimiento === "Cerrado") { await connection.rollback(); return res.status(409).json({ ok: false, code: "SEGUIMIENTO_CERRADO", message: "No puedes modificar el historial de un seguimiento cerrado." }); }
    const campos = validarCampos(req.body, actual);
    if (sendValidation(res, campos)) { await connection.rollback(); return; }
    const idUsuario = tiene(req.body, "id_usuario") ? (texto(req.body.id_usuario) || String(req.auth.id_usuario)) : String(actual.IdUsuario);
    const fechaRegistro = tiene(req.body, "fecha_registro") ? fechaHora(req.body.fecha_registro) : actual.FechaRegistro;
    if (!fechaRegistro) { await connection.rollback(); return res.status(400).json({ ok: false, code: "FECHA_REGISTRO_INVALIDA", message: "Selecciona una fecha y hora válidas para el registro." }); }
    if (!(await usuarioValido(idUsuario))) { await connection.rollback(); return res.status(400).json({ ok: false, code: "USUARIO_REGISTRO_INVALIDO", message: "Selecciona un Admin o Directivo activo." }); }
    const antes = { id_detalle: actual.id_detalle, id_seguimiento: actual.id_seguimiento, IdUsuario: actual.IdUsuario, FechaRegistro: actual.FechaRegistro, TipoRegistro: actual.TipoRegistro, FormaContacto: actual.FormaContacto, ResultadoContacto: actual.ResultadoContacto, Comentario: actual.Comentario, RequiereProximoSeguimiento: actual.RequiereProximoSeguimiento, FechaProximoSeguimiento: actual.FechaProximoSeguimiento, VisibleCliente: actual.VisibleCliente };
    const despues = { ...antes, IdUsuario: idUsuario, FechaRegistro: fechaRegistro, TipoRegistro: campos.tipo, FormaContacto: campos.forma, ResultadoContacto: campos.resultado, Comentario: campos.comentario, RequiereProximoSeguimiento: campos.requiere ? 1 : 0, FechaProximoSeguimiento: campos.fechaProxima, VisibleCliente: campos.visible ? 1 : 0 };
    await connection.query(`UPDATE alumnos_seguimiento_detalle SET IdUsuario = ?, FechaRegistro = ?, TipoRegistro = ?, FormaContacto = ?, ResultadoContacto = ?, Comentario = ?, RequiereProximoSeguimiento = ?, FechaProximoSeguimiento = ?, VisibleCliente = ? WHERE id_detalle = ?`, [despues.IdUsuario, despues.FechaRegistro, despues.TipoRegistro, despues.FormaContacto, despues.ResultadoContacto, despues.Comentario, despues.RequiereProximoSeguimiento, despues.FechaProximoSeguimiento, despues.VisibleCliente, idDetalle]);
    await auditoria(connection, req, "SEGUIMIENTO_DETALLE_ACTUALIZADO", idDetalle, antes, despues);
    const actualizado = await consultar(connection, idDetalle);
    await connection.commit();
    return res.json({ ok: true, message: "Registro actualizado correctamente.", data: actualizado || despues });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD DETALLES SEGUIMIENTOS] Error actualizando fecha/usuario", error);
    return res.status(500).json({ ok: false, code: "ERROR_ACTUALIZANDO_DETALLE_SEGUIMIENTO", message: "No pudimos actualizar el registro del seguimiento." });
  } finally { connection.release(); }
});

module.exports = router;
