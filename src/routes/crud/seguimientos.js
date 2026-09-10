const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

function permitirSeguimientos(req, res) {
  if (!req.auth.modulos.includes("seguimientos")) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de seguimientos."
    });
    return false;
  }

  return true;
}

function normalizarTexto(valor) {
  const texto = String(valor ?? "").trim();
  return texto || null;
}

function normalizarFechaHoraLocal(valor) {
  const texto = String(valor ?? "").trim();
  const match = texto.match(
    /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/
  );

  if (!match) return null;

  const [, anio, mes, dia, hora, minuto, segundo = "00"] = match;
  const partes = [anio, mes, dia, hora, minuto, segundo].map(Number);
  const [y, m, d, h, min, s] = partes;

  const prueba = new Date(Date.UTC(y, m - 1, d, h, min, s));
  if (
    prueba.getUTCFullYear() !== y ||
    prueba.getUTCMonth() !== m - 1 ||
    prueba.getUTCDate() !== d ||
    prueba.getUTCHours() !== h ||
    prueba.getUTCMinutes() !== min ||
    prueba.getUTCSeconds() !== s
  ) {
    return null;
  }

  return `${anio}-${mes}-${dia} ${hora}:${minuto}:${segundo}`;
}

function fechaMexicoAhora() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Mexico_City",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23"
  }).formatToParts(new Date());

  const valores = Object.fromEntries(
    parts.filter((p) => p.type !== "literal").map((p) => [p.type, p.value])
  );

  return `${valores.year}-${valores.month}-${valores.day} ${valores.hour}:${valores.minute}:${valores.second}`;
}

async function validarAlumno(connection, idAlumno) {
  const [rows] = await connection.query(
    `
    SELECT IdAlumno
    FROM ALUMNOS
    WHERE IdAlumno = ?
    LIMIT 1
    `,
    [idAlumno]
  );

  return rows.length > 0;
}

async function validarResponsable(connection, idUsuario) {
  const [rows] = await connection.query(
    `
    SELECT \`ID Usuario\` AS IdUsuario
    FROM USUARIOS
    WHERE \`ID Usuario\` = ?
      AND Status = 'Activo'
      AND LOWER(TRIM(Rol)) IN ('admin', 'directivo')
    LIMIT 1
    `,
    [idUsuario]
  );

  return rows.length > 0;
}

async function registrarAuditoria(
  connection,
  req,
  evento,
  idRegistro,
  antes,
  despues
) {
  await connection.query(
    `
    INSERT INTO auditoria_eventos (
      actor_tipo,
      actor_id,
      evento,
      entidad,
      id_registro,
      antes_json,
      despues_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      "INTERNO",
      String(req.auth.id_usuario),
      evento,
      "alumnos_seguimientos",
      idRegistro,
      antes == null ? null : JSON.stringify(antes),
      despues == null ? null : JSON.stringify(despues)
    ]
  );
}

async function consultarSeguimiento(connection, idSeguimiento) {
  const [rows] = await connection.query(
    `
    SELECT *
    FROM vw_company_viewer_alumnos_seguimiento
    WHERE id_seguimiento = ?
    LIMIT 1
    `,
    [idSeguimiento]
  );

  return rows[0] || null;
}

router.post("/", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  const idAlumno = normalizarTexto(req.body?.id_alumno);
  const idUsuarioResponsable = normalizarTexto(
    req.body?.id_usuario ?? req.body?.id_usuario_responsable
  );
  const fechaApertura = normalizarFechaHoraLocal(req.body?.fecha_apertura);
  const comentarioApertura = normalizarTexto(req.body?.comentario_apertura);

  if (!idAlumno) {
    return res.status(400).json({ ok: false, code: "ALUMNO_REQUERIDO", message: "Selecciona el alumno que estará en seguimiento." });
  }
  if (!idUsuarioResponsable) {
    return res.status(400).json({ ok: false, code: "RESPONSABLE_REQUERIDO", message: "Selecciona al responsable del seguimiento." });
  }
  if (!fechaApertura) {
    return res.status(400).json({ ok: false, code: "FECHA_APERTURA_INVALIDA", message: "Selecciona una fecha y hora de apertura válidas." });
  }
  if (!comentarioApertura) {
    return res.status(400).json({ ok: false, code: "COMENTARIO_APERTURA_REQUERIDO", message: "Escribe el motivo por el que se abre este seguimiento." });
  }

  const connection = await pool.getConnection();
  const idSeguimiento = crypto.randomUUID();
  try {
    await connection.beginTransaction();
    if (!(await validarAlumno(connection, idAlumno))) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "ALUMNO_INVALIDO", message: "El alumno indicado no está disponible." });
    }
    if (!(await validarResponsable(connection, idUsuarioResponsable))) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "RESPONSABLE_INVALIDO", message: "El responsable indicado no está disponible." });
    }

    await connection.query(
      `INSERT INTO alumnos_seguimientos (
        id_seguimiento, IdAlumno, IdUsuarioResponsable, Status,
        FechaApertura, ComentarioApertura, FechaCierre, ComentarioCierre
      ) VALUES (?, ?, ?, 'Abierto', ?, ?, NULL, NULL)`,
      [idSeguimiento, idAlumno, idUsuarioResponsable, fechaApertura, comentarioApertura]
    );

    const despues = {
      id_seguimiento: idSeguimiento,
      IdAlumno: idAlumno,
      IdUsuarioResponsable: idUsuarioResponsable,
      Status: "Abierto",
      FechaApertura: fechaApertura,
      ComentarioApertura: comentarioApertura,
      FechaCierre: null,
      ComentarioCierre: null
    };
    await registrarAuditoria(connection, req, "SEGUIMIENTO_CREADO", idSeguimiento, null, despues);
    const creado = await consultarSeguimiento(connection, idSeguimiento);
    await connection.commit();
    return res.status(201).json({
      ok: true,
      message: "Seguimiento abierto correctamente.",
      data: creado ? { ...creado, SeguimientoPropio: String(creado.IdUsuarioResponsable) === String(req.auth.id_usuario) } : despues
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD SEGUIMIENTOS] Error creando", { id_alumno: idAlumno, id_usuario: req.auth?.id_usuario, message: error?.message, code: error?.code });
    return res.status(500).json({ ok: false, code: "ERROR_CREANDO_SEGUIMIENTO", message: "No pudimos abrir el seguimiento." });
  } finally { connection.release(); }
});

router.patch("/:id_seguimiento", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;
  const idSeguimiento = normalizarTexto(req.params.id_seguimiento);
  if (!idSeguimiento) return res.status(400).json({ ok: false, code: "SEGUIMIENTO_REQUERIDO", message: "El seguimiento indicado no es válido." });

  const tieneResponsable = Object.prototype.hasOwnProperty.call(req.body || {}, "id_usuario") || Object.prototype.hasOwnProperty.call(req.body || {}, "id_usuario_responsable");
  const tieneFechaApertura = Object.prototype.hasOwnProperty.call(req.body || {}, "fecha_apertura");
  const tieneComentarioApertura = Object.prototype.hasOwnProperty.call(req.body || {}, "comentario_apertura");
  const tieneStatus = Object.prototype.hasOwnProperty.call(req.body || {}, "status");
  const tieneComentarioCierre = Object.prototype.hasOwnProperty.call(req.body || {}, "comentario_cierre");
  if (!tieneResponsable && !tieneFechaApertura && !tieneComentarioApertura && !tieneStatus && !tieneComentarioCierre) {
    return res.status(400).json({ ok: false, code: "SIN_CAMBIOS", message: "No hay cambios para guardar." });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.query(
      `SELECT id_seguimiento, IdAlumno, IdUsuarioResponsable, Status, FechaApertura, ComentarioApertura, FechaCierre, ComentarioCierre
       FROM alumnos_seguimientos WHERE id_seguimiento = ? LIMIT 1 FOR UPDATE`,
      [idSeguimiento]
    );
    if (!rows.length) { await connection.rollback(); return res.status(404).json({ ok: false, code: "SEGUIMIENTO_NO_ENCONTRADO", message: "No encontramos ese seguimiento." }); }
    const antes = rows[0];
    if (antes.Status === "Cerrado") { await connection.rollback(); return res.status(409).json({ ok: false, code: "SEGUIMIENTO_CERRADO", message: "Este seguimiento ya está cerrado y no puede editarse." }); }

    let idUsuarioResponsable = antes.IdUsuarioResponsable;
    let fechaApertura = antes.FechaApertura;
    let comentarioApertura = antes.ComentarioApertura;
    let status = antes.Status;
    let fechaCierre = antes.FechaCierre;
    let comentarioCierre = antes.ComentarioCierre;

    if (tieneResponsable) {
      idUsuarioResponsable = normalizarTexto(req.body?.id_usuario ?? req.body?.id_usuario_responsable);
      if (!idUsuarioResponsable) { await connection.rollback(); return res.status(400).json({ ok: false, code: "RESPONSABLE_REQUERIDO", message: "Selecciona al responsable del seguimiento." }); }
      if (!(await validarResponsable(connection, idUsuarioResponsable))) { await connection.rollback(); return res.status(400).json({ ok: false, code: "RESPONSABLE_INVALIDO", message: "El responsable indicado no está disponible." }); }
    }

    if (tieneFechaApertura) {
      fechaApertura = normalizarFechaHoraLocal(req.body?.fecha_apertura);
      if (!fechaApertura) { await connection.rollback(); return res.status(400).json({ ok: false, code: "FECHA_APERTURA_INVALIDA", message: "Selecciona una fecha y hora de apertura válidas." }); }
    }
    if (tieneComentarioApertura) {
      comentarioApertura = normalizarTexto(req.body?.comentario_apertura);
      if (!comentarioApertura) { await connection.rollback(); return res.status(400).json({ ok: false, code: "COMENTARIO_APERTURA_REQUERIDO", message: "El motivo de apertura no puede quedar vacío." }); }
    }

    if (tieneStatus) {
      const statusSolicitado = normalizarTexto(req.body?.status);
      if (!["Abierto", "Cerrado"].includes(statusSolicitado)) { await connection.rollback(); return res.status(400).json({ ok: false, code: "STATUS_SEGUIMIENTO_INVALIDO", message: "Selecciona un status de seguimiento válido." }); }
      if (statusSolicitado === "Cerrado") {
        comentarioCierre = normalizarTexto(req.body?.comentario_cierre);
        if (!comentarioCierre) { await connection.rollback(); return res.status(400).json({ ok: false, code: "COMENTARIO_CIERRE_REQUERIDO", message: "Escribe el motivo o resultado del cierre del seguimiento." }); }
        status = "Cerrado";
        fechaCierre = fechaMexicoAhora();
      } else if (tieneComentarioCierre) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "CIERRE_INVALIDO", message: "El motivo de cierre solo puede registrarse al cerrar el seguimiento." });
      }
    } else if (tieneComentarioCierre) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "CIERRE_INVALIDO", message: "El motivo de cierre solo puede registrarse al cerrar el seguimiento." });
    }

    const despues = { id_seguimiento: antes.id_seguimiento, IdAlumno: antes.IdAlumno, IdUsuarioResponsable: idUsuarioResponsable, Status: status, FechaApertura: fechaApertura, ComentarioApertura: comentarioApertura, FechaCierre: fechaCierre, ComentarioCierre: comentarioCierre };
    await connection.query(
      `UPDATE alumnos_seguimientos SET IdUsuarioResponsable = ?, Status = ?, FechaApertura = ?, ComentarioApertura = ?, FechaCierre = ?, ComentarioCierre = ? WHERE id_seguimiento = ?`,
      [despues.IdUsuarioResponsable, despues.Status, despues.FechaApertura, despues.ComentarioApertura, despues.FechaCierre, despues.ComentarioCierre, idSeguimiento]
    );
    await registrarAuditoria(connection, req, "SEGUIMIENTO_ACTUALIZADO", idSeguimiento, antes, despues);
    const actualizado = await consultarSeguimiento(connection, idSeguimiento);
    await connection.commit();
    return res.json({
      ok: true,
      message: despues.Status === "Cerrado" ? "Seguimiento cerrado correctamente." : "Seguimiento actualizado correctamente.",
      data: actualizado ? { ...actualizado, SeguimientoPropio: String(actualizado.IdUsuarioResponsable) === String(req.auth.id_usuario) } : despues
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD SEGUIMIENTOS] Error actualizando", { id_seguimiento: idSeguimiento, id_usuario: req.auth?.id_usuario, message: error?.message, code: error?.code });
    return res.status(500).json({ ok: false, code: "ERROR_ACTUALIZANDO_SEGUIMIENTO", message: "No pudimos guardar los cambios del seguimiento." });
  } finally { connection.release(); }
});

router.delete("/:id_seguimiento", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;
  const idSeguimiento = normalizarTexto(req.params.id_seguimiento);
  if (!idSeguimiento) return res.status(400).json({ ok: false, code: "SEGUIMIENTO_REQUERIDO", message: "El seguimiento indicado no es válido." });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.query(
      `SELECT id_seguimiento, IdAlumno, IdUsuarioResponsable, Status, FechaApertura, ComentarioApertura, FechaCierre, ComentarioCierre
       FROM alumnos_seguimientos WHERE id_seguimiento = ? LIMIT 1 FOR UPDATE`,
      [idSeguimiento]
    );
    if (!rows.length) { await connection.rollback(); return res.status(404).json({ ok: false, code: "SEGUIMIENTO_NO_ENCONTRADO", message: "No encontramos ese seguimiento." }); }
    const antes = rows[0];
    const [detalles] = await connection.query(`SELECT * FROM alumnos_seguimiento_detalle WHERE id_seguimiento = ? ORDER BY FechaRegistro ASC, id_detalle ASC`, [idSeguimiento]);
    await registrarAuditoria(connection, req, "SEGUIMIENTO_ELIMINADO", idSeguimiento, { seguimiento: antes, detalles }, null);
    await connection.query(`DELETE FROM alumnos_seguimientos WHERE id_seguimiento = ?`, [idSeguimiento]);
    await connection.commit();
    return res.json({ ok: true, message: "Seguimiento eliminado correctamente.", data: { id_seguimiento: idSeguimiento } });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD SEGUIMIENTOS] Error eliminando", { id_seguimiento: idSeguimiento, id_usuario: req.auth?.id_usuario, message: error?.message, code: error?.code });
    return res.status(500).json({ ok: false, code: "ERROR_ELIMINANDO_SEGUIMIENTO", message: "No pudimos eliminar el seguimiento." });
  } finally { connection.release(); }
});

module.exports = router;
