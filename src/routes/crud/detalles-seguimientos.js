const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

const TIPOS_REGISTRO = {
  nota: "Nota",
  contacto: "Contacto",
  reunion: "Reunion"
};

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

function normalizarTipo(valor) {
  const clave = String(valor ?? "").trim().toLowerCase();
  return TIPOS_REGISTRO[clave] || null;
}

function normalizarBooleano(valor) {
  if (valor === true || valor === 1 || valor === "1" || valor === "true") return true;
  if (valor === false || valor === 0 || valor === "0" || valor === "false") return false;
  return null;
}

function normalizarFecha(valor) {
  const texto = String(valor ?? "").trim();
  const match = texto.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;

  const [, anio, mes, dia] = match;
  const prueba = new Date(Date.UTC(Number(anio), Number(mes) - 1, Number(dia)));
  if (
    prueba.getUTCFullYear() !== Number(anio) ||
    prueba.getUTCMonth() !== Number(mes) - 1 ||
    prueba.getUTCDate() !== Number(dia)
  ) {
    return null;
  }
  return `${anio}-${mes}-${dia}`;
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

async function registrarAuditoria(connection, req, evento, idRegistro, antes, despues) {
  await connection.query(
    `
    INSERT INTO auditoria_eventos (
      actor_tipo, actor_id, evento, entidad, id_registro, antes_json, despues_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      "INTERNO",
      String(req.auth.id_usuario),
      evento,
      "alumnos_seguimiento_detalle",
      idRegistro,
      antes == null ? null : JSON.stringify(antes),
      despues == null ? null : JSON.stringify(despues)
    ]
  );
}

async function consultarDetalle(connection, idDetalle) {
  const [rows] = await connection.query(
    `SELECT * FROM vw_company_viewer_alumnos_seguimiento_detalle WHERE id_detalle = ? LIMIT 1`,
    [idDetalle]
  );
  return rows[0] || null;
}

function validarProximo(req, res, actual = null) {
  const tieneRequiere = Object.prototype.hasOwnProperty.call(
    req.body || {},
    "requiere_proximo_seguimiento"
  );
  const tieneFecha = Object.prototype.hasOwnProperty.call(
    req.body || {},
    "fecha_proximo_seguimiento"
  );

  let requiere = actual ? Boolean(actual.RequiereProximoSeguimiento) : false;
  let fecha = actual?.FechaProximoSeguimiento ?? null;

  if (tieneRequiere) {
    const valor = normalizarBooleano(req.body?.requiere_proximo_seguimiento);
    if (valor === null) {
      res.status(400).json({
        ok: false,
        code: "PROXIMO_SEGUIMIENTO_INVALIDO",
        message: "Indica si este registro requiere un próximo seguimiento."
      });
      return null;
    }
    requiere = valor;
  }

  if (!actual && !tieneRequiere) {
    requiere = false;
  }

  if (!requiere) {
    return { requiere: false, fecha: null };
  }

  if (tieneFecha || !fecha) {
    fecha = normalizarFecha(req.body?.fecha_proximo_seguimiento);
  }

  if (!fecha) {
    res.status(400).json({
      ok: false,
      code: "FECHA_PROXIMO_SEGUIMIENTO_REQUERIDA",
      message: "Selecciona la fecha del próximo seguimiento."
    });
    return null;
  }

  return { requiere: true, fecha };
}

function validarCamposTipo(req, res, tipoRegistro, actuales = null) {
  let formaContacto = actuales?.FormaContacto ?? null;
  let resultadoContacto = actuales?.ResultadoContacto ?? null;

  if (Object.prototype.hasOwnProperty.call(req.body || {}, "resultado_contacto") || !actuales) {
    resultadoContacto = normalizarTexto(req.body?.resultado_contacto);
  }

  if (!resultadoContacto) {
    res.status(400).json({
      ok: false,
      code: "RESULTADO_CONTACTO_REQUERIDO",
      message: tipoRegistro === "Nota"
        ? "Escribe un título breve para la nota."
        : "Escribe el resultado de este seguimiento."
    });
    return null;
  }

  if (tipoRegistro === "Nota") {
    formaContacto = null;
  } else {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "forma_contacto") || !actuales) {
      formaContacto = normalizarTexto(req.body?.forma_contacto);
    }

    if (!formaContacto) {
      res.status(400).json({
        ok: false,
        code: "FORMA_CONTACTO_REQUERIDA",
        message: tipoRegistro === "Reunion"
          ? "Selecciona si la reunión fue virtual o presencial."
          : "Selecciona la forma de contacto."
      });
      return null;
    }
  }

  return { formaContacto, resultadoContacto };
}

function visibleClienteDesdeBody(req, res, actual = true) {
  if (!Object.prototype.hasOwnProperty.call(req.body || {}, "visible_cliente")) {
    return actual;
  }

  const valor = normalizarBooleano(req.body?.visible_cliente);
  if (valor === null) {
    res.status(400).json({
      ok: false,
      code: "VISIBLE_CLIENTE_INVALIDO",
      message: "Indica si este registro será visible para el plantel."
    });
    return null;
  }
  return valor;
}

router.post("/", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  const idSeguimiento = normalizarTexto(req.body?.id_seguimiento);
  const tipoRegistro = normalizarTipo(req.body?.tipo_registro);
  const comentario = normalizarTexto(req.body?.comentario);

  if (!idSeguimiento) {
    return res.status(400).json({
      ok: false,
      code: "SEGUIMIENTO_REQUERIDO",
      message: "Selecciona el seguimiento al que pertenece este registro."
    });
  }

  if (!tipoRegistro) {
    return res.status(400).json({
      ok: false,
      code: "TIPO_REGISTRO_INVALIDO",
      message: "Selecciona un tipo de registro válido."
    });
  }

  const camposTipo = validarCamposTipo(req, res, tipoRegistro);
  if (!camposTipo) return;

  const proximo = validarProximo(req, res);
  if (!proximo) return;

  const visibleCliente = visibleClienteDesdeBody(req, res, true);
  if (visibleCliente === null) return;

  const idDetalle = crypto.randomUUID();
  const fechaRegistro = fechaMexicoAhora();
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [seguimientos] = await connection.query(
      `SELECT id_seguimiento, Status FROM alumnos_seguimientos WHERE id_seguimiento = ? LIMIT 1 FOR UPDATE`,
      [idSeguimiento]
    );

    if (!seguimientos.length) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "SEGUIMIENTO_NO_ENCONTRADO",
        message: "No encontramos ese seguimiento."
      });
    }

    if (seguimientos[0].Status === "Cerrado") {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "SEGUIMIENTO_CERRADO",
        message: "No puedes agregar registros a un seguimiento cerrado."
      });
    }

    const despues = {
      id_detalle: idDetalle,
      id_seguimiento: idSeguimiento,
      IdUsuario: String(req.auth.id_usuario),
      FechaRegistro: fechaRegistro,
      TipoRegistro: tipoRegistro,
      FormaContacto: camposTipo.formaContacto,
      ResultadoContacto: camposTipo.resultadoContacto,
      Comentario: comentario,
      RequiereProximoSeguimiento: proximo.requiere ? 1 : 0,
      FechaProximoSeguimiento: proximo.fecha,
      VisibleCliente: visibleCliente ? 1 : 0
    };

    await connection.query(
      `
      INSERT INTO alumnos_seguimiento_detalle (
        id_detalle, id_seguimiento, IdUsuario, FechaRegistro, TipoRegistro,
        FormaContacto, ResultadoContacto, Comentario,
        RequiereProximoSeguimiento, FechaProximoSeguimiento, VisibleCliente
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        despues.id_detalle,
        despues.id_seguimiento,
        despues.IdUsuario,
        despues.FechaRegistro,
        despues.TipoRegistro,
        despues.FormaContacto,
        despues.ResultadoContacto,
        despues.Comentario,
        despues.RequiereProximoSeguimiento,
        despues.FechaProximoSeguimiento,
        despues.VisibleCliente
      ]
    );

    await registrarAuditoria(
      connection,
      req,
      "SEGUIMIENTO_DETALLE_CREADO",
      idDetalle,
      null,
      despues
    );

    const creado = await consultarDetalle(connection, idDetalle);
    await connection.commit();

    return res.status(201).json({
      ok: true,
      message: "Registro agregado al seguimiento.",
      data: creado || despues
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD DETALLES SEGUIMIENTOS] Error creando", {
      id_seguimiento: idSeguimiento,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });
    return res.status(500).json({
      ok: false,
      code: "ERROR_CREANDO_DETALLE_SEGUIMIENTO",
      message: "No pudimos agregar el registro al seguimiento."
    });
  } finally {
    connection.release();
  }
});

router.patch("/:id_detalle", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  const idDetalle = normalizarTexto(req.params.id_detalle);
  if (!idDetalle) {
    return res.status(400).json({
      ok: false,
      code: "DETALLE_REQUERIDO",
      message: "El registro indicado no es válido."
    });
  }

  const camposPermitidos = [
    "tipo_registro",
    "forma_contacto",
    "resultado_contacto",
    "comentario",
    "requiere_proximo_seguimiento",
    "fecha_proximo_seguimiento",
    "visible_cliente"
  ];

  if (!camposPermitidos.some((campo) => Object.prototype.hasOwnProperty.call(req.body || {}, campo))) {
    return res.status(400).json({
      ok: false,
      code: "SIN_CAMBIOS",
      message: "No hay cambios para guardar."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [rows] = await connection.query(
      `
      SELECT
        d.id_detalle, d.id_seguimiento, d.IdUsuario, d.FechaRegistro,
        d.TipoRegistro, d.FormaContacto, d.ResultadoContacto, d.Comentario,
        d.RequiereProximoSeguimiento, d.FechaProximoSeguimiento, d.VisibleCliente,
        s.Status AS StatusSeguimiento
      FROM alumnos_seguimiento_detalle d
      INNER JOIN alumnos_seguimientos s ON s.id_seguimiento = d.id_seguimiento
      WHERE d.id_detalle = ?
      LIMIT 1
      FOR UPDATE
      `,
      [idDetalle]
    );

    if (!rows.length) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "DETALLE_NO_ENCONTRADO",
        message: "No encontramos ese registro de seguimiento."
      });
    }

    const fila = rows[0];
    if (fila.StatusSeguimiento === "Cerrado") {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "SEGUIMIENTO_CERRADO",
        message: "No puedes modificar el historial de un seguimiento cerrado."
      });
    }

    const antes = {
      id_detalle: fila.id_detalle,
      id_seguimiento: fila.id_seguimiento,
      IdUsuario: fila.IdUsuario,
      FechaRegistro: fila.FechaRegistro,
      TipoRegistro: fila.TipoRegistro,
      FormaContacto: fila.FormaContacto,
      ResultadoContacto: fila.ResultadoContacto,
      Comentario: fila.Comentario,
      RequiereProximoSeguimiento: fila.RequiereProximoSeguimiento,
      FechaProximoSeguimiento: fila.FechaProximoSeguimiento,
      VisibleCliente: fila.VisibleCliente
    };

    let tipoRegistro = fila.TipoRegistro;
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "tipo_registro")) {
      tipoRegistro = normalizarTipo(req.body?.tipo_registro);
      if (!tipoRegistro) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          code: "TIPO_REGISTRO_INVALIDO",
          message: "Selecciona un tipo de registro válido."
        });
      }
    }

    const camposTipo = validarCamposTipo(req, res, tipoRegistro, fila);
    if (!camposTipo) {
      await connection.rollback();
      return;
    }

    let comentario = fila.Comentario;
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "comentario")) {
      comentario = normalizarTexto(req.body?.comentario);
    }

    const proximo = validarProximo(req, res, fila);
    if (!proximo) {
      await connection.rollback();
      return;
    }

    const visibleCliente = visibleClienteDesdeBody(req, res, Boolean(fila.VisibleCliente));
    if (visibleCliente === null) {
      await connection.rollback();
      return;
    }

    const despues = {
      id_detalle: fila.id_detalle,
      id_seguimiento: fila.id_seguimiento,
      IdUsuario: fila.IdUsuario,
      FechaRegistro: fila.FechaRegistro,
      TipoRegistro: tipoRegistro,
      FormaContacto: camposTipo.formaContacto,
      ResultadoContacto: camposTipo.resultadoContacto,
      Comentario: comentario,
      RequiereProximoSeguimiento: proximo.requiere ? 1 : 0,
      FechaProximoSeguimiento: proximo.fecha,
      VisibleCliente: visibleCliente ? 1 : 0
    };

    await connection.query(
      `
      UPDATE alumnos_seguimiento_detalle
      SET TipoRegistro = ?, FormaContacto = ?, ResultadoContacto = ?, Comentario = ?,
          RequiereProximoSeguimiento = ?, FechaProximoSeguimiento = ?, VisibleCliente = ?
      WHERE id_detalle = ?
      `,
      [
        despues.TipoRegistro,
        despues.FormaContacto,
        despues.ResultadoContacto,
        despues.Comentario,
        despues.RequiereProximoSeguimiento,
        despues.FechaProximoSeguimiento,
        despues.VisibleCliente,
        idDetalle
      ]
    );

    await registrarAuditoria(
      connection,
      req,
      "SEGUIMIENTO_DETALLE_ACTUALIZADO",
      idDetalle,
      antes,
      despues
    );

    const actualizado = await consultarDetalle(connection, idDetalle);
    await connection.commit();

    return res.json({
      ok: true,
      message: "Registro de seguimiento actualizado correctamente.",
      data: actualizado || despues
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD DETALLES SEGUIMIENTOS] Error actualizando", {
      id_detalle: idDetalle,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });
    return res.status(500).json({
      ok: false,
      code: "ERROR_ACTUALIZANDO_DETALLE_SEGUIMIENTO",
      message: "No pudimos guardar los cambios del registro."
    });
  } finally {
    connection.release();
  }
});

router.delete("/:id_detalle", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  const idDetalle = normalizarTexto(req.params.id_detalle);
  if (!idDetalle) {
    return res.status(400).json({
      ok: false,
      code: "DETALLE_REQUERIDO",
      message: "El registro indicado no es válido."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [rows] = await connection.query(
      `
      SELECT
        d.id_detalle, d.id_seguimiento, d.IdUsuario, d.FechaRegistro,
        d.TipoRegistro, d.FormaContacto, d.ResultadoContacto, d.Comentario,
        d.RequiereProximoSeguimiento, d.FechaProximoSeguimiento, d.VisibleCliente,
        s.Status AS StatusSeguimiento
      FROM alumnos_seguimiento_detalle d
      INNER JOIN alumnos_seguimientos s ON s.id_seguimiento = d.id_seguimiento
      WHERE d.id_detalle = ?
      LIMIT 1
      FOR UPDATE
      `,
      [idDetalle]
    );

    if (!rows.length) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "DETALLE_NO_ENCONTRADO",
        message: "No encontramos ese registro de seguimiento."
      });
    }

    const fila = rows[0];
    if (fila.StatusSeguimiento === "Cerrado") {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "SEGUIMIENTO_CERRADO",
        message: "No puedes modificar el historial de un seguimiento cerrado."
      });
    }

    const antes = {
      id_detalle: fila.id_detalle,
      id_seguimiento: fila.id_seguimiento,
      IdUsuario: fila.IdUsuario,
      FechaRegistro: fila.FechaRegistro,
      TipoRegistro: fila.TipoRegistro,
      FormaContacto: fila.FormaContacto,
      ResultadoContacto: fila.ResultadoContacto,
      Comentario: fila.Comentario,
      RequiereProximoSeguimiento: fila.RequiereProximoSeguimiento,
      FechaProximoSeguimiento: fila.FechaProximoSeguimiento,
      VisibleCliente: fila.VisibleCliente
    };

    await registrarAuditoria(
      connection,
      req,
      "SEGUIMIENTO_DETALLE_ELIMINADO",
      idDetalle,
      antes,
      null
    );

    await connection.query(
      `DELETE FROM alumnos_seguimiento_detalle WHERE id_detalle = ?`,
      [idDetalle]
    );

    await connection.commit();

    return res.json({
      ok: true,
      message: "Registro de seguimiento eliminado correctamente.",
      data: { id_detalle: idDetalle, id_seguimiento: fila.id_seguimiento }
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD DETALLES SEGUIMIENTOS] Error eliminando", {
      id_detalle: idDetalle,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });
    return res.status(500).json({
      ok: false,
      code: "ERROR_ELIMINANDO_DETALLE_SEGUIMIENTO",
      message: "No pudimos eliminar el registro de seguimiento."
    });
  } finally {
    connection.release();
  }
});

module.exports = router;
