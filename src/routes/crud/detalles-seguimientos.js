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
  if (valor === true || valor === 1 || valor === "1" || valor === "true") {
    return true;
  }

  if (
    valor === false ||
    valor === 0 ||
    valor === "0" ||
    valor === "false"
  ) {
    return false;
  }

  return null;
}

function normalizarFecha(valor) {
  const texto = String(valor ?? "").trim();
  const match = texto.match(/^(\d{4})-(\d{2})-(\d{2})$/);

  if (!match) return null;

  const [, anio, mes, dia] = match;
  const y = Number(anio);
  const m = Number(mes);
  const d = Number(dia);
  const prueba = new Date(Date.UTC(y, m - 1, d));

  if (
    prueba.getUTCFullYear() !== y ||
    prueba.getUTCMonth() !== m - 1 ||
    prueba.getUTCDate() !== d
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
      "alumnos_seguimiento_detalle",
      idRegistro,
      antes == null ? null : JSON.stringify(antes),
      despues == null ? null : JSON.stringify(despues)
    ]
  );
}

async function consultarDetalle(connection, idDetalle) {
  const [rows] = await connection.query(
    `
    SELECT *
    FROM vw_company_viewer_alumnos_seguimiento_detalle
    WHERE id_detalle = ?
    LIMIT 1
    `,
    [idDetalle]
  );

  return rows[0] || null;
}

function validarProximoSeguimiento(req, res) {
  const requiere = normalizarBooleano(req.body?.requiere_proximo_seguimiento);

  if (requiere === null) {
    res.status(400).json({
      ok: false,
      code: "PROXIMO_SEGUIMIENTO_INVALIDO",
      message: "Indica si este registro requiere un próximo seguimiento."
    });
    return null;
  }

  if (!requiere) {
    return {
      requiere: false,
      fecha: null
    };
  }

  const fecha = normalizarFecha(req.body?.fecha_proximo_seguimiento);

  if (!fecha) {
    res.status(400).json({
      ok: false,
      code: "FECHA_PROXIMO_SEGUIMIENTO_REQUERIDA",
      message: "Selecciona la fecha del próximo seguimiento."
    });
    return null;
  }

  return {
    requiere: true,
    fecha
  };
}

// ======================================================
// POST /crud/detalles-seguimientos
// ======================================================

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

  const proximo = validarProximoSeguimiento(req, res);
  if (!proximo) return;

  const formaContacto =
    tipoRegistro === "Contacto"
      ? normalizarTexto(req.body?.forma_contacto)
      : null;
  const resultadoContacto =
    tipoRegistro === "Contacto"
      ? normalizarTexto(req.body?.resultado_contacto)
      : null;

  const idDetalle = crypto.randomUUID();
  const fechaRegistro = fechaMexicoAhora();
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [seguimientos] = await connection.query(
      `
      SELECT id_seguimiento, Status
      FROM alumnos_seguimientos
      WHERE id_seguimiento = ?
      LIMIT 1
      FOR UPDATE
      `,
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
      FormaContacto: formaContacto,
      ResultadoContacto: resultadoContacto,
      Comentario: comentario,
      RequiereProximoSeguimiento: proximo.requiere ? 1 : 0,
      FechaProximoSeguimiento: proximo.fecha
    };

    await connection.query(
      `
      INSERT INTO alumnos_seguimiento_detalle (
        id_detalle,
        id_seguimiento,
        IdUsuario,
        FechaRegistro,
        TipoRegistro,
        FormaContacto,
        ResultadoContacto,
        Comentario,
        RequiereProximoSeguimiento,
        FechaProximoSeguimiento
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        despues.FechaProximoSeguimiento
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
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

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

// ======================================================
// PATCH /crud/detalles-seguimientos/:id_detalle
// ======================================================

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
    "fecha_proximo_seguimiento"
  ];

  const tieneCambios = camposPermitidos.some((campo) =>
    Object.prototype.hasOwnProperty.call(req.body || {}, campo)
  );

  if (!tieneCambios) {
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
        d.id_detalle,
        d.id_seguimiento,
        d.IdUsuario,
        d.FechaRegistro,
        d.TipoRegistro,
        d.FormaContacto,
        d.ResultadoContacto,
        d.Comentario,
        d.RequiereProximoSeguimiento,
        d.FechaProximoSeguimiento,
        s.Status AS StatusSeguimiento
      FROM alumnos_seguimiento_detalle d
      INNER JOIN alumnos_seguimientos s
        ON s.id_seguimiento = d.id_seguimiento
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
      FechaProximoSeguimiento: fila.FechaProximoSeguimiento
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

    let comentario = fila.Comentario;
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "comentario")) {
      comentario = normalizarTexto(req.body?.comentario);
    }

    let formaContacto = fila.FormaContacto;
    let resultadoContacto = fila.ResultadoContacto;

    if (tipoRegistro === "Contacto") {
      if (
        Object.prototype.hasOwnProperty.call(req.body || {}, "forma_contacto")
      ) {
        formaContacto = normalizarTexto(req.body?.forma_contacto);
      }

      if (
        Object.prototype.hasOwnProperty.call(
          req.body || {},
          "resultado_contacto"
        )
      ) {
        resultadoContacto = normalizarTexto(req.body?.resultado_contacto);
      }
    } else {
      formaContacto = null;
      resultadoContacto = null;
    }

    let requiereProximo = Boolean(fila.RequiereProximoSeguimiento);
    let fechaProximo = fila.FechaProximoSeguimiento;

    if (
      Object.prototype.hasOwnProperty.call(
        req.body || {},
        "requiere_proximo_seguimiento"
      )
    ) {
      const valor = normalizarBooleano(req.body?.requiere_proximo_seguimiento);

      if (valor === null) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          code: "PROXIMO_SEGUIMIENTO_INVALIDO",
          message: "Indica si este registro requiere un próximo seguimiento."
        });
      }

      requiereProximo = valor;
    }

    if (requiereProximo) {
      if (
        Object.prototype.hasOwnProperty.call(
          req.body || {},
          "fecha_proximo_seguimiento"
        )
      ) {
        fechaProximo = normalizarFecha(req.body?.fecha_proximo_seguimiento);
      }

      if (!fechaProximo) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          code: "FECHA_PROXIMO_SEGUIMIENTO_REQUERIDA",
          message: "Selecciona la fecha del próximo seguimiento."
        });
      }
    } else {
      fechaProximo = null;
    }

    const despues = {
      id_detalle: fila.id_detalle,
      id_seguimiento: fila.id_seguimiento,
      IdUsuario: fila.IdUsuario,
      FechaRegistro: fila.FechaRegistro,
      TipoRegistro: tipoRegistro,
      FormaContacto: formaContacto,
      ResultadoContacto: resultadoContacto,
      Comentario: comentario,
      RequiereProximoSeguimiento: requiereProximo ? 1 : 0,
      FechaProximoSeguimiento: fechaProximo
    };

    await connection.query(
      `
      UPDATE alumnos_seguimiento_detalle
      SET
        TipoRegistro = ?,
        FormaContacto = ?,
        ResultadoContacto = ?,
        Comentario = ?,
        RequiereProximoSeguimiento = ?,
        FechaProximoSeguimiento = ?
      WHERE id_detalle = ?
      `,
      [
        despues.TipoRegistro,
        despues.FormaContacto,
        despues.ResultadoContacto,
        despues.Comentario,
        despues.RequiereProximoSeguimiento,
        despues.FechaProximoSeguimiento,
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
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

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

// ======================================================
// DELETE /crud/detalles-seguimientos/:id_detalle
// ======================================================

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
        d.id_detalle,
        d.id_seguimiento,
        d.IdUsuario,
        d.FechaRegistro,
        d.TipoRegistro,
        d.FormaContacto,
        d.ResultadoContacto,
        d.Comentario,
        d.RequiereProximoSeguimiento,
        d.FechaProximoSeguimiento,
        s.Status AS StatusSeguimiento
      FROM alumnos_seguimiento_detalle d
      INNER JOIN alumnos_seguimientos s
        ON s.id_seguimiento = d.id_seguimiento
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
      FechaProximoSeguimiento: fila.FechaProximoSeguimiento
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
      `
      DELETE FROM alumnos_seguimiento_detalle
      WHERE id_detalle = ?
      `,
      [idDetalle]
    );

    await connection.commit();

    return res.json({
      ok: true,
      message: "Registro de seguimiento eliminado correctamente.",
      data: {
        id_detalle: idDetalle,
        id_seguimiento: fila.id_seguimiento
      }
    });
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

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
