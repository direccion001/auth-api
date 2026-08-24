const express = require("express");

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

// ======================================================
// PATCH /crud/seguimientos/:id_seguimiento/estado
// Cierra o reabre un seguimiento desde el toggle del viewer.
// ======================================================

router.patch("/:id_seguimiento/estado", async (req, res) => {
  if (!permitirSeguimientos(req, res)) return;

  const idSeguimiento = normalizarTexto(req.params.id_seguimiento);
  const statusSolicitado = normalizarTexto(req.body?.status);
  const motivo = normalizarTexto(req.body?.motivo);

  if (!idSeguimiento) {
    return res.status(400).json({
      ok: false,
      code: "SEGUIMIENTO_REQUERIDO",
      message: "El seguimiento indicado no es válido."
    });
  }

  if (!["Abierto", "Cerrado"].includes(statusSolicitado)) {
    return res.status(400).json({
      ok: false,
      code: "STATUS_SEGUIMIENTO_INVALIDO",
      message: "Selecciona un status de seguimiento válido."
    });
  }

  if (!motivo) {
    return res.status(400).json({
      ok: false,
      code:
        statusSolicitado === "Cerrado"
          ? "COMENTARIO_CIERRE_REQUERIDO"
          : "MOTIVO_REAPERTURA_REQUERIDO",
      message:
        statusSolicitado === "Cerrado"
          ? "Escribe el motivo o resultado del cierre del seguimiento."
          : "Escribe el motivo de reapertura del seguimiento."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [rows] = await connection.query(
      `
      SELECT
        id_seguimiento,
        IdAlumno,
        IdUsuarioResponsable,
        Status,
        FechaApertura,
        ComentarioApertura,
        FechaCierre,
        ComentarioCierre
      FROM alumnos_seguimientos
      WHERE id_seguimiento = ?
      LIMIT 1
      FOR UPDATE
      `,
      [idSeguimiento]
    );

    if (!rows.length) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "SEGUIMIENTO_NO_ENCONTRADO",
        message: "No encontramos ese seguimiento."
      });
    }

    const antes = rows[0];

    if (antes.Status === statusSolicitado) {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "STATUS_SIN_CAMBIOS",
        message:
          statusSolicitado === "Cerrado"
            ? "Este seguimiento ya está cerrado."
            : "Este seguimiento ya está abierto."
      });
    }

    let fechaCierre = antes.FechaCierre;
    let comentarioCierre = antes.ComentarioCierre;
    let evento;
    let mensaje;

    if (statusSolicitado === "Cerrado") {
      fechaCierre = fechaMexicoAhora();
      comentarioCierre = motivo;
      evento = "SEGUIMIENTO_CERRADO";
      mensaje = "Seguimiento cerrado correctamente.";
    } else {
      // Al reabrir se conserva el motivo original de apertura y se limpia
      // completamente la información del cierre anterior.
      fechaCierre = null;
      comentarioCierre = null;
      evento = "SEGUIMIENTO_REABIERTO";
      mensaje = "Seguimiento reabierto correctamente.";
    }

    await connection.query(
      `
      UPDATE alumnos_seguimientos
      SET
        Status = ?,
        FechaCierre = ?,
        ComentarioCierre = ?
      WHERE id_seguimiento = ?
      `,
      [statusSolicitado, fechaCierre, comentarioCierre, idSeguimiento]
    );

    const despues = {
      ...antes,
      Status: statusSolicitado,
      FechaCierre: fechaCierre,
      ComentarioCierre: comentarioCierre
    };

    // El motivo de reapertura no reemplaza ComentarioApertura; queda
    // preservado en auditoría para no destruir el motivo original del ticket.
    const despuesAuditoria =
      statusSolicitado === "Abierto"
        ? { ...despues, MotivoReapertura: motivo }
        : despues;

    await registrarAuditoria(
      connection,
      req,
      evento,
      idSeguimiento,
      antes,
      despuesAuditoria
    );

    const actualizado = await consultarSeguimiento(connection, idSeguimiento);

    await connection.commit();

    return res.json({
      ok: true,
      message: mensaje,
      data: actualizado ?? despues
    });
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

    console.error("[CRUD SEGUIMIENTOS] Error cambiando estado", {
      id_seguimiento: idSeguimiento,
      status: statusSolicitado,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CAMBIANDO_STATUS_SEGUIMIENTO",
      message: "No pudimos cambiar el estado del seguimiento."
    });
  } finally {
    connection.release();
  }
});

module.exports = router;
