const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

function permitir(req, res) {
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

function texto(value) {
  const normalized = String(value ?? "").trim();
  return normalized || null;
}

function bool(value) {
  if ([true, 1, "1", "true"].includes(value)) return true;
  if ([false, 0, "0", "false"].includes(value)) return false;
  return null;
}

function fecha(value) {
  if (value === null || value === undefined || value === "") return null;
  const raw = String(value).trim();
  const match = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return undefined;
  const [, y, m, d] = match;
  const test = new Date(Date.UTC(Number(y), Number(m) - 1, Number(d)));
  if (
    test.getUTCFullYear() !== Number(y) ||
    test.getUTCMonth() !== Number(m) - 1 ||
    test.getUTCDate() !== Number(d)
  ) {
    return undefined;
  }
  return raw;
}

router.patch("/:id_detalle/proximo", async (req, res) => {
  if (!permitir(req, res)) return;

  const idDetalle = texto(req.params.id_detalle);
  if (!idDetalle) {
    return res.status(400).json({
      ok: false,
      code: "DETALLE_REQUERIDO",
      message: "El registro indicado no es válido."
    });
  }

  const requiereRaw = Object.prototype.hasOwnProperty.call(req.body || {}, "requiere_proximo_seguimiento")
    ? bool(req.body.requiere_proximo_seguimiento)
    : null;

  const tieneFecha = Object.prototype.hasOwnProperty.call(req.body || {}, "fecha_proximo_seguimiento");
  const tieneAccion = Object.prototype.hasOwnProperty.call(req.body || {}, "proxima_accion");

  if (requiereRaw === null && !tieneFecha && !tieneAccion) {
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
        d.*,
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

    const actual = rows[0];
    if (actual.StatusSeguimiento === "Cerrado") {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "SEGUIMIENTO_CERRADO",
        message: "No puedes modificar el próximo paso de un seguimiento cerrado."
      });
    }

    const requiere = requiereRaw === null
      ? Boolean(actual.RequiereProximoSeguimiento)
      : requiereRaw;

    let fechaProxima = actual.FechaProximoSeguimiento ?? null;
    let proximaAccion = actual.ProximaAccion ?? null;

    if (!requiere) {
      fechaProxima = null;
      proximaAccion = null;
    } else {
      if (tieneFecha) {
        fechaProxima = fecha(req.body.fecha_proximo_seguimiento);
        if (fechaProxima === undefined) {
          await connection.rollback();
          return res.status(400).json({
            ok: false,
            code: "FECHA_PROXIMO_SEGUIMIENTO_INVALIDA",
            message: "Selecciona una fecha válida para el próximo seguimiento."
          });
        }
      }

      if (!fechaProxima) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          code: "FECHA_PROXIMO_SEGUIMIENTO_REQUERIDA",
          message: "Selecciona la fecha del próximo seguimiento."
        });
      }

      if (tieneAccion) {
        proximaAccion = texto(req.body.proxima_accion);
        if (proximaAccion && proximaAccion.length > 255) {
          await connection.rollback();
          return res.status(400).json({
            ok: false,
            code: "PROXIMA_ACCION_MUY_LARGA",
            message: "La próxima acción no puede exceder 255 caracteres."
          });
        }
      }
    }

    const antes = {
      RequiereProximoSeguimiento: actual.RequiereProximoSeguimiento,
      FechaProximoSeguimiento: actual.FechaProximoSeguimiento,
      ProximaAccion: actual.ProximaAccion
    };

    const despues = {
      RequiereProximoSeguimiento: requiere ? 1 : 0,
      FechaProximoSeguimiento: fechaProxima,
      ProximaAccion: proximaAccion
    };

    await connection.query(
      `
      UPDATE alumnos_seguimiento_detalle
      SET
        RequiereProximoSeguimiento = ?,
        FechaProximoSeguimiento = ?,
        ProximaAccion = ?
      WHERE id_detalle = ?
      `,
      [
        despues.RequiereProximoSeguimiento,
        despues.FechaProximoSeguimiento,
        despues.ProximaAccion,
        idDetalle
      ]
    );

    await connection.query(
      `
      INSERT INTO auditoria_eventos (
        actor_tipo, actor_id, evento, entidad, id_registro, antes_json, despues_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      [
        "INTERNO",
        String(req.auth.id_usuario),
        "SEGUIMIENTO_PROXIMO_PASO_ACTUALIZADO",
        "alumnos_seguimiento_detalle",
        idDetalle,
        JSON.stringify(antes),
        JSON.stringify(despues)
      ]
    );

    const [vista] = await connection.query(
      "SELECT * FROM vw_company_viewer_alumnos_seguimiento_detalle WHERE id_detalle = ? LIMIT 1",
      [idDetalle]
    );

    await connection.commit();

    return res.json({
      ok: true,
      message: "Próximo seguimiento actualizado correctamente.",
      data: vista[0] || { id_detalle: idDetalle, ...despues }
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD DETALLES SEGUIMIENTOS] Error actualizando próximo paso", {
      id_detalle: idDetalle,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_ACTUALIZANDO_PROXIMO_SEGUIMIENTO",
      message: "No pudimos actualizar el próximo seguimiento."
    });
  } finally {
    connection.release();
  }
});

module.exports = router;
