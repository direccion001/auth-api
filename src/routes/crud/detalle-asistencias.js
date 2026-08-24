const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

const INTENCIONES = {
  asistio: { Presente: "Asistio", Justificada: "No" },
  falto: { Presente: "Falto", Justificada: "No" },
  justifico: { Presente: "Falto", Justificada: "Si" }
};

const TITULOS = {
  justifico: [
    "Por enfermedad",
    "Por carga laboral",
    "Por asuntos personales",
    "Por vacaciones",
    "Por fallas técnicas",
    "Otro"
  ],
  asistio: [
    "Reposición de clase",
    "Otro"
  ],
  falto: [
    "Otro"
  ]
};

function normalizarTexto(valor) {
  const texto = String(valor ?? "").trim();
  return texto || null;
}

function validarTitulo(intencion, esOtro, titulo) {
  if (!titulo) return !esOtro;
  if (esOtro) return true;
  return TITULOS[intencion]?.includes(titulo) ?? false;
}

router.patch("/:idDetalle", async (req, res) => {
  if (!req.auth.modulos.includes("asistencias")) {
    return res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso a este módulo."
    });
  }

  const idDetalle = String(req.params.idDetalle || "").trim();
  const intencion = String(req.body?.intencion || "").trim().toLowerCase();
  const esOtro = Boolean(req.body?.es_otro);
  const tituloComentario = normalizarTexto(req.body?.titulo_comentario);
  const comentario = normalizarTexto(req.body?.comentario);

  if (!idDetalle) {
    return res.status(400).json({
      ok: false,
      code: "ID_DETALLE_REQUERIDO",
      message: "La asistencia indicada no es válida."
    });
  }

  if (!INTENCIONES[intencion]) {
    return res.status(400).json({
      ok: false,
      code: "INTENCION_INVALIDA",
      message: "Selecciona un estado de asistencia válido."
    });
  }

  if (!validarTitulo(intencion, esOtro, tituloComentario)) {
    return res.status(400).json({
      ok: false,
      code: "TITULO_INVALIDO",
      message: esOtro
        ? "Escribe el motivo personalizado."
        : "Selecciona un motivo válido para este estado."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [rows] = await connection.query(
      `
      SELECT
        IdDetalle,
        Presente,
        Justificada,
        TituloComentario,
        Comentario
      FROM DETALLE_ASISTENCIAS
      WHERE IdDetalle = ?
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
        message: "No encontramos ese registro de asistencia."
      });
    }

    const antes = rows[0];
    const destino = INTENCIONES[intencion];

    await connection.query(
      `
      UPDATE DETALLE_ASISTENCIAS
      SET
        Presente = ?,
        Justificada = ?,
        TituloComentario = ?,
        Comentario = ?
      WHERE IdDetalle = ?
      `,
      [
        destino.Presente,
        destino.Justificada,
        tituloComentario,
        comentario,
        idDetalle
      ]
    );

    const despues = {
      Presente: destino.Presente,
      Justificada: destino.Justificada,
      TituloComentario: tituloComentario,
      Comentario: comentario
    };

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
        "DETALLE_ASISTENCIA_ACTUALIZADO",
        "DETALLE_ASISTENCIAS",
        idDetalle,
        JSON.stringify({
          Presente: antes.Presente,
          Justificada: antes.Justificada,
          TituloComentario: antes.TituloComentario,
          Comentario: antes.Comentario
        }),
        JSON.stringify(despues)
      ]
    );

    await connection.commit();

    return res.json({
      ok: true,
      message: "Asistencia actualizada correctamente.",
      data: {
        IdDetalle: idDetalle,
        ...despues
      }
    });
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

    console.error("[CRUD DETALLE ASISTENCIAS] Error actualizando", {
      id_detalle: idDetalle,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_ACTUALIZANDO_ASISTENCIA",
      message: "No pudimos guardar el cambio de asistencia."
    });
  } finally {
    connection.release();
  }
});

module.exports = router;
