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

function booleano(value) {
  if (value === true || value === 1 || value === "1") return 1;
  if (value === false || value === 0 || value === "0") return 0;
  return null;
}

router.patch("/:id_seguimiento/visibilidad", async (req, res) => {
  if (!permitir(req, res)) return;

  const idSeguimiento = String(req.params.id_seguimiento || "").trim();
  const visible = booleano(req.body?.visible_plantel);

  if (!idSeguimiento) {
    return res.status(400).json({ ok: false, code: "SEGUIMIENTO_REQUERIDO", message: "El seguimiento indicado no es válido." });
  }
  if (visible === null) {
    return res.status(400).json({ ok: false, code: "VISIBILIDAD_INVALIDA", message: "Indica si el seguimiento será visible al plantel." });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id_seguimiento FROM alumnos_seguimientos WHERE id_seguimiento = ? LIMIT 1",
      [idSeguimiento]
    );
    if (!rows.length) {
      return res.status(404).json({ ok: false, code: "SEGUIMIENTO_NO_ENCONTRADO", message: "No encontramos ese seguimiento." });
    }

    await pool.query(
      `UPDATE alumnos_seguimientos
       SET VisiblePlantel = ?
       WHERE id_seguimiento = ?`,
      [visible, idSeguimiento]
    );

    return res.json({
      ok: true,
      message: visible ? "Seguimiento visible al plantel." : "Seguimiento interno.",
      data: { id_seguimiento: idSeguimiento, VisiblePlantel: visible }
    });
  } catch (error) {
    console.error("[CRUD SEGUIMIENTOS] Error actualizando visibilidad", error);
    return res.status(500).json({ ok: false, code: "ERROR_VISIBILIDAD_SEGUIMIENTO", message: "No pudimos actualizar la visibilidad del seguimiento." });
  }
});

module.exports = router;
