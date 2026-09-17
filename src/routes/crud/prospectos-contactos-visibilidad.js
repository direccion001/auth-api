const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();
router.use(requireAuth, requireInterno);

function permitir(req, res) {
  if (!req.auth.modulos.includes("prospectos")) {
    res.status(403).json({ ok: false, code: "MODULO_NO_AUTORIZADO", message: "No tienes acceso al módulo de prospectos." });
    return false;
  }
  return true;
}

function booleano(value) {
  if (value === true || value === 1 || value === "1") return 1;
  if (value === false || value === 0 || value === "0") return 0;
  return null;
}

router.patch("/:id_appsheet/contactos/:id_contacto/visibilidad", async (req, res) => {
  if (!permitir(req, res)) return;

  const idAppsheet = String(req.params.id_appsheet || "").trim();
  const idContacto = String(req.params.id_contacto || "").trim();
  const visible = booleano(req.body?.visible_plantel);

  if (!idAppsheet || !idContacto) {
    return res.status(400).json({ ok: false, code: "CONTACTO_INVALIDO", message: "El contacto indicado no es válido." });
  }
  if (visible === null) {
    return res.status(400).json({ ok: false, code: "VISIBILIDAD_INVALIDA", message: "Indica si el contacto será visible al plantel." });
  }

  try {
    const [result] = await pool.query(
      `UPDATE contactos_examenes_evaluacion
       SET VisiblePlantel = ?
       WHERE id_contacto = ? AND id_appsheet = ?`,
      [visible, idContacto, idAppsheet]
    );

    if (!result.affectedRows) {
      return res.status(404).json({ ok: false, code: "CONTACTO_NO_ENCONTRADO", message: "No encontramos ese contacto." });
    }

    return res.json({
      ok: true,
      message: visible ? "Contacto visible al plantel." : "Contacto interno.",
      data: { id_contacto: idContacto, VisiblePlantel: visible }
    });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error actualizando visibilidad de contacto", error);
    return res.status(500).json({ ok: false, code: "ERROR_VISIBILIDAD_CONTACTO", message: "No pudimos actualizar la visibilidad del contacto." });
  }
});

module.exports = router;
