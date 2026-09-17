const express = require("express");

const pool = require("../db/pool");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

function permitir(req, res) {
  if (!req.auth.modulos.includes("prospectos")) {
    res.status(403).json({ ok: false, code: "MODULO_NO_AUTORIZADO", message: "No tienes acceso a este módulo." });
    return false;
  }
  return true;
}

router.get("/:id_appsheet/contactos", async (req, res) => {
  if (!permitir(req, res)) return;

  const idAppsheet = String(req.params.id_appsheet || "").trim();
  if (!idAppsheet || idAppsheet.length > 40) {
    return res.status(400).json({ ok: false, code: "PROSPECTO_INVALIDO", message: "El prospecto indicado no es válido." });
  }

  try {
    const params = [idAppsheet];
    let sql = `
      SELECT
        c.id_contacto,
        c.id_appsheet,
        c.id_evaluacion,
        c.id_usuario,
        c.es_plantel,
        c.VisiblePlantel,
        c.fecha_hora_contacto,
        c.forma_contacto,
        c.resultado_contacto,
        c.descripcion,
        c.fecha_proximo_seguimiento,
        c.proxima_accion,
        CONCAT_WS(' ', u.Nombre, u.Apellidos) AS usuario_nombre
      FROM contactos_examenes_evaluacion c
      INNER JOIN Examenes_Evaluacion e
        ON e.id_appsheet = c.id_appsheet
      LEFT JOIN USUARIOS u
        ON u.\`ID Usuario\` = c.id_usuario
      WHERE c.id_appsheet = ?
    `;

    if (!req.auth.acceso_global) {
      sql += " AND e.id_plantel = ?";
      params.push(req.auth.id_plantel);
    }

    if (req.auth.tipo_usuario === "PLANTEL") {
      sql += " AND COALESCE(c.VisiblePlantel, 1) = 1";
    }

    sql += " ORDER BY c.fecha_hora_contacto DESC, c.id_contacto DESC";

    const [rows] = await pool.query(sql, params);
    return res.json({ ok: true, data: rows });
  } catch (error) {
    console.error("[VIEWER] contactos prospecto", error);
    return res.status(500).json({ ok: false, code: "ERROR_CONTACTOS", message: "No pudimos consultar los contactos del prospecto." });
  }
});

module.exports = router;
