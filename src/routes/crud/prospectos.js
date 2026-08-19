const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);


// ======================================================
// Helpers
// ======================================================

function permitir(req, res, modulo) {
  if (!req.auth.modulos.includes(modulo)) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso a este módulo."
    });

    return false;
  }

  return true;
}

function normalizarTexto(valor) {
  const texto = String(valor || "").trim();
  return texto || null;
}

function normalizarCorreo(correo) {
  return String(correo || "").trim().toLowerCase();
}

function correoValido(correo) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo);
}


// ======================================================
// POST /crud/prospectos
// ======================================================

router.post("/", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const nombre = String(req.body?.nombre || "").trim();
    const apellido = normalizarTexto(req.body?.apellido);
    const telefono = String(req.body?.telefono || "").trim();
    const correo = normalizarCorreo(req.body?.correo);

    const origenLead = normalizarTexto(req.body?.origen_lead);
    const horarioPreferido = normalizarTexto(
      req.body?.horario_preferido
    );

    const etiquetaProspecto = normalizarTexto(
      req.body?.etiqueta_prospecto
    );


    // ==================================================
    // Validaciones básicas
    // ==================================================

    if (!nombre) {
      return res.status(400).json({
        ok: false,
        code: "NOMBRE_REQUERIDO",
        message: "Ingresa el nombre del prospecto."
      });
    }

    if (!telefono) {
      return res.status(400).json({
        ok: false,
        code: "TELEFONO_REQUERIDO",
        message: "Ingresa el teléfono del prospecto."
      });
    }

    if (!correo) {
      return res.status(400).json({
        ok: false,
        code: "CORREO_REQUERIDO",
        message: "Ingresa el correo electrónico del prospecto."
      });
    }

    if (!correoValido(correo)) {
      return res.status(400).json({
        ok: false,
        code: "CORREO_INVALIDO",
        message: "Ingresa un correo electrónico válido."
      });
    }


    // ==================================================
    // Resolver plantel
    // ==================================================

    let idPlantel;

    if (req.auth.acceso_global) {

      // Usuario interno:
      // puede seleccionar el plantel desde el frontend.
      idPlantel = String(req.body?.id_plantel || "").trim();

      if (!idPlantel) {
        return res.status(400).json({
          ok: false,
          code: "PLANTEL_REQUERIDO",
          message: "Selecciona el plantel del prospecto."
        });
      }

    } else {

      // Cliente / plantel:
      // nunca confiamos en el id_plantel enviado por frontend.
      idPlantel = req.auth.id_plantel;
    }


    // ==================================================
    // Validar que el plantel exista y esté activo
    // ==================================================

    const [planteles] = await pool.query(
      `
      SELECT IdPlantel
      FROM PLANTELES
      WHERE IdPlantel = ?
        AND Status = 'Activo'
      LIMIT 1
      `,
      [idPlantel]
    );

    if (!planteles.length) {
      return res.status(400).json({
        ok: false,
        code: "PLANTEL_INVALIDO",
        message: "El plantel indicado no está disponible."
      });
    }


    // ==================================================
    // Crear prospecto
    // ==================================================

    const [result] = await pool.query(
      `
      INSERT INTO Examenes_Evaluacion (
        nombre,
        apellido,
        correo,
        telefono,
        id_plantel,
        origen_lead,
        horario_preferido,
        etiqueta_prospecto
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        nombre,
        apellido,
        correo,
        telefono,
        idPlantel,
        origenLead,
        horarioPreferido,
        etiquetaProspecto
      ]
    );


    // ==================================================
    // Consultar registro creado desde la VIEW
    // ==================================================

    const [rows] = await pool.query(
      `
      SELECT *
      FROM vw_company_viewer_prospectos
      WHERE id_evaluacion = ?
      LIMIT 1
      `,
      [result.insertId]
    );


    console.log("[CRUD PROSPECTOS] Prospecto creado", {
      id_evaluacion: result.insertId,
      id_plantel: idPlantel,
      tipo_usuario: req.auth.tipo_usuario
    });


    return res.status(201).json({
      ok: true,
      message: "Prospecto registrado correctamente.",
      data: rows[0] || {
        id_evaluacion: result.insertId
      }
    });

  } catch (error) {

    console.error("[CRUD PROSPECTOS] Error creando prospecto", {
      message: error?.message,
      code: error?.code
    });


    // El DDL actual tiene correo único.
    if (error?.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        ok: false,
        code: "CORREO_YA_REGISTRADO",
        message:
          "Ya existe un prospecto registrado con este correo electrónico."
      });
    }


    return res.status(500).json({
      ok: false,
      code: "ERROR_CREANDO_PROSPECTO",
      message: "No pudimos registrar el prospecto."
    });
  }
});


module.exports = router;