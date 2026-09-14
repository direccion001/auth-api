const express = require("express");
const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

function permitir(req, res) {
  if (!req.auth.modulos.includes("prospectos")) {
    res.status(403).json({ ok: false, code: "MODULO_NO_AUTORIZADO", message: "No tienes acceso a este módulo." });
    return false;
  }
  return true;
}

function tiene(objeto, campo) {
  return Object.prototype.hasOwnProperty.call(objeto || {}, campo);
}

function texto(value) {
  const normalized = String(value ?? "").trim();
  return normalized || null;
}

function correoNormalizado(value) {
  return String(value ?? "").trim().toLowerCase();
}

function correoValido(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

async function plantelActivo(idPlantel) {
  const [rows] = await pool.query(
    "SELECT IdPlantel FROM PLANTELES WHERE IdPlantel = ? AND Status = 'Activo' LIMIT 1",
    [idPlantel]
  );
  return rows.length > 0;
}

async function usuarioResponsableValido(idUsuario) {
  if (!idUsuario) return true;
  const [rows] = await pool.query(
    `SELECT \`ID Usuario\` FROM USUARIOS
     WHERE \`ID Usuario\` = ?
       AND Status = 'Activo'
       AND LOWER(TRIM(Rol)) IN ('admin','administrador','directivo')
     LIMIT 1`,
    [idUsuario]
  );
  return rows.length > 0;
}

async function prospectoVisible(idAppsheet, req) {
  const params = [idAppsheet];
  let sql = "SELECT * FROM Examenes_Evaluacion WHERE id_appsheet = ?";
  if (!req.auth.acceso_global) {
    sql += " AND id_plantel = ?";
    params.push(req.auth.id_plantel);
  }
  sql += " LIMIT 1";
  const [rows] = await pool.query(sql, params);
  return rows[0] || null;
}

async function responderProspecto(idAppsheet, res, message) {
  const [rows] = await pool.query(
    "SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1",
    [idAppsheet]
  );
  return res.json({ ok: true, message, data: rows[0] || null });
}

function responderDuplicado(error, res) {
  if (error?.code !== "ER_DUP_ENTRY") return false;
  res.status(409).json({
    ok: false,
    code: "CORREO_YA_REGISTRADO",
    message: "Ya existe un prospecto registrado con este correo electrónico."
  });
  return true;
}

router.post("/", async (req, res, next) => {
  if (!permitir(req, res)) return;

  try {
    const nombre = String(req.body?.nombre || "").trim();
    const apellido = texto(req.body?.apellido);
    const telefono = texto(req.body?.telefono);
    const correoRaw = correoNormalizado(req.body?.correo);
    const correo = correoRaw || null;
    const origenLead = texto(req.body?.origen_lead);
    const horarioPreferido = texto(req.body?.horario_preferido);
    const etiquetaProspecto = texto(req.body?.etiqueta_prospecto);
    const comentarios = texto(req.body?.comentarios);

    if (!nombre) {
      return res.status(400).json({ ok: false, code: "NOMBRE_REQUERIDO", message: "Ingresa el nombre del prospecto." });
    }
    if (!telefono && !correo) {
      return res.status(400).json({ ok: false, code: "CONTACTO_REQUERIDO", message: "Ingresa al menos un teléfono o correo electrónico." });
    }
    if (correo && !correoValido(correo)) {
      return res.status(400).json({ ok: false, code: "CORREO_INVALIDO", message: "Ingresa un correo electrónico válido." });
    }

    const idPlantel = req.auth.acceso_global
      ? String(req.body?.id_plantel || "").trim()
      : String(req.auth.id_plantel || "").trim();

    if (!idPlantel) {
      return res.status(400).json({ ok: false, code: "PLANTEL_REQUERIDO", message: "Selecciona el plantel del prospecto." });
    }
    if (!(await plantelActivo(idPlantel))) {
      return res.status(400).json({ ok: false, code: "PLANTEL_INVALIDO", message: "El plantel indicado no está disponible." });
    }

    let idUsuarioResponsable = null;
    if (req.auth.acceso_global) {
      idUsuarioResponsable = texto(req.body?.id_usuario_responsable) || texto(req.auth.id_usuario);
      if (!(await usuarioResponsableValido(idUsuarioResponsable))) {
        return res.status(400).json({ ok: false, code: "RESPONSABLE_INVALIDO", message: "El responsable debe ser un Admin o Directivo activo." });
      }
    }

    const [result] = await pool.query(
      `INSERT INTO Examenes_Evaluacion (
        nombre, apellido, correo, telefono, id_plantel,
        origen_lead, horario_preferido, etiqueta_prospecto,
        comentarios, id_usuario_responsable
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        nombre,
        apellido,
        correo,
        telefono,
        idPlantel,
        origenLead,
        horarioPreferido,
        etiquetaProspecto,
        req.auth.acceso_global ? comentarios : null,
        req.auth.acceso_global ? idUsuarioResponsable : null
      ]
    );

    const [rows] = await pool.query(
      "SELECT * FROM vw_company_viewer_prospectos WHERE id_evaluacion = ? LIMIT 1",
      [result.insertId]
    );

    return res.status(201).json({
      ok: true,
      message: "Prospecto registrado correctamente.",
      data: rows[0] || { id_evaluacion: result.insertId }
    });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error creando prospecto flexible", error);
    if (responderDuplicado(error, res)) return;
    return res.status(500).json({ ok: false, code: "ERROR_CREANDO_PROSPECTO", message: "No pudimos registrar el prospecto." });
  }
});

// Compatibilidad para edición: teléfono y correo son alternativos, no obligatorios ambos.
// Se actualizan aquí y se retiran del body antes de delegar el resto al CRUD existente.
router.patch("/:id_appsheet", async (req, res, next) => {
  const body = req.body || {};
  const tocaTelefono = tiene(body, "telefono");
  const tocaCorreo = tiene(body, "correo");
  if (!tocaTelefono && !tocaCorreo) return next();
  if (!permitir(req, res)) return;

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const actual = await prospectoVisible(idAppsheet, req);
    if (!actual) {
      return res.status(404).json({ ok: false, code: "PROSPECTO_NO_ENCONTRADO", message: "No encontramos el prospecto indicado." });
    }

    const telefono = tocaTelefono ? texto(body.telefono) : texto(actual.telefono);
    const correoRaw = tocaCorreo ? correoNormalizado(body.correo) : correoNormalizado(actual.correo);
    const correo = correoRaw || null;

    if (!telefono && !correo) {
      return res.status(400).json({ ok: false, code: "CONTACTO_REQUERIDO", message: "El prospecto debe conservar al menos un teléfono o correo electrónico." });
    }
    if (correo && !correoValido(correo)) {
      return res.status(400).json({ ok: false, code: "CORREO_INVALIDO", message: "Ingresa un correo electrónico válido." });
    }

    const updates = [];
    const params = [];
    if (tocaTelefono) {
      updates.push("telefono = ?");
      params.push(telefono);
      delete body.telefono;
    }
    if (tocaCorreo) {
      updates.push("correo = ?");
      params.push(correo);
      delete body.correo;
    }

    if (updates.length) {
      params.push(idAppsheet);
      await pool.query(`UPDATE Examenes_Evaluacion SET ${updates.join(", ")} WHERE id_appsheet = ?`, params);
    }

    if (Object.keys(body).length === 0) {
      return responderProspecto(idAppsheet, res, "Datos de contacto actualizados correctamente.");
    }

    return next();
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error actualizando medios de contacto", error);
    if (responderDuplicado(error, res)) return;
    return res.status(500).json({ ok: false, code: "ERROR_ACTUALIZANDO_CONTACTO_PROSPECTO", message: "No pudimos actualizar los medios de contacto del prospecto." });
  }
});

router.patch("/:id_appsheet/plantel", async (req, res) => {
  if (!permitir(req, res)) return;
  if (!req.auth.acceso_global) {
    return res.status(403).json({ ok: false, code: "SOLO_INTERNO", message: "Solo un usuario interno puede cambiar el plantel del prospecto." });
  }

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const idPlantel = String(req.body?.id_plantel || "").trim();
    if (!idPlantel) {
      return res.status(400).json({ ok: false, code: "PLANTEL_REQUERIDO", message: "Selecciona el plantel del prospecto." });
    }
    if (!(await plantelActivo(idPlantel))) {
      return res.status(400).json({ ok: false, code: "PLANTEL_INVALIDO", message: "El plantel indicado no está disponible." });
    }

    const [existentes] = await pool.query(
      "SELECT id_evaluacion FROM Examenes_Evaluacion WHERE id_appsheet = ? LIMIT 1",
      [idAppsheet]
    );
    if (!existentes.length) {
      return res.status(404).json({ ok: false, code: "PROSPECTO_NO_ENCONTRADO", message: "No encontramos el prospecto indicado." });
    }

    await pool.query(
      "UPDATE Examenes_Evaluacion SET id_plantel = ? WHERE id_appsheet = ?",
      [idPlantel, idAppsheet]
    );

    return responderProspecto(idAppsheet, res, "Plantel actualizado correctamente.");
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error cambiando plantel", error);
    return res.status(500).json({ ok: false, code: "ERROR_CAMBIANDO_PLANTEL", message: "No pudimos cambiar el plantel del prospecto." });
  }
});

module.exports = router;
