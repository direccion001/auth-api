const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();

router.use(requireAuth);

const STATUS_NO_APLICA = "0 No aplica";
const STATUS_LISTO_EVALUAR = "3 Listo para evaluar";
const STATUS_NIVEL_ASIGNADO = "4 Nivel Asignado";
const STATUS_CONTACTO_INSCRITO = "2 Inscrito";
const STATUS_ALUMNO_PERMITIDOS = new Set(["Activo", "En formación"]);
const STATUS_PERMITEN_NIVEL = new Set([
  STATUS_NO_APLICA,
  STATUS_LISTO_EVALUAR,
  STATUS_NIVEL_ASIGNADO
]);

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
  if (valor === null || valor === undefined) return null;
  const texto = String(valor).trim();
  return texto || null;
}

function normalizarCorreo(correo) {
  return String(correo || "").trim().toLowerCase();
}

function correoValido(correo) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo);
}

function tiene(obj, campo) {
  return Object.prototype.hasOwnProperty.call(obj || {}, campo);
}

function packedUuid() {
  return crypto.randomUUID().replace(/-/g, "");
}

function fechaMexico() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Mexico_City",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date());
}

async function buscarProspecto(idAppsheet, req, connection = pool, forUpdate = false) {
  const params = [idAppsheet];
  let sql = `
    SELECT *
    FROM Examenes_Evaluacion
    WHERE id_appsheet = ?
  `;

  if (!req.auth.acceso_global) {
    sql += " AND id_plantel = ?";
    params.push(req.auth.id_plantel);
  }

  sql += " LIMIT 1";
  if (forUpdate) sql += " FOR UPDATE";

  const [rows] = await connection.query(sql, params);
  return rows[0] || null;
}

async function validarUsuarioResponsable(idUsuario, connection = pool) {
  if (!idUsuario) return true;

  const [rows] = await connection.query(
    `
    SELECT \`ID Usuario\`
    FROM USUARIOS
    WHERE \`ID Usuario\` = ?
      AND Status = 'Activo'
      AND Rol IN ('Administrador', 'Directivo')
    LIMIT 1
    `,
    [idUsuario]
  );

  return rows.length > 0;
}

async function obtenerContacto(idContacto, idAppsheet, req, connection = pool) {
  const params = [idContacto, idAppsheet];
  let sql = `
    SELECT
      c.*,
      e.id_plantel
    FROM contactos_examenes_evaluacion c
    INNER JOIN Examenes_Evaluacion e
      ON e.id_appsheet = c.id_appsheet
    WHERE c.id_contacto = ?
      AND c.id_appsheet = ?
  `;

  if (!req.auth.acceso_global) {
    sql += " AND e.id_plantel = ?";
    params.push(req.auth.id_plantel);
  }

  sql += " LIMIT 1";

  const [rows] = await connection.query(sql, params);
  return rows[0] || null;
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
    const horarioPreferido = normalizarTexto(req.body?.horario_preferido);
    const etiquetaProspecto = normalizarTexto(req.body?.etiqueta_prospecto);

    if (!nombre) {
      return res.status(400).json({ ok: false, code: "NOMBRE_REQUERIDO", message: "Ingresa el nombre del prospecto." });
    }
    if (!telefono) {
      return res.status(400).json({ ok: false, code: "TELEFONO_REQUERIDO", message: "Ingresa el teléfono del prospecto." });
    }
    if (!correo) {
      return res.status(400).json({ ok: false, code: "CORREO_REQUERIDO", message: "Ingresa el correo electrónico del prospecto." });
    }
    if (!correoValido(correo)) {
      return res.status(400).json({ ok: false, code: "CORREO_INVALIDO", message: "Ingresa un correo electrónico válido." });
    }

    let idPlantel;
    if (req.auth.acceso_global) {
      idPlantel = String(req.body?.id_plantel || "").trim();
      if (!idPlantel) {
        return res.status(400).json({ ok: false, code: "PLANTEL_REQUERIDO", message: "Selecciona el plantel del prospecto." });
      }
    } else {
      idPlantel = req.auth.id_plantel;
    }

    const [planteles] = await pool.query(
      `SELECT IdPlantel FROM PLANTELES WHERE IdPlantel = ? AND Status = 'Activo' LIMIT 1`,
      [idPlantel]
    );

    if (!planteles.length) {
      return res.status(400).json({ ok: false, code: "PLANTEL_INVALIDO", message: "El plantel indicado no está disponible." });
    }

    const [result] = await pool.query(
      `
      INSERT INTO Examenes_Evaluacion (
        nombre, apellido, correo, telefono, id_plantel,
        origen_lead, horario_preferido, etiqueta_prospecto
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [nombre, apellido, correo, telefono, idPlantel, origenLead, horarioPreferido, etiquetaProspecto]
    );

    const [rows] = await pool.query(
      `SELECT * FROM vw_company_viewer_prospectos WHERE id_evaluacion = ? LIMIT 1`,
      [result.insertId]
    );

    return res.status(201).json({
      ok: true,
      message: "Prospecto registrado correctamente.",
      data: rows[0] || { id_evaluacion: result.insertId }
    });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error creando prospecto", error);
    if (responderDuplicado(error, res)) return;
    return res.status(500).json({ ok: false, code: "ERROR_CREANDO_PROSPECTO", message: "No pudimos registrar el prospecto." });
  }
});

// ======================================================
// PATCH /crud/prospectos/:id_appsheet
// ======================================================

router.patch("/:id_appsheet", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const actual = await buscarProspecto(idAppsheet, req);

    if (!actual) {
      return res.status(404).json({ ok: false, code: "PROSPECTO_NO_ENCONTRADO", message: "No encontramos el prospecto indicado." });
    }

    const updates = [];
    const params = [];
    const body = req.body || {};

    const camposGenerales = [
      ["nombre", "nombre"],
      ["apellido", "apellido"],
      ["telefono", "telefono"],
      ["status_contacto", "status_contacto"],
      ["etiqueta_prospecto", "etiqueta_prospecto"],
      ["origen_lead", "origen_lead"],
      ["horario_preferido", "horario_preferido"]
    ];

    for (const [entrada, columna] of camposGenerales) {
      if (!tiene(body, entrada)) continue;
      const valor = normalizarTexto(body[entrada]);

      if (["nombre", "telefono"].includes(entrada) && !valor) {
        return res.status(400).json({ ok: false, code: "CAMPO_REQUERIDO", message: `${entrada} no puede quedar vacío.` });
      }

      if (entrada === "status_contacto" && valor === STATUS_CONTACTO_INSCRITO) {
        return res.status(400).json({
          ok: false,
          code: "INSCRIPCION_REQUIERE_ACCION",
          message: "Para marcar un prospecto como inscrito utiliza la acción de inscripción."
        });
      }

      updates.push(`${columna} = ?`);
      params.push(valor);
    }

    if (tiene(body, "correo")) {
      const correo = normalizarCorreo(body.correo);
      if (!correo || !correoValido(correo)) {
        return res.status(400).json({ ok: false, code: "CORREO_INVALIDO", message: "Ingresa un correo electrónico válido." });
      }
      updates.push("correo = ?");
      params.push(correo);
    }

    if (req.auth.acceso_global) {
      if (tiene(body, "id_usuario_responsable")) {
        const responsable = normalizarTexto(body.id_usuario_responsable);
        if (!(await validarUsuarioResponsable(responsable))) {
          return res.status(400).json({ ok: false, code: "RESPONSABLE_INVALIDO", message: "El responsable debe ser un Administrador o Directivo activo." });
        }
        updates.push("id_usuario_responsable = ?");
        params.push(responsable);
      }

      if (tiene(body, "id_grupo_propuesto")) {
        updates.push("id_grupo_propuesto = ?");
        params.push(normalizarTexto(body.id_grupo_propuesto));
      }

      if (tiene(body, "id_otras_opciones_grupo")) {
        updates.push("id_otras_opciones_grupo = ?");
        params.push(normalizarTexto(body.id_otras_opciones_grupo));
      }

      const solicitaStatusAcademico = tiene(body, "status");
      const solicitaNivel = tiene(body, "nivel_sugerido");

      if (solicitaStatusAcademico) {
        const statusSolicitado = normalizarTexto(body.status);
        if (statusSolicitado !== STATUS_NO_APLICA) {
          return res.status(400).json({
            ok: false,
            code: "STATUS_ACADEMICO_NO_PERMITIDO",
            message: `Desde Company Viewer solo puede establecerse manualmente ${STATUS_NO_APLICA}.`
          });
        }
        updates.push("status = ?");
        params.push(STATUS_NO_APLICA);
      }

      if (solicitaNivel) {
        const statusBase = solicitaStatusAcademico ? STATUS_NO_APLICA : actual.status;
        if (!STATUS_PERMITEN_NIVEL.has(statusBase)) {
          return res.status(409).json({
            ok: false,
            code: "NIVEL_NO_EDITABLE",
            message: "El nivel solo puede modificarse cuando el prospecto está listo para evaluar, no aplica o ya tiene nivel asignado."
          });
        }

        const nivel = normalizarTexto(body.nivel_sugerido);
        updates.push("nivel_sugerido = ?");
        params.push(nivel);
        updates.push("status = ?");
        params.push(nivel ? STATUS_NIVEL_ASIGNADO : STATUS_LISTO_EVALUAR);
      }
    } else {
      const camposRestringidos = [
        "id_usuario_responsable",
        "id_grupo_propuesto",
        "id_otras_opciones_grupo",
        "status",
        "nivel_sugerido"
      ];

      if (camposRestringidos.some((campo) => tiene(body, campo))) {
        return res.status(403).json({
          ok: false,
          code: "CAMPO_NO_AUTORIZADO",
          message: "El plantel no puede modificar información académica, responsable o grupos propuestos."
        });
      }
    }

    if (!updates.length) {
      return res.status(400).json({ ok: false, code: "SIN_CAMBIOS", message: "No se enviaron campos editables." });
    }

    params.push(idAppsheet);
    await pool.query(
      `UPDATE Examenes_Evaluacion SET ${updates.join(", ")} WHERE id_appsheet = ?`,
      params
    );

    const [rows] = await pool.query(
      `SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1`,
      [idAppsheet]
    );

    return res.json({ ok: true, message: "Prospecto actualizado correctamente.", data: rows[0] || null });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error actualizando prospecto", error);
    if (responderDuplicado(error, res)) return;
    return res.status(500).json({ ok: false, code: "ERROR_ACTUALIZANDO_PROSPECTO", message: "No pudimos actualizar el prospecto." });
  }
});

// ======================================================
// POST /crud/prospectos/:id_appsheet/contactos
// ======================================================

router.post("/:id_appsheet/contactos", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const prospecto = await buscarProspecto(idAppsheet, req);

    if (!prospecto) {
      return res.status(404).json({ ok: false, code: "PROSPECTO_NO_ENCONTRADO", message: "No encontramos el prospecto indicado." });
    }

    const formaContacto = normalizarTexto(req.body?.forma_contacto);
    const resultadoContacto = normalizarTexto(req.body?.resultado_contacto);
    const descripcion = normalizarTexto(req.body?.descripcion);
    const fechaProximo = normalizarTexto(req.body?.fecha_proximo_seguimiento);

    if (!formaContacto || !resultadoContacto || !descripcion) {
      return res.status(400).json({
        ok: false,
        code: "CONTACTO_INCOMPLETO",
        message: "Forma de contacto, resultado y descripción son obligatorios."
      });
    }

    let idUsuario = null;
    let esPlantel = 1;

    if (req.auth.acceso_global) {
      idUsuario = normalizarTexto(req.body?.id_usuario) || req.auth.id_usuario;
      esPlantel = 0;

      if (!(await validarUsuarioResponsable(idUsuario))) {
        return res.status(400).json({ ok: false, code: "USUARIO_CONTACTO_INVALIDO", message: "El usuario del contacto debe ser un Administrador o Directivo activo." });
      }
    }

    const idContacto = packedUuid();

    await pool.query(
      `
      INSERT INTO contactos_examenes_evaluacion (
        id_contacto, id_appsheet, id_evaluacion, id_usuario, es_plantel,
        forma_contacto, resultado_contacto, descripcion, fecha_proximo_seguimiento
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [idContacto, idAppsheet, prospecto.id_evaluacion, idUsuario, esPlantel, formaContacto, resultadoContacto, descripcion, fechaProximo]
    );

    const [rows] = await pool.query(
      `
      SELECT c.*, CONCAT_WS(' ', u.Nombre, u.Apellidos) AS usuario_nombre
      FROM contactos_examenes_evaluacion c
      LEFT JOIN USUARIOS u ON u.\`ID Usuario\` = c.id_usuario
      WHERE c.id_contacto = ?
      LIMIT 1
      `,
      [idContacto]
    );

    return res.status(201).json({ ok: true, message: "Contacto registrado correctamente.", data: rows[0] || null });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error creando contacto", error);
    return res.status(500).json({ ok: false, code: "ERROR_CREANDO_CONTACTO", message: "No pudimos registrar el contacto." });
  }
});

// ======================================================
// PATCH /crud/prospectos/:id_appsheet/contactos/:id_contacto
// ======================================================

router.patch("/:id_appsheet/contactos/:id_contacto", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const idContacto = String(req.params.id_contacto || "").trim();
    const actual = await obtenerContacto(idContacto, idAppsheet, req);

    if (!actual) {
      return res.status(404).json({ ok: false, code: "CONTACTO_NO_ENCONTRADO", message: "No encontramos el contacto indicado." });
    }

    if (!req.auth.acceso_global && Number(actual.es_plantel) !== 1) {
      return res.status(403).json({
        ok: false,
        code: "CONTACTO_SOLO_LECTURA",
        message: "El plantel solo puede editar contactos registrados por el propio plantel."
      });
    }

    const body = req.body || {};
    const siguiente = {
      forma_contacto: tiene(body, "forma_contacto") ? normalizarTexto(body.forma_contacto) : actual.forma_contacto,
      resultado_contacto: tiene(body, "resultado_contacto") ? normalizarTexto(body.resultado_contacto) : actual.resultado_contacto,
      descripcion: tiene(body, "descripcion") ? normalizarTexto(body.descripcion) : actual.descripcion,
      fecha_proximo_seguimiento: tiene(body, "fecha_proximo_seguimiento") ? normalizarTexto(body.fecha_proximo_seguimiento) : actual.fecha_proximo_seguimiento,
      id_usuario: actual.id_usuario
    };

    if (!siguiente.forma_contacto || !siguiente.resultado_contacto || !siguiente.descripcion) {
      return res.status(400).json({
        ok: false,
        code: "CONTACTO_INCOMPLETO",
        message: "Forma de contacto, resultado y descripción son obligatorios."
      });
    }

    if (req.auth.acceso_global && tiene(body, "id_usuario")) {
      siguiente.id_usuario = normalizarTexto(body.id_usuario) || req.auth.id_usuario;
      if (!(await validarUsuarioResponsable(siguiente.id_usuario))) {
        return res.status(400).json({ ok: false, code: "USUARIO_CONTACTO_INVALIDO", message: "El usuario del contacto debe ser un Administrador o Directivo activo." });
      }
    }

    await pool.query(
      `
      UPDATE contactos_examenes_evaluacion
      SET forma_contacto = ?,
          resultado_contacto = ?,
          descripcion = ?,
          fecha_proximo_seguimiento = ?,
          id_usuario = ?
      WHERE id_contacto = ?
        AND id_appsheet = ?
      `,
      [
        siguiente.forma_contacto,
        siguiente.resultado_contacto,
        siguiente.descripcion,
        siguiente.fecha_proximo_seguimiento,
        siguiente.id_usuario,
        idContacto,
        idAppsheet
      ]
    );

    const [rows] = await pool.query(
      `
      SELECT c.*, CONCAT_WS(' ', u.Nombre, u.Apellidos) AS usuario_nombre
      FROM contactos_examenes_evaluacion c
      LEFT JOIN USUARIOS u ON u.\`ID Usuario\` = c.id_usuario
      WHERE c.id_contacto = ?
      LIMIT 1
      `,
      [idContacto]
    );

    return res.json({ ok: true, message: "Contacto actualizado correctamente.", data: rows[0] || null });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error actualizando contacto", error);
    return res.status(500).json({ ok: false, code: "ERROR_ACTUALIZANDO_CONTACTO", message: "No pudimos actualizar el contacto." });
  }
});

// ======================================================
// DELETE /crud/prospectos/:id_appsheet/contactos/:id_contacto
// Solo usuarios internos.
// ======================================================

router.delete("/:id_appsheet/contactos/:id_contacto", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  if (!req.auth.acceso_global) {
    return res.status(403).json({ ok: false, code: "SOLO_INTERNO", message: "Solo un usuario interno puede eliminar contactos." });
  }

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const idContacto = String(req.params.id_contacto || "").trim();
    const contacto = await obtenerContacto(idContacto, idAppsheet, req);

    if (!contacto) {
      return res.status(404).json({ ok: false, code: "CONTACTO_NO_ENCONTRADO", message: "No encontramos el contacto indicado." });
    }

    await pool.query(
      `DELETE FROM contactos_examenes_evaluacion WHERE id_contacto = ? AND id_appsheet = ?`,
      [idContacto, idAppsheet]
    );

    return res.json({ ok: true, message: "Contacto eliminado correctamente." });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error eliminando contacto", error);
    return res.status(500).json({ ok: false, code: "ERROR_ELIMINANDO_CONTACTO", message: "No pudimos eliminar el contacto." });
  }
});

// ======================================================
// POST /crud/prospectos/:id_appsheet/inscribir
// Crea ALUMNOS + cambia status_contacto en una transacción.
// ======================================================

router.post("/:id_appsheet/inscribir", async (req, res) => {
  if (!permitir(req, res, "prospectos")) return;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const prospecto = await buscarProspecto(idAppsheet, req, connection, true);

    if (!prospecto) {
      await connection.rollback();
      return res.status(404).json({ ok: false, code: "PROSPECTO_NO_ENCONTRADO", message: "No encontramos el prospecto indicado." });
    }

    const [existentes] = await connection.query(
      `SELECT IdAlumno FROM ALUMNOS WHERE IdEvaluacionOrigen = ? LIMIT 1`,
      [prospecto.id_evaluacion]
    );

    if (existentes.length) {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "PROSPECTO_YA_INSCRITO",
        message: "Este prospecto ya está ligado a un alumno.",
        data: { IdAlumno: existentes[0].IdAlumno }
      });
    }

    const statusAlumno = String(req.body?.status || "").trim();
    if (!STATUS_ALUMNO_PERMITIDOS.has(statusAlumno)) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "STATUS_ALUMNO_INVALIDO",
        message: "El status del alumno debe ser Activo o En formación."
      });
    }

    const idGrupo = normalizarTexto(req.body?.id_grupo);
    const cuotaMensualRaw = req.body?.cuota_mensual;
    const cuotaMensual = cuotaMensualRaw === null || cuotaMensualRaw === undefined || cuotaMensualRaw === ""
      ? null
      : Number(cuotaMensualRaw);

    if (cuotaMensual !== null && (!Number.isFinite(cuotaMensual) || cuotaMensual < 0)) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "CUOTA_INVALIDA", message: "La cuota mensual no es válida." });
    }

    if (idGrupo) {
      const [grupos] = await connection.query(
        `SELECT IdGrupo FROM GRUPOS WHERE IdGrupo = ? AND IdPlantel = ? AND Status = 'Activo' LIMIT 1`,
        [idGrupo, prospecto.id_plantel]
      );

      if (!grupos.length) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "GRUPO_INVALIDO", message: "El grupo indicado no pertenece al plantel o no está activo." });
      }
    }

    const idAlumno = packedUuid();
    const fechaRegistro = fechaMexico();

    await connection.query(
      `
      INSERT INTO ALUMNOS (
        IdAlumno,
        IdPlantel,
        IdGrupo,
        Nombre,
        Apellidos,
        Telefono,
        Correo,
        FechaNacimiento,
        FechaRegistro,
        CuotaMensual,
        Status,
        IdEvaluacionOrigen,
        AudioUrlEvaluacion
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        idAlumno,
        prospecto.id_plantel,
        idGrupo,
        prospecto.nombre,
        prospecto.apellido,
        prospecto.telefono,
        prospecto.correo,
        prospecto.fecha_nacimiento,
        fechaRegistro,
        cuotaMensual,
        statusAlumno,
        prospecto.id_evaluacion,
        prospecto.audio_url
      ]
    );

    await connection.query(
      `UPDATE Examenes_Evaluacion SET status_contacto = ? WHERE id_evaluacion = ?`,
      [STATUS_CONTACTO_INSCRITO, prospecto.id_evaluacion]
    );

    await connection.commit();

    return res.status(201).json({
      ok: true,
      message: "Prospecto inscrito correctamente.",
      data: {
        IdAlumno: idAlumno,
        IdEvaluacionOrigen: prospecto.id_evaluacion,
        IdPlantel: prospecto.id_plantel,
        IdGrupo: idGrupo,
        Status: statusAlumno,
        FechaRegistro: fechaRegistro,
        CuotaMensual: cuotaMensual
      }
    });
  } catch (error) {
    await connection.rollback();
    console.error("[CRUD PROSPECTOS] Error inscribiendo prospecto", error);
    return res.status(500).json({ ok: false, code: "ERROR_INSCRIBIENDO_PROSPECTO", message: "No pudimos completar la inscripción." });
  } finally {
    connection.release();
  }
});

module.exports = router;
