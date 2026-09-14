const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

const STATUS_CONTACTO_INSCRITO = "2 Inscrito";
const STATUS_CONTACTO_REABIERTO = "0 Por contactar";
const STATUS_ALUMNO_PERMITIDOS = new Set(["Activo", "En formación"]);
const STATUS_ALUMNO_INACTIVO = "Inactivo";

function tiene(obj, campo) {
  return Object.prototype.hasOwnProperty.call(obj || {}, campo);
}

function normalizarTexto(valor) {
  if (valor === null || valor === undefined) return null;
  const texto = String(valor).trim();
  return texto || null;
}

function packedUuid() {
  return crypto.randomUUID().replace(/-/g, "");
}

function normalizarBooleano(valor) {
  if ([true, 1, "1", "true"].includes(valor)) return true;
  if ([false, 0, "0", "false"].includes(valor)) return false;
  return null;
}

function normalizarFecha(valor) {
  const raw = String(valor ?? "").trim();
  const match = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;

  const [, year, month, day] = match;
  const fecha = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)));

  if (
    fecha.getUTCFullYear() !== Number(year) ||
    fecha.getUTCMonth() !== Number(month) - 1 ||
    fecha.getUTCDate() !== Number(day)
  ) {
    return null;
  }

  return raw;
}

function permitir(req, res) {
  if (!req.auth.modulos.includes("prospectos")) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de prospectos."
    });
    return false;
  }
  return true;
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

async function validarUsuarioInscripcion(idUsuario, connection = pool) {
  if (!idUsuario) return false;

  const [rows] = await connection.query(
    `
    SELECT \`ID Usuario\`
    FROM USUARIOS
    WHERE \`ID Usuario\` = ?
      AND Status = 'Activo'
      AND LOWER(Rol) IN ('admin', 'administrador', 'directivo')
    LIMIT 1
    `,
    [idUsuario]
  );

  return rows.length > 0;
}

async function buscarAlumnoRelacionado(idEvaluacion, connection = pool, forUpdate = false) {
  let sql = `
    SELECT
      IdAlumno,
      Nombre,
      Apellidos,
      Status,
      IdGrupo,
      CuotaMensual,
      FechaRegistro
    FROM ALUMNOS
    WHERE IdEvaluacionOrigen = ?
    LIMIT 1
  `;

  if (forUpdate) sql += " FOR UPDATE";

  const [rows] = await connection.query(sql, [idEvaluacion]);
  return rows[0] || null;
}

async function validarGrupo(idGrupo, idPlantel, connection = pool) {
  if (!idGrupo) return true;

  const [rows] = await connection.query(
    `
    SELECT IdGrupo
    FROM GRUPOS
    WHERE IdGrupo = ?
      AND IdPlantel = ?
      AND Status = 'Activo'
    LIMIT 1
    `,
    [idGrupo, idPlantel]
  );

  return rows.length > 0;
}

async function responderVista(idAppsheet, res, statusCode = 200, extra = {}) {
  const [rows] = await pool.query(
    "SELECT * FROM vw_company_viewer_prospectos WHERE id_appsheet = ? LIMIT 1",
    [idAppsheet]
  );

  return res.status(statusCode).json({
    ok: true,
    ...extra,
    data: rows[0] || null
  });
}

// ======================================================
// PATCH /crud/prospectos/:id_appsheet
// Edita exclusivamente metadatos de inscripción.
// ======================================================
router.patch("/:id_appsheet", async (req, res, next) => {
  const body = req.body || {};
  const editaFecha = tiene(body, "fecha_inscripcion");
  const editaUsuario = tiene(body, "id_usuario_inscribe");

  if (!editaFecha && !editaUsuario) return next();
  if (!permitir(req, res)) return;

  const otrosCampos = Object.keys(body).filter(
    (campo) => !["fecha_inscripcion", "id_usuario_inscribe"].includes(campo)
  );

  if (otrosCampos.length) {
    return res.status(400).json({
      ok: false,
      code: "EDICION_INSCRIPCION_SEPARADA",
      message: "Fecha y usuario de inscripción deben editarse en una solicitud separada de otros cambios del prospecto."
    });
  }

  try {
    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const prospecto = await buscarProspecto(idAppsheet, req);

    if (!prospecto) {
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto indicado."
      });
    }

    if (String(prospecto.status_contacto || "").trim() !== STATUS_CONTACTO_INSCRITO) {
      return res.status(409).json({
        ok: false,
        code: "PROSPECTO_NO_INSCRITO",
        message: "Solo puede editarse la inscripción de un prospecto que ya está inscrito."
      });
    }

    const updates = [];
    const params = [];

    if (editaFecha) {
      const fechaInscripcion = normalizarFecha(body.fecha_inscripcion);
      if (!fechaInscripcion) {
        return res.status(400).json({
          ok: false,
          code: "FECHA_INSCRIPCION_INVALIDA",
          message: "La fecha de inscripción debe tener formato YYYY-MM-DD y ser una fecha válida."
        });
      }
      updates.push("fecha_inscripcion = ?");
      params.push(fechaInscripcion);
    }

    if (editaUsuario) {
      const idUsuario = normalizarTexto(body.id_usuario_inscribe);
      if (!(await validarUsuarioInscripcion(idUsuario))) {
        return res.status(400).json({
          ok: false,
          code: "USUARIO_INSCRIPCION_INVALIDO",
          message: "El usuario que inscribe debe ser un Admin o Directivo activo."
        });
      }
      updates.push("id_usuario_inscribe = ?");
      params.push(idUsuario);
    }

    params.push(idAppsheet);
    await pool.query(
      `UPDATE Examenes_Evaluacion SET ${updates.join(", ")} WHERE id_appsheet = ?`,
      params
    );

    return responderVista(idAppsheet, res, 200, {
      message: "Inscripción actualizada correctamente."
    });
  } catch (error) {
    console.error("[CRUD PROSPECTOS] Error editando inscripción", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_EDITANDO_INSCRIPCION",
      message: "No pudimos actualizar los datos de inscripción."
    });
  }
});

// ======================================================
// POST /crud/prospectos/:id_appsheet/inscribir
// Registra inscripción y opcionalmente crea/reactiva ALUMNOS.
// ======================================================
router.post("/:id_appsheet/inscribir", async (req, res) => {
  if (!permitir(req, res)) return;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const prospecto = await buscarProspecto(idAppsheet, req, connection, true);

    if (!prospecto) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto indicado."
      });
    }

    const fechaInscripcion = normalizarFecha(req.body?.fecha_inscripcion);
    if (!fechaInscripcion) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "FECHA_INSCRIPCION_INVALIDA",
        message: "Selecciona una fecha de inscripción válida."
      });
    }

    const idUsuarioInscribe = normalizarTexto(req.body?.id_usuario_inscribe);
    if (!(await validarUsuarioInscripcion(idUsuarioInscribe, connection))) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "USUARIO_INSCRIPCION_INVALIDO",
        message: "El usuario que inscribe debe ser un Admin o Directivo activo."
      });
    }

    const crearAlumno = normalizarBooleano(req.body?.crear_alumno);
    if (crearAlumno === null) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "CREAR_ALUMNO_INVALIDO",
        message: "Indica si debe crearse o reactivarse el perfil del alumno."
      });
    }

    let alumno = await buscarAlumnoRelacionado(prospecto.id_evaluacion, connection, true);
    let accionAlumno = "sin_cambios";

    if (crearAlumno) {
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
      const cuotaRaw = req.body?.cuota_mensual;
      const cuotaMensual = cuotaRaw === null || cuotaRaw === undefined || cuotaRaw === ""
        ? null
        : Number(cuotaRaw);

      if (cuotaMensual !== null && (!Number.isFinite(cuotaMensual) || cuotaMensual < 0)) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          code: "CUOTA_INVALIDA",
          message: "La cuota mensual no es válida."
        });
      }

      if (!(await validarGrupo(idGrupo, prospecto.id_plantel, connection))) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          code: "GRUPO_INVALIDO",
          message: "El grupo indicado no pertenece al plantel o no está activo."
        });
      }

      if (!alumno) {
        const idAlumno = packedUuid();

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
            fechaInscripcion,
            cuotaMensual,
            statusAlumno,
            prospecto.id_evaluacion,
            prospecto.audio_url
          ]
        );

        alumno = {
          IdAlumno: idAlumno,
          Nombre: prospecto.nombre,
          Apellidos: prospecto.apellido,
          Status: statusAlumno,
          IdGrupo: idGrupo,
          CuotaMensual: cuotaMensual,
          FechaRegistro: fechaInscripcion
        };
        accionAlumno = "creado";
      } else if (String(alumno.Status || "").trim() === STATUS_ALUMNO_INACTIVO) {
        await connection.query(
          `
          UPDATE ALUMNOS
          SET Status = ?,
              IdGrupo = ?,
              CuotaMensual = ?,
              FechaRegistro = ?
          WHERE IdAlumno = ?
          `,
          [statusAlumno, idGrupo, cuotaMensual, fechaInscripcion, alumno.IdAlumno]
        );

        alumno.Status = statusAlumno;
        alumno.IdGrupo = idGrupo;
        alumno.CuotaMensual = cuotaMensual;
        alumno.FechaRegistro = fechaInscripcion;
        accionAlumno = "reactivado";
      } else if (STATUS_ALUMNO_PERMITIDOS.has(String(alumno.Status || "").trim())) {
        await connection.rollback();
        return res.status(409).json({
          ok: false,
          code: "ALUMNO_YA_ACTIVO",
          message: "Este prospecto ya tiene un alumno activo o en formación.",
          data: {
            IdAlumno: alumno.IdAlumno,
            NombreAlumno: [alumno.Nombre, alumno.Apellidos].filter(Boolean).join(" "),
            StatusAlumno: alumno.Status
          }
        });
      } else {
        await connection.rollback();
        return res.status(409).json({
          ok: false,
          code: "STATUS_ALUMNO_NO_REACTIVABLE",
          message: "El alumno relacionado existe, pero su status actual no permite reactivarlo automáticamente.",
          data: {
            IdAlumno: alumno.IdAlumno,
            NombreAlumno: [alumno.Nombre, alumno.Apellidos].filter(Boolean).join(" "),
            StatusAlumno: alumno.Status
          }
        });
      }
    }

    await connection.query(
      `
      UPDATE Examenes_Evaluacion
      SET status_contacto = ?,
          fecha_inscripcion = ?,
          id_usuario_inscribe = ?
      WHERE id_evaluacion = ?
      `,
      [STATUS_CONTACTO_INSCRITO, fechaInscripcion, idUsuarioInscribe, prospecto.id_evaluacion]
    );

    await connection.commit();

    return responderVista(idAppsheet, res, 201, {
      message: "Prospecto inscrito correctamente.",
      accion_alumno: crearAlumno ? accionAlumno : "no_solicitado",
      IdAlumno: alumno?.IdAlumno || null
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD PROSPECTOS] Error inscribiendo prospecto", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_INSCRIBIENDO_PROSPECTO",
      message: "No pudimos completar la inscripción."
    });
  } finally {
    connection.release();
  }
});

// ======================================================
// POST /crud/prospectos/:id_appsheet/deshacer-inscripcion
// Revierte inscripción e inactiva el alumno relacionado.
// ======================================================
router.post("/:id_appsheet/deshacer-inscripcion", async (req, res) => {
  if (!permitir(req, res)) return;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const prospecto = await buscarProspecto(idAppsheet, req, connection, true);

    if (!prospecto) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto indicado."
      });
    }

    if (String(prospecto.status_contacto || "").trim() !== STATUS_CONTACTO_INSCRITO) {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "PROSPECTO_NO_INSCRITO",
        message: "Este prospecto no está marcado como inscrito."
      });
    }

    const alumno = await buscarAlumnoRelacionado(prospecto.id_evaluacion, connection, true);

    if (alumno) {
      await connection.query(
        "UPDATE ALUMNOS SET Status = ? WHERE IdAlumno = ?",
        [STATUS_ALUMNO_INACTIVO, alumno.IdAlumno]
      );
    }

    await connection.query(
      `
      UPDATE Examenes_Evaluacion
      SET status_contacto = ?,
          fecha_inscripcion = NULL,
          id_usuario_inscribe = NULL
      WHERE id_evaluacion = ?
      `,
      [STATUS_CONTACTO_REABIERTO, prospecto.id_evaluacion]
    );

    await connection.commit();

    return responderVista(idAppsheet, res, 200, {
      message: alumno
        ? "Inscripción deshecha. El alumno relacionado quedó inactivo."
        : "Inscripción deshecha correctamente.",
      IdAlumno: alumno?.IdAlumno || null
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD PROSPECTOS] Error deshaciendo inscripción", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_DESHACIENDO_INSCRIPCION",
      message: "No pudimos deshacer la inscripción."
    });
  } finally {
    connection.release();
  }
});

// ======================================================
// DELETE /crud/prospectos/:id_appsheet
// Borra prospecto solo si nunca generó un alumno.
// ======================================================
router.delete("/:id_appsheet", async (req, res) => {
  if (!permitir(req, res)) return;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const idAppsheet = String(req.params.id_appsheet || "").trim();
    const prospecto = await buscarProspecto(idAppsheet, req, connection, true);

    if (!prospecto) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "PROSPECTO_NO_ENCONTRADO",
        message: "No encontramos el prospecto indicado."
      });
    }

    const alumno = await buscarAlumnoRelacionado(prospecto.id_evaluacion, connection, true);

    if (alumno) {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "PROSPECTO_CON_ALUMNO_RELACIONADO",
        message: "No se puede eliminar este prospecto porque ya tiene un alumno relacionado.",
        data: {
          IdAlumno: alumno.IdAlumno,
          NombreAlumno: [alumno.Nombre, alumno.Apellidos].filter(Boolean).join(" "),
          StatusAlumno: alumno.Status
        }
      });
    }

    await connection.query(
      "DELETE FROM Examenes_Evaluacion WHERE id_evaluacion = ?",
      [prospecto.id_evaluacion]
    );

    await connection.commit();

    return res.json({
      ok: true,
      message: "Prospecto eliminado correctamente.",
      data: {
        id_appsheet: idAppsheet,
        id_evaluacion: prospecto.id_evaluacion
      }
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD PROSPECTOS] Error eliminando prospecto", error);
    return res.status(500).json({
      ok: false,
      code: "ERROR_ELIMINANDO_PROSPECTO",
      message: "No pudimos eliminar el prospecto."
    });
  } finally {
    connection.release();
  }
});

module.exports = router;
