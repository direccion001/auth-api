const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);


// ======================================================
// Helpers
// ======================================================

function permitirGraduaciones(req, res) {
  if (!req.auth.modulos.includes("graduaciones")) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de graduaciones."
    });
    return false;
  }

  return true;
}

function normalizarTexto(valor) {
  const texto = String(valor ?? "").trim();
  return texto || null;
}

function tieneCampo(objeto, campo) {
  return Object.prototype.hasOwnProperty.call(objeto || {}, campo);
}

function fechaValida(fecha) {
  if (typeof fecha !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
    return false;
  }

  const [year, month, day] = fecha.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));

  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function normalizarBooleano(valor) {
  if (valor === true || valor === 1 || valor === "1" || valor === "true") {
    return true;
  }

  if (valor === false || valor === 0 || valor === "0" || valor === "false") {
    return false;
  }

  return null;
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
    parts.filter((part) => part.type !== "literal").map((part) => [part.type, part.value])
  );

  return `${valores.year}-${valores.month}-${valores.day} ${valores.hour}:${valores.minute}:${valores.second}`;
}

async function validarGrupo(connection, idGrupo) {
  const [rows] = await connection.query(
    `
    SELECT IdGrupo
    FROM GRUPOS
    WHERE IdGrupo = ?
    LIMIT 1
    `,
    [idGrupo]
  );

  return rows.length > 0;
}

async function validarCurso(connection, idCurso) {
  const [rows] = await connection.query(
    `
    SELECT \`ID CURSO\` AS IdCurso
    FROM CURSOS
    WHERE \`ID CURSO\` = ?
      AND Status = 'Activo'
    LIMIT 1
    `,
    [idCurso]
  );

  return rows.length > 0;
}

async function validarUsuarioRol(connection, idUsuario, roles) {
  if (!idUsuario) return false;

  const placeholders = roles.map(() => "?").join(", ");
  const [rows] = await connection.query(
    `
    SELECT \`ID Usuario\` AS IdUsuario
    FROM USUARIOS
    WHERE \`ID Usuario\` = ?
      AND Status = 'Activo'
      AND Rol IN (${placeholders})
    LIMIT 1
    `,
    [idUsuario, ...roles]
  );

  return rows.length > 0;
}

async function obtenerGraduacionBloqueada(connection, idGraduacion) {
  const [rows] = await connection.query(
    `
    SELECT
      id_graduacion,
      id_grupo,
      id_curso,
      id_maestro_inicio,
      id_maestro_fin,
      fecha_curso_inicio,
      fecha_curso_fin_programada,
      fecha_curso_fin,
      fecha_graduacion_programada,
      fecha_graduacion,
      foto_graduacion,
      asiste_administracion,
      id_administrativo,
      status_graduacion,
      calidad,
      observaciones,
      fecha_registro,
      registrado_por
    FROM graduaciones
    WHERE id_graduacion = ?
    LIMIT 1
    FOR UPDATE
    `,
    [idGraduacion]
  );

  return rows[0] || null;
}

async function consultarGraduacion(connection, idGraduacion) {
  const [rows] = await connection.query(
    `
    SELECT *
    FROM vw_company_viewer_graduaciones
    WHERE IdGraduacion = ?
    LIMIT 1
    `,
    [idGraduacion]
  );

  return rows[0] || null;
}

async function registrarAuditoria(
  connection,
  req,
  evento,
  idGraduacion,
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
      "graduaciones",
      idGraduacion,
      antes == null ? null : JSON.stringify(antes),
      despues == null ? null : JSON.stringify(despues)
    ]
  );
}


// ======================================================
// POST /crud/graduaciones
// Programa el ciclo del curso y su graduación.
// ======================================================

router.post("/", async (req, res) => {
  if (!permitirGraduaciones(req, res)) return;

  const idGrupo = normalizarTexto(req.body?.id_grupo);
  const idCurso = normalizarTexto(req.body?.id_curso);
  const idMaestroInicio = normalizarTexto(req.body?.id_maestro_inicio);
  const fechaCursoInicio = normalizarTexto(req.body?.fecha_curso_inicio);
  const fechaCursoFinProgramada = normalizarTexto(
    req.body?.fecha_curso_fin_programada
  );
  const fechaGraduacionProgramada = normalizarTexto(
    req.body?.fecha_graduacion_programada
  );
  const observaciones = normalizarTexto(req.body?.observaciones);

  if (!idGrupo) {
    return res.status(400).json({
      ok: false,
      code: "GRUPO_REQUERIDO",
      message: "Selecciona el grupo."
    });
  }

  if (!idCurso) {
    return res.status(400).json({
      ok: false,
      code: "CURSO_REQUERIDO",
      message: "Selecciona el curso."
    });
  }

  if (!fechaValida(fechaCursoInicio)) {
    return res.status(400).json({
      ok: false,
      code: "FECHA_CURSO_INICIO_INVALIDA",
      message: "Selecciona una fecha de inicio de curso válida."
    });
  }

  if (!fechaValida(fechaCursoFinProgramada)) {
    return res.status(400).json({
      ok: false,
      code: "FECHA_CURSO_FIN_PROGRAMADA_INVALIDA",
      message: "Selecciona una fecha programada de fin de curso válida."
    });
  }

  if (!fechaValida(fechaGraduacionProgramada)) {
    return res.status(400).json({
      ok: false,
      code: "FECHA_GRADUACION_PROGRAMADA_INVALIDA",
      message: "Selecciona una fecha programada de graduación válida."
    });
  }

  if (fechaCursoFinProgramada < fechaCursoInicio) {
    return res.status(400).json({
      ok: false,
      code: "ORDEN_FECHAS_CURSO_INVALIDO",
      message: "La fecha programada de fin de curso no puede ser anterior al inicio."
    });
  }

  if (fechaGraduacionProgramada < fechaCursoFinProgramada) {
    return res.status(400).json({
      ok: false,
      code: "ORDEN_FECHA_GRADUACION_INVALIDO",
      message: "La graduación programada no puede ser anterior al fin programado del curso."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    if (!(await validarGrupo(connection, idGrupo))) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "GRUPO_INVALIDO",
        message: "El grupo indicado no existe."
      });
    }

    if (!(await validarCurso(connection, idCurso))) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "CURSO_INVALIDO",
        message: "El curso indicado no está disponible."
      });
    }

    if (
      idMaestroInicio &&
      !(await validarUsuarioRol(connection, idMaestroInicio, ["Maestro"]))
    ) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "MAESTRO_INICIO_INVALIDO",
        message: "El maestro de inicio indicado no está disponible."
      });
    }

    const idGraduacion = crypto.randomUUID();
    const fechaRegistro = fechaMexicoAhora();

    const nuevo = {
      id_graduacion: idGraduacion,
      id_grupo: idGrupo,
      id_curso: idCurso,
      id_maestro_inicio: idMaestroInicio,
      id_maestro_fin: null,
      fecha_curso_inicio: fechaCursoInicio,
      fecha_curso_fin_programada: fechaCursoFinProgramada,
      fecha_curso_fin: null,
      fecha_graduacion_programada: fechaGraduacionProgramada,
      fecha_graduacion: null,
      foto_graduacion: null,
      asiste_administracion: 0,
      id_administrativo: null,
      status_graduacion: "PENDIENTE",
      calidad: null,
      observaciones,
      fecha_registro: fechaRegistro,
      registrado_por: String(req.auth.id_usuario)
    };

    await connection.query(
      `
      INSERT INTO graduaciones (
        id_graduacion,
        id_grupo,
        id_curso,
        id_maestro_inicio,
        fecha_curso_inicio,
        fecha_curso_fin_programada,
        fecha_graduacion_programada,
        status_graduacion,
        observaciones,
        fecha_registro,
        registrado_por
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDIENTE', ?, ?, ?)
      `,
      [
        idGraduacion,
        idGrupo,
        idCurso,
        idMaestroInicio,
        fechaCursoInicio,
        fechaCursoFinProgramada,
        fechaGraduacionProgramada,
        observaciones,
        fechaRegistro,
        String(req.auth.id_usuario)
      ]
    );

    await registrarAuditoria(
      connection,
      req,
      "GRADUACION_CREADA",
      idGraduacion,
      null,
      nuevo
    );

    const creado = await consultarGraduacion(connection, idGraduacion);

    await connection.commit();

    return res.status(201).json({
      ok: true,
      message: "Graduación programada correctamente.",
      data: creado ?? nuevo
    });
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

    console.error("[CRUD GRADUACIONES] Error creando", {
      id_grupo: idGrupo,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CREANDO_GRADUACION",
      message: "No pudimos programar la graduación."
    });
  } finally {
    connection.release();
  }
});


// ======================================================
// PATCH /crud/graduaciones/:id_graduacion/cerrar-curso
// Registra el fin real del libro/curso. No completa graduación.
// ======================================================

router.patch("/:id_graduacion/cerrar-curso", async (req, res) => {
  if (!permitirGraduaciones(req, res)) return;

  const idGraduacion = normalizarTexto(req.params.id_graduacion);
  const fechaCursoFin = normalizarTexto(req.body?.fecha_curso_fin);
  const idMaestroFin = normalizarTexto(req.body?.id_maestro_fin);
  const observacionesSolicitadas = tieneCampo(req.body, "observaciones")
    ? normalizarTexto(req.body?.observaciones)
    : undefined;

  if (!idGraduacion) {
    return res.status(400).json({
      ok: false,
      code: "GRADUACION_REQUERIDA",
      message: "La graduación indicada no es válida."
    });
  }

  if (!fechaValida(fechaCursoFin)) {
    return res.status(400).json({
      ok: false,
      code: "FECHA_CURSO_FIN_INVALIDA",
      message: "Selecciona una fecha real de fin de curso válida."
    });
  }

  if (!idMaestroFin) {
    return res.status(400).json({
      ok: false,
      code: "MAESTRO_FIN_REQUERIDO",
      message: "Selecciona el maestro con el que terminó el curso."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const antes = await obtenerGraduacionBloqueada(connection, idGraduacion);

    if (!antes) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "GRADUACION_NO_ENCONTRADA",
        message: "No encontramos esa graduación."
      });
    }

    if (antes.status_graduacion === "COMPLETADA") {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "GRADUACION_YA_COMPLETADA",
        message: "No se puede cerrar el curso después de completar la graduación."
      });
    }

    if (antes.fecha_curso_fin) {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "CURSO_YA_CERRADO",
        message: "Este curso ya tiene registrada una fecha de fin."
      });
    }

    if (fechaCursoFin < antes.fecha_curso_inicio) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "ORDEN_FECHA_CURSO_FIN_INVALIDO",
        message: "La fecha de fin no puede ser anterior al inicio del curso."
      });
    }

    if (!(await validarUsuarioRol(connection, idMaestroFin, ["Maestro"]))) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "MAESTRO_FIN_INVALIDO",
        message: "El maestro final indicado no está disponible."
      });
    }

    const observaciones =
      observacionesSolicitadas === undefined
        ? antes.observaciones
        : observacionesSolicitadas;

    await connection.query(
      `
      UPDATE graduaciones
      SET
        fecha_curso_fin = ?,
        id_maestro_fin = ?,
        observaciones = ?
      WHERE id_graduacion = ?
      `,
      [fechaCursoFin, idMaestroFin, observaciones, idGraduacion]
    );

    const despues = {
      ...antes,
      fecha_curso_fin: fechaCursoFin,
      id_maestro_fin: idMaestroFin,
      observaciones
    };

    await registrarAuditoria(
      connection,
      req,
      "CURSO_CERRADO",
      idGraduacion,
      antes,
      despues
    );

    const actualizado = await consultarGraduacion(connection, idGraduacion);

    await connection.commit();

    return res.json({
      ok: true,
      message: "Curso cerrado correctamente.",
      data: actualizado ?? despues
    });
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

    console.error("[CRUD GRADUACIONES] Error cerrando curso", {
      id_graduacion: idGraduacion,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CERRANDO_CURSO",
      message: "No pudimos registrar el fin del curso."
    });
  } finally {
    connection.release();
  }
});


// ======================================================
// PATCH /crud/graduaciones/:id_graduacion/completar
// Registra la graduación real y cambia el status a COMPLETADA.
// ======================================================

router.patch("/:id_graduacion/completar", async (req, res) => {
  if (!permitirGraduaciones(req, res)) return;

  const idGraduacion = normalizarTexto(req.params.id_graduacion);
  const fechaGraduacion = normalizarTexto(req.body?.fecha_graduacion);
  const asisteAdministracion = normalizarBooleano(
    req.body?.asiste_administracion ?? false
  );
  const idAdministrativo = normalizarTexto(req.body?.id_administrativo);
  const fotoGraduacion = normalizarTexto(req.body?.foto_graduacion);
  const calidad = normalizarTexto(req.body?.calidad);
  const observacionesSolicitadas = tieneCampo(req.body, "observaciones")
    ? normalizarTexto(req.body?.observaciones)
    : undefined;

  if (!idGraduacion) {
    return res.status(400).json({
      ok: false,
      code: "GRADUACION_REQUERIDA",
      message: "La graduación indicada no es válida."
    });
  }

  if (!fechaValida(fechaGraduacion)) {
    return res.status(400).json({
      ok: false,
      code: "FECHA_GRADUACION_INVALIDA",
      message: "Selecciona una fecha real de graduación válida."
    });
  }

  if (asisteAdministracion === null) {
    return res.status(400).json({
      ok: false,
      code: "ASISTENCIA_ADMINISTRACION_INVALIDA",
      message: "Indica si asistió administración."
    });
  }

  if (asisteAdministracion && !idAdministrativo) {
    return res.status(400).json({
      ok: false,
      code: "ADMINISTRATIVO_REQUERIDO",
      message: "Selecciona el administrativo que asistió."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const antes = await obtenerGraduacionBloqueada(connection, idGraduacion);

    if (!antes) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "GRADUACION_NO_ENCONTRADA",
        message: "No encontramos esa graduación."
      });
    }

    if (antes.status_graduacion !== "PENDIENTE") {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "GRADUACION_NO_PENDIENTE",
        message: "Solo una graduación pendiente puede completarse."
      });
    }

    if (!antes.fecha_curso_fin) {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "CURSO_NO_CERRADO",
        message: "Primero registra el fin del curso antes de completar la graduación."
      });
    }

    if (fechaGraduacion < antes.fecha_curso_fin) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "ORDEN_FECHA_GRADUACION_INVALIDO",
        message: "La fecha de graduación no puede ser anterior al fin real del curso."
      });
    }

    if (
      asisteAdministracion &&
      !(await validarUsuarioRol(connection, idAdministrativo, ["Admin", "Directivo"]))
    ) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        code: "ADMINISTRATIVO_INVALIDO",
        message: "El administrativo indicado no está disponible."
      });
    }

    const observaciones =
      observacionesSolicitadas === undefined
        ? antes.observaciones
        : observacionesSolicitadas;

    const idAdministrativoFinal = asisteAdministracion
      ? idAdministrativo
      : null;

    await connection.query(
      `
      UPDATE graduaciones
      SET
        fecha_graduacion = ?,
        asiste_administracion = ?,
        id_administrativo = ?,
        foto_graduacion = ?,
        calidad = ?,
        observaciones = ?,
        status_graduacion = 'COMPLETADA'
      WHERE id_graduacion = ?
      `,
      [
        fechaGraduacion,
        asisteAdministracion ? 1 : 0,
        idAdministrativoFinal,
        fotoGraduacion,
        calidad,
        observaciones,
        idGraduacion
      ]
    );

    const despues = {
      ...antes,
      fecha_graduacion: fechaGraduacion,
      asiste_administracion: asisteAdministracion ? 1 : 0,
      id_administrativo: idAdministrativoFinal,
      foto_graduacion: fotoGraduacion,
      calidad,
      observaciones,
      status_graduacion: "COMPLETADA"
    };

    await registrarAuditoria(
      connection,
      req,
      "GRADUACION_COMPLETADA",
      idGraduacion,
      antes,
      despues
    );

    const actualizado = await consultarGraduacion(connection, idGraduacion);

    await connection.commit();

    return res.json({
      ok: true,
      message: "Graduación completada correctamente.",
      data: actualizado ?? despues
    });
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

    console.error("[CRUD GRADUACIONES] Error completando", {
      id_graduacion: idGraduacion,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_COMPLETANDO_GRADUACION",
      message: "No pudimos completar la graduación."
    });
  } finally {
    connection.release();
  }
});


// ======================================================
// PATCH /crud/graduaciones/:id_graduacion/cancelar
// Cancela únicamente la graduación; el curso conserva su historia.
// ======================================================

router.patch("/:id_graduacion/cancelar", async (req, res) => {
  if (!permitirGraduaciones(req, res)) return;

  const idGraduacion = normalizarTexto(req.params.id_graduacion);
  const observaciones = normalizarTexto(req.body?.observaciones);

  if (!idGraduacion) {
    return res.status(400).json({
      ok: false,
      code: "GRADUACION_REQUERIDA",
      message: "La graduación indicada no es válida."
    });
  }

  if (!observaciones) {
    return res.status(400).json({
      ok: false,
      code: "OBSERVACIONES_REQUERIDAS",
      message: "Escribe el motivo de cancelación."
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const antes = await obtenerGraduacionBloqueada(connection, idGraduacion);

    if (!antes) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "GRADUACION_NO_ENCONTRADA",
        message: "No encontramos esa graduación."
      });
    }

    if (antes.status_graduacion !== "PENDIENTE") {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "GRADUACION_NO_PENDIENTE",
        message: "Solo una graduación pendiente puede cancelarse."
      });
    }

    await connection.query(
      `
      UPDATE graduaciones
      SET
        status_graduacion = 'CANCELADA',
        observaciones = ?
      WHERE id_graduacion = ?
      `,
      [observaciones, idGraduacion]
    );

    const despues = {
      ...antes,
      status_graduacion: "CANCELADA",
      observaciones
    };

    await registrarAuditoria(
      connection,
      req,
      "GRADUACION_CANCELADA",
      idGraduacion,
      antes,
      despues
    );

    const actualizado = await consultarGraduacion(connection, idGraduacion);

    await connection.commit();

    return res.json({
      ok: true,
      message: "Graduación cancelada correctamente.",
      data: actualizado ?? despues
    });
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
      // Conserva el error original.
    }

    console.error("[CRUD GRADUACIONES] Error cancelando", {
      id_graduacion: idGraduacion,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_CANCELANDO_GRADUACION",
      message: "No pudimos cancelar la graduación."
    });
  } finally {
    connection.release();
  }
});


module.exports = router;
