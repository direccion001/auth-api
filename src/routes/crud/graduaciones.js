const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

const CALIDADES = new Set(["Baja", "Buena", "Muy buena"]);
const STATUS_GRADUACION = new Set(["PENDIENTE", "COMPLETADA", "CANCELADA"]);

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
  if (fecha === null) return true;
  if (typeof fecha !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return false;
  const [year, month, day] = fecha.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function normalizarBooleano(valor) {
  if (valor === true || valor === 1 || valor === "1" || valor === "true") return true;
  if (valor === false || valor === 0 || valor === "0" || valor === "false") return false;
  return null;
}

function fechaMexico() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Mexico_City",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date());
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
  const valores = Object.fromEntries(parts.filter((p) => p.type !== "literal").map((p) => [p.type, p.value]));
  return `${valores.year}-${valores.month}-${valores.day} ${valores.hour}:${valores.minute}:${valores.second}`;
}

async function obtenerGrupoActivo(connection, idGrupo, bloquear = false) {
  const [rows] = await connection.query(
    `SELECT IdGrupo, IdMaestroTitular FROM GRUPOS WHERE IdGrupo = ? AND Status = 'Activo' LIMIT 1${bloquear ? " FOR UPDATE" : ""}`,
    [idGrupo]
  );
  return rows[0] || null;
}

async function validarCursoActivo(connection, idCurso) {
  const [rows] = await connection.query(
    "SELECT `ID CURSO` AS IdCurso FROM CURSOS WHERE `ID CURSO` = ? AND Status = 'Activo' LIMIT 1",
    [idCurso]
  );
  return rows.length > 0;
}

async function validarUsuarioRol(connection, idUsuario, roles) {
  if (!idUsuario) return false;
  const placeholders = roles.map(() => "?").join(", ");
  const [rows] = await connection.query(
    `SELECT \`ID Usuario\` AS IdUsuario FROM USUARIOS WHERE \`ID Usuario\` = ? AND Status = 'Activo' AND Rol IN (${placeholders}) LIMIT 1`,
    [idUsuario, ...roles]
  );
  return rows.length > 0;
}

async function obtenerGraduacionBloqueada(connection, idGraduacion) {
  const [rows] = await connection.query(
    `SELECT id_graduacion, id_grupo, id_curso, id_maestro_inicio, id_maestro_fin,
            fecha_curso_inicio, fecha_curso_fin_programada, fecha_graduacion_programada,
            fecha_curso_fin, fecha_graduacion, foto_graduacion, asiste_administracion,
            id_administrativo, status_graduacion, calidad, observaciones, fecha_registro, registrado_por
       FROM graduaciones WHERE id_graduacion = ? LIMIT 1 FOR UPDATE`,
    [idGraduacion]
  );
  return rows[0] || null;
}

async function consultarGraduacion(connection, idGraduacion) {
  const [rows] = await connection.query(
    "SELECT * FROM vw_company_viewer_graduaciones WHERE IdGraduacion = ? LIMIT 1",
    [idGraduacion]
  );
  return rows[0] || null;
}

async function revisarDuplicados(connection, idGrupo, idCurso, excluirId = null) {
  const params = [idGrupo, idCurso];
  let sql = `SELECT id_graduacion, fecha_curso_fin, status_graduacion
               FROM graduaciones
              WHERE id_grupo = ? AND id_curso = ?`;
  if (excluirId) {
    sql += " AND id_graduacion <> ?";
    params.push(excluirId);
  }
  sql += " FOR UPDATE";
  const [rows] = await connection.query(sql, params);

  const abierta = rows.find((r) => !r.fecha_curso_fin && r.status_graduacion !== "CANCELADA");
  const cerradas = rows.filter((r) => r.fecha_curso_fin);
  return { abierta: abierta || null, cerradas };
}

function warningHistorico(cerradas) {
  if (!cerradas.length) return [];
  return [{
    code: "CURSO_GRUPO_REPETIDO",
    message: "Este grupo ya cursó anteriormente el mismo curso. Se permite crear un nuevo ciclo porque el anterior ya fue cerrado.",
    total_registros_previos: cerradas.length
  }];
}

function warningCalidad(calidad, observaciones) {
  if (calidad === "Baja" && !observaciones) {
    return [{
      code: "OBSERVACIONES_RECOMENDADAS",
      message: "Se recomienda registrar observaciones cuando la calidad de la graduación es Baja."
    }];
  }
  return [];
}

async function registrarAuditoria(connection, req, evento, idGraduacion, antes, despues) {
  await connection.query(
    `INSERT INTO auditoria_eventos (actor_tipo, actor_id, evento, entidad, id_registro, antes_json, despues_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ["INTERNO", String(req.auth.id_usuario), evento, "graduaciones", idGraduacion,
      antes == null ? null : JSON.stringify(antes), despues == null ? null : JSON.stringify(despues)]
  );
}

function validarFechasFinales(datos) {
  const inicio = datos.fecha_curso_inicio;
  if (!inicio) return null;
  const pares = [
    [datos.fecha_curso_fin_programada, "La fecha programada de fin de curso no puede ser anterior al inicio."],
    [datos.fecha_curso_fin, "La fecha real de fin de curso no puede ser anterior al inicio."],
    [datos.fecha_graduacion_programada, "La fecha programada de graduación no puede ser anterior al inicio."],
    [datos.fecha_graduacion, "La fecha real de graduación no puede ser anterior al inicio."]
  ];
  for (const [fecha, message] of pares) {
    if (fecha && fecha < inicio) return message;
  }
  return null;
}

router.post("/", async (req, res) => {
  if (!permitirGraduaciones(req, res)) return;

  const idGrupo = normalizarTexto(req.body?.id_grupo);
  const idCurso = normalizarTexto(req.body?.id_curso);
  const idMaestroInicioSolicitado = normalizarTexto(req.body?.id_maestro_inicio);
  const fechaCursoInicio = normalizarTexto(req.body?.fecha_curso_inicio);
  const fechaCursoFinProgramada = normalizarTexto(req.body?.fecha_curso_fin_programada);
  const fechaGraduacionProgramada = normalizarTexto(req.body?.fecha_graduacion_programada);
  const observaciones = normalizarTexto(req.body?.observaciones);

  if (!idGrupo) return res.status(400).json({ ok: false, code: "GRUPO_REQUERIDO", message: "Selecciona el grupo." });
  if (!idCurso) return res.status(400).json({ ok: false, code: "CURSO_REQUERIDO", message: "Selecciona el curso." });
  if (!fechaValida(fechaCursoInicio) || !fechaCursoInicio) return res.status(400).json({ ok: false, code: "FECHA_CURSO_INICIO_INVALIDA", message: "Selecciona una fecha de inicio de curso válida." });
  if (!fechaValida(fechaCursoFinProgramada) || !fechaCursoFinProgramada) return res.status(400).json({ ok: false, code: "FECHA_CURSO_FIN_PROGRAMADA_INVALIDA", message: "Selecciona una fecha programada de fin de curso válida." });
  if (!fechaValida(fechaGraduacionProgramada)) return res.status(400).json({ ok: false, code: "FECHA_GRADUACION_PROGRAMADA_INVALIDA", message: "La fecha programada de graduación no es válida." });

  const errorFechas = validarFechasFinales({
    fecha_curso_inicio: fechaCursoInicio,
    fecha_curso_fin_programada: fechaCursoFinProgramada,
    fecha_graduacion_programada: fechaGraduacionProgramada,
    fecha_curso_fin: null,
    fecha_graduacion: null
  });
  if (errorFechas) return res.status(400).json({ ok: false, code: "ORDEN_FECHAS_INVALIDO", message: errorFechas });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const grupo = await obtenerGrupoActivo(connection, idGrupo, true);
    if (!grupo) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "GRUPO_INVALIDO", message: "El grupo indicado no existe o no está activo." });
    }
    if (!(await validarCursoActivo(connection, idCurso))) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "CURSO_INVALIDO", message: "El curso indicado no existe o no está activo." });
    }

    const idMaestroInicio = idMaestroInicioSolicitado || normalizarTexto(grupo.IdMaestroTitular);
    if (idMaestroInicio && !(await validarUsuarioRol(connection, idMaestroInicio, ["Maestro"]))) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "MAESTRO_INICIO_INVALIDO", message: "El maestro de inicio indicado no está disponible." });
    }

    const duplicados = await revisarDuplicados(connection, idGrupo, idCurso);
    if (duplicados.abierta) {
      await connection.rollback();
      return res.status(409).json({
        ok: false,
        code: "CURSO_GRUPO_YA_ABIERTO",
        message: "Ya existe un ciclo abierto para este mismo grupo y curso. Cierra ese curso antes de crear otro.",
        data: { id_graduacion_existente: duplicados.abierta.id_graduacion }
      });
    }

    const idGraduacion = crypto.randomUUID();
    const fechaRegistro = fechaMexicoAhora();
    await connection.query(
      `INSERT INTO graduaciones (
        id_graduacion, id_grupo, id_curso, id_maestro_inicio,
        fecha_curso_inicio, fecha_curso_fin_programada, fecha_graduacion_programada,
        status_graduacion, observaciones, fecha_registro, registrado_por
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDIENTE', ?, ?, ?)`,
      [idGraduacion, idGrupo, idCurso, idMaestroInicio, fechaCursoInicio,
        fechaCursoFinProgramada, fechaGraduacionProgramada, observaciones,
        fechaRegistro, String(req.auth.id_usuario)]
    );

    const nuevo = await obtenerGraduacionBloqueada(connection, idGraduacion);
    await registrarAuditoria(connection, req, "GRADUACION_CREADA", idGraduacion, null, nuevo);
    const creado = await consultarGraduacion(connection, idGraduacion);
    await connection.commit();

    return res.status(201).json({
      ok: true,
      message: "Ciclo de curso y graduación creado correctamente.",
      warnings: warningHistorico(duplicados.cerradas),
      data: creado || nuevo
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD GRADUACIONES] Error creando", error);
    return res.status(500).json({ ok: false, code: "ERROR_CREANDO_GRADUACION", message: "No pudimos crear el ciclo de graduación." });
  } finally {
    connection.release();
  }
});

router.patch("/:id_graduacion", async (req, res, next) => {
  if (["cerrar-curso", "graduar", "completar", "cancelar"].includes(req.params.id_graduacion)) return next();
  if (!permitirGraduaciones(req, res)) return;

  const idGraduacion = normalizarTexto(req.params.id_graduacion);
  if (!idGraduacion) return res.status(400).json({ ok: false, code: "GRADUACION_REQUERIDA", message: "La graduación indicada no es válida." });

  const campos = [
    "id_grupo", "id_curso", "id_maestro_inicio", "id_maestro_fin",
    "fecha_curso_inicio", "fecha_curso_fin_programada", "fecha_graduacion_programada",
    "fecha_curso_fin", "fecha_graduacion", "foto_graduacion",
    "asiste_administracion", "id_administrativo", "status_graduacion", "calidad", "observaciones"
  ];
  if (!campos.some((c) => tieneCampo(req.body, c))) {
    return res.status(400).json({ ok: false, code: "SIN_CAMBIOS", message: "No se recibieron campos editables." });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const antes = await obtenerGraduacionBloqueada(connection, idGraduacion);
    if (!antes) {
      await connection.rollback();
      return res.status(404).json({ ok: false, code: "GRADUACION_NO_ENCONTRADA", message: "No encontramos esa graduación." });
    }

    const final = { ...antes };
    for (const campo of campos) {
      if (!tieneCampo(req.body, campo)) continue;
      if (campo === "asiste_administracion") {
        const booleano = normalizarBooleano(req.body[campo]);
        if (booleano === null) {
          await connection.rollback();
          return res.status(400).json({ ok: false, code: "ASISTENCIA_ADMINISTRACION_INVALIDA", message: "Indica correctamente si asistió administración." });
        }
        final[campo] = booleano ? 1 : 0;
      } else {
        final[campo] = normalizarTexto(req.body[campo]);
      }
    }

    if (!final.id_grupo || !final.id_curso) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "GRUPO_CURSO_REQUERIDOS", message: "Grupo y curso son obligatorios." });
    }

    for (const campo of ["fecha_curso_inicio", "fecha_curso_fin_programada", "fecha_graduacion_programada", "fecha_curso_fin", "fecha_graduacion"]) {
      if (!fechaValida(final[campo])) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "FECHA_INVALIDA", message: `El campo ${campo} no contiene una fecha válida.` });
      }
    }

    const errorFechas = validarFechasFinales(final);
    if (errorFechas) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "ORDEN_FECHAS_INVALIDO", message: errorFechas });
    }

    if (tieneCampo(req.body, "id_grupo")) {
      const grupo = await obtenerGrupoActivo(connection, final.id_grupo, true);
      if (!grupo) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "GRUPO_INVALIDO", message: "El grupo indicado no existe o no está activo." });
      }
    }
    if (tieneCampo(req.body, "id_curso") && !(await validarCursoActivo(connection, final.id_curso))) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "CURSO_INVALIDO", message: "El curso indicado no existe o no está activo." });
    }

    for (const [campo, code] of [["id_maestro_inicio", "MAESTRO_INICIO_INVALIDO"], ["id_maestro_fin", "MAESTRO_FIN_INVALIDO"]]) {
      if (final[campo] && !(await validarUsuarioRol(connection, final[campo], ["Maestro"]))) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code, message: "El maestro indicado no está disponible." });
      }
    }

    if (final.status_graduacion && !STATUS_GRADUACION.has(final.status_graduacion)) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "STATUS_GRADUACION_INVALIDO", message: "El status de graduación no es válido." });
    }
    if (final.calidad && !CALIDADES.has(final.calidad)) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "CALIDAD_INVALIDA", message: "Calidad debe ser Baja, Buena o Muy buena." });
    }

    if (!final.asiste_administracion) final.id_administrativo = null;
    if (final.asiste_administracion) {
      if (!final.id_administrativo) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "ADMINISTRATIVO_REQUERIDO", message: "Selecciona el administrativo que asistió." });
      }
      if (!(await validarUsuarioRol(connection, final.id_administrativo, ["Admin", "Administrador", "Directivo"]))) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "ADMINISTRATIVO_INVALIDO", message: "El administrativo indicado no está disponible." });
      }
    }

    let warnings = [];
    if (final.id_grupo !== antes.id_grupo || final.id_curso !== antes.id_curso) {
      const duplicados = await revisarDuplicados(connection, final.id_grupo, final.id_curso, idGraduacion);
      if (duplicados.abierta) {
        await connection.rollback();
        return res.status(409).json({
          ok: false,
          code: "CURSO_GRUPO_YA_ABIERTO",
          message: "Ya existe otro ciclo abierto para este mismo grupo y curso.",
          data: { id_graduacion_existente: duplicados.abierta.id_graduacion }
        });
      }
      warnings = warningHistorico(duplicados.cerradas);
    }
    warnings.push(...warningCalidad(final.calidad, final.observaciones));

    await connection.query(
      `UPDATE graduaciones SET
        id_grupo = ?, id_curso = ?, id_maestro_inicio = ?, id_maestro_fin = ?,
        fecha_curso_inicio = ?, fecha_curso_fin_programada = ?, fecha_graduacion_programada = ?,
        fecha_curso_fin = ?, fecha_graduacion = ?, foto_graduacion = ?,
        asiste_administracion = ?, id_administrativo = ?, status_graduacion = ?, calidad = ?, observaciones = ?
       WHERE id_graduacion = ?`,
      [final.id_grupo, final.id_curso, final.id_maestro_inicio, final.id_maestro_fin,
        final.fecha_curso_inicio, final.fecha_curso_fin_programada, final.fecha_graduacion_programada,
        final.fecha_curso_fin, final.fecha_graduacion, final.foto_graduacion,
        final.asiste_administracion, final.id_administrativo, final.status_graduacion, final.calidad,
        final.observaciones, idGraduacion]
    );

    await registrarAuditoria(connection, req, "GRADUACION_EDITADA", idGraduacion, antes, final);
    const actualizado = await consultarGraduacion(connection, idGraduacion);
    await connection.commit();
    return res.json({ ok: true, message: "Graduación actualizada correctamente.", warnings, data: actualizado || final });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD GRADUACIONES] Error editando", error);
    return res.status(500).json({ ok: false, code: "ERROR_EDITANDO_GRADUACION", message: "No pudimos actualizar la graduación." });
  } finally {
    connection.release();
  }
});

async function cerrarCurso(req, res) {
  if (!permitirGraduaciones(req, res)) return;
  const idGraduacion = normalizarTexto(req.params.id_graduacion);
  const fechaCursoFin = normalizarTexto(req.body?.fecha_curso_fin) || fechaMexico();
  const idMaestroFinSolicitado = normalizarTexto(req.body?.id_maestro_fin);
  const observacionesSolicitadas = tieneCampo(req.body, "observaciones") ? normalizarTexto(req.body?.observaciones) : undefined;

  if (!fechaValida(fechaCursoFin)) return res.status(400).json({ ok: false, code: "FECHA_CURSO_FIN_INVALIDA", message: "Selecciona una fecha real de fin de curso válida." });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const antes = await obtenerGraduacionBloqueada(connection, idGraduacion);
    if (!antes) {
      await connection.rollback();
      return res.status(404).json({ ok: false, code: "GRADUACION_NO_ENCONTRADA", message: "No encontramos esa graduación." });
    }

    const grupo = await obtenerGrupoActivo(connection, antes.id_grupo, false);
    const idMaestroFin = idMaestroFinSolicitado || normalizarTexto(grupo?.IdMaestroTitular) || antes.id_maestro_fin || antes.id_maestro_inicio;
    if (!idMaestroFin || !(await validarUsuarioRol(connection, idMaestroFin, ["Maestro"]))) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "MAESTRO_FIN_INVALIDO", message: "Selecciona un maestro final válido." });
    }
    if (antes.fecha_curso_inicio && fechaCursoFin < antes.fecha_curso_inicio) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "ORDEN_FECHA_CURSO_FIN_INVALIDO", message: "La fecha de fin no puede ser anterior al inicio del curso." });
    }

    const despues = {
      ...antes,
      fecha_curso_fin: fechaCursoFin,
      id_maestro_fin: idMaestroFin,
      observaciones: observacionesSolicitadas === undefined ? antes.observaciones : observacionesSolicitadas
    };
    await connection.query(
      "UPDATE graduaciones SET fecha_curso_fin = ?, id_maestro_fin = ?, observaciones = ? WHERE id_graduacion = ?",
      [despues.fecha_curso_fin, despues.id_maestro_fin, despues.observaciones, idGraduacion]
    );
    await registrarAuditoria(connection, req, "CURSO_CERRADO", idGraduacion, antes, despues);
    const actualizado = await consultarGraduacion(connection, idGraduacion);
    await connection.commit();
    return res.json({ ok: true, message: "Fin de curso registrado correctamente.", data: actualizado || despues });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD GRADUACIONES] Error cerrando curso", error);
    return res.status(500).json({ ok: false, code: "ERROR_CERRANDO_CURSO", message: "No pudimos registrar el fin del curso." });
  } finally {
    connection.release();
  }
}

router.patch("/:id_graduacion/cerrar-curso", cerrarCurso);

async function graduar(req, res) {
  if (!permitirGraduaciones(req, res)) return;
  const idGraduacion = normalizarTexto(req.params.id_graduacion);
  const fechaGraduacion = normalizarTexto(req.body?.fecha_graduacion) || fechaMexico();
  const asisteAdministracion = normalizarBooleano(req.body?.asiste_administracion ?? false);
  const idAdministrativo = normalizarTexto(req.body?.id_administrativo);
  const fotoGraduacion = normalizarTexto(req.body?.foto_graduacion);
  const calidad = normalizarTexto(req.body?.calidad);
  const observacionesSolicitadas = tieneCampo(req.body, "observaciones") ? normalizarTexto(req.body?.observaciones) : undefined;

  if (!fechaValida(fechaGraduacion)) return res.status(400).json({ ok: false, code: "FECHA_GRADUACION_INVALIDA", message: "Selecciona una fecha real de graduación válida." });
  if (asisteAdministracion === null) return res.status(400).json({ ok: false, code: "ASISTENCIA_ADMINISTRACION_INVALIDA", message: "Indica si asistió administración." });
  if (calidad && !CALIDADES.has(calidad)) return res.status(400).json({ ok: false, code: "CALIDAD_INVALIDA", message: "Calidad debe ser Baja, Buena o Muy buena." });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const antes = await obtenerGraduacionBloqueada(connection, idGraduacion);
    if (!antes) {
      await connection.rollback();
      return res.status(404).json({ ok: false, code: "GRADUACION_NO_ENCONTRADA", message: "No encontramos esa graduación." });
    }
    if (antes.fecha_curso_inicio && fechaGraduacion < antes.fecha_curso_inicio) {
      await connection.rollback();
      return res.status(400).json({ ok: false, code: "ORDEN_FECHA_GRADUACION_INVALIDO", message: "La fecha de graduación no puede ser anterior al inicio del curso." });
    }
    if (asisteAdministracion) {
      if (!idAdministrativo) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "ADMINISTRATIVO_REQUERIDO", message: "Selecciona el administrativo que asistió." });
      }
      if (!(await validarUsuarioRol(connection, idAdministrativo, ["Admin", "Administrador", "Directivo"]))) {
        await connection.rollback();
        return res.status(400).json({ ok: false, code: "ADMINISTRATIVO_INVALIDO", message: "El administrativo indicado no está disponible." });
      }
    }

    const despues = {
      ...antes,
      fecha_graduacion: fechaGraduacion,
      foto_graduacion: fotoGraduacion,
      calidad,
      asiste_administracion: asisteAdministracion ? 1 : 0,
      id_administrativo: asisteAdministracion ? idAdministrativo : null,
      observaciones: observacionesSolicitadas === undefined ? antes.observaciones : observacionesSolicitadas,
      status_graduacion: "COMPLETADA"
    };

    await connection.query(
      `UPDATE graduaciones SET fecha_graduacion = ?, foto_graduacion = ?, calidad = ?,
       asiste_administracion = ?, id_administrativo = ?, observaciones = ?, status_graduacion = 'COMPLETADA'
       WHERE id_graduacion = ?`,
      [despues.fecha_graduacion, despues.foto_graduacion, despues.calidad, despues.asiste_administracion,
        despues.id_administrativo, despues.observaciones, idGraduacion]
    );
    await registrarAuditoria(connection, req, "GRADUACION_COMPLETADA", idGraduacion, antes, despues);
    const actualizado = await consultarGraduacion(connection, idGraduacion);
    await connection.commit();
    return res.json({
      ok: true,
      message: "Graduación registrada correctamente.",
      warnings: warningCalidad(calidad, despues.observaciones),
      data: actualizado || despues
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD GRADUACIONES] Error graduando", error);
    return res.status(500).json({ ok: false, code: "ERROR_COMPLETANDO_GRADUACION", message: "No pudimos registrar la graduación." });
  } finally {
    connection.release();
  }
}

router.patch("/:id_graduacion/graduar", graduar);
router.patch("/:id_graduacion/completar", graduar);

router.patch("/:id_graduacion/cancelar", async (req, res) => {
  if (!permitirGraduaciones(req, res)) return;
  const idGraduacion = normalizarTexto(req.params.id_graduacion);
  const observaciones = normalizarTexto(req.body?.observaciones);
  if (!observaciones) return res.status(400).json({ ok: false, code: "OBSERVACIONES_REQUERIDAS", message: "Escribe el motivo de cancelación." });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const antes = await obtenerGraduacionBloqueada(connection, idGraduacion);
    if (!antes) {
      await connection.rollback();
      return res.status(404).json({ ok: false, code: "GRADUACION_NO_ENCONTRADA", message: "No encontramos esa graduación." });
    }
    const despues = { ...antes, status_graduacion: "CANCELADA", observaciones };
    await connection.query("UPDATE graduaciones SET status_graduacion = 'CANCELADA', observaciones = ? WHERE id_graduacion = ?", [observaciones, idGraduacion]);
    await registrarAuditoria(connection, req, "GRADUACION_CANCELADA", idGraduacion, antes, despues);
    const actualizado = await consultarGraduacion(connection, idGraduacion);
    await connection.commit();
    return res.json({ ok: true, message: "Graduación cancelada correctamente. El curso conserva su historial.", data: actualizado || despues });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD GRADUACIONES] Error cancelando", error);
    return res.status(500).json({ ok: false, code: "ERROR_CANCELANDO_GRADUACION", message: "No pudimos cancelar la graduación." });
  } finally {
    connection.release();
  }
});

module.exports = router;
