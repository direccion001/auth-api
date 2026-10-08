const express = require("express");
const crypto = require("crypto");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");

const router = express.Router();
router.use(requireAuth);

function normalizarTexto(valor) {
  if (valor === null || valor === undefined) return null;
  const texto = String(valor).trim();
  return texto || null;
}

function rolInterno(req) {
  return String(req.auth?.rol || "").trim().toLowerCase();
}

function puedeRegistrar(req) {
  return req.auth?.tipo_usuario === "INTERNO"
    && req.auth?.modulos?.includes("asistencias")
    && ["admin", "administrador", "directivo", "maestro"].includes(rolInterno(req));
}

function esMaestro(req) {
  return req.auth?.tipo_usuario === "INTERNO" && rolInterno(req) === "maestro";
}

function fechaHoyMexico() {
  const partes = new Intl.DateTimeFormat("en-US", {
    timeZone: "America/Mexico_City", year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(new Date());
  const valor = (tipo) => partes.find((parte) => parte.type === tipo)?.value;
  return `${valor("year")}-${valor("month")}-${valor("day")}`;
}

function validarGrupoMaestro(req, grupo) {
  return !esMaestro(req) || (
    String(grupo.IdMaestroTitular || "") === String(req.auth.id_usuario) &&
    Number(grupo.EsExtraHelp || 0) === 0
  );
}

function puedeRegistrarSinAlumnos(req) {
  return ["admin", "administrador", "directivo"].includes(rolInterno(req));
}

function minutosDesdeHora(valor) {
  const texto = String(valor || "").slice(0, 5);
  const [h, m] = texto.split(":").map(Number);
  if (!Number.isFinite(h) || !Number.isFinite(m)) return null;
  return h * 60 + m;
}

function duracionHoras(horaInicio, horaFin) {
  const inicio = minutosDesdeHora(horaInicio);
  const fin = minutosDesdeHora(horaFin);
  if (inicio === null || fin === null || fin <= inicio) return null;
  return Math.round(((fin - inicio) / 60) * 100) / 100;
}

function normalizarDia(texto) {
  return String(texto || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

function diaFecha(fecha) {
  const [y, m, d] = String(fecha || "").split("-").map(Number);
  if (!y || !m || !d) return null;
  const dias = ["domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado"];
  return dias[new Date(Date.UTC(y, m - 1, d)).getUTCDay()] || null;
}

function fechaValidaParaGrupo(grupo, fecha) {
  if (Number(grupo.EsExtraHelp || 0) === 1 || Number(grupo.ClasePrivada || 0) === 1) return true;
  const dia = diaFecha(fecha);
  if (!dia) return false;
  const dias = normalizarDia(grupo.DiasClase)
    .split(/[,/|;-]+/)
    .map((x) => x.trim())
    .filter(Boolean);
  return dias.some((item) => item === dia || item.startsWith(dia.slice(0, 3)));
}

async function obtenerGrupo(connection, idGrupo) {
  const [rows] = await connection.query(
    `
      SELECT
        g.IdGrupo,
        g.NombreGrupo,
        g.IdPlantel,
        g.IdMaestroTitular,
        g.\`DíasClase\` AS DiasClase,
        g.HoraInicio,
        g.HoraFin,
        g.CuotaHora,
        g.CuotaSustitucion,
        g.Status,
        g.ClasePrivada,
        COALESCE(g.EsExtraHelp, 0) AS EsExtraHelp,
        CONCAT_WS(' ', u.Nombre, u.Apellidos) AS MaestroTitular
      FROM GRUPOS g
      LEFT JOIN USUARIOS u ON u.\`ID Usuario\` = g.IdMaestroTitular
      WHERE g.IdGrupo = ?
      LIMIT 1
    `,
    [idGrupo]
  );
  return rows[0] || null;
}


function esAdminDirectivo(req) {
  return req.auth?.tipo_usuario === "INTERNO"
    && req.auth?.modulos?.includes("asistencias")
    && ["admin", "administrador", "directivo"].includes(rolInterno(req));
}

router.get("/pendientes", async (req, res) => {
  if (!puedeRegistrar(req)) {
    return res.status(403).json({ ok: false, code: "ASISTENCIA_NO_AUTORIZADA", message: "No tienes permiso para consultar pendientes." });
  }
  const fechaMaxima = fechaHoyMexico();
  const params = [fechaMaxima];
  let sql = `
    SELECT p.IdAgenda, p.Fecha, p.IdPlantel, p.IdGrupo,
           p.Grupo, p.Plantel, p.HoraInicio, p.HoraFin,
           p.EsExtraHelp, p.StatusGrupo
    FROM vw_company_viewer_asistencias_pendientes p
    WHERE p.Fecha <= ?
  `;
  if (esMaestro(req)) {
    sql += " AND p.IdMaestroTitularActual = ? AND p.EsExtraHelp = 0 AND p.StatusGrupo = 'Activo'";
    params.push(req.auth.id_usuario);
  } else if (req.query.id_plantel) {
    sql += " AND p.IdPlantel = ?";
    params.push(String(req.query.id_plantel));
  }
  sql += " ORDER BY p.Fecha DESC, p.HoraInicio ASC, p.Grupo ASC";
  try {
    const [rows] = await pool.query(sql, params);
    return res.json({ ok: true, data: rows, fecha_hoy: fechaMaxima });
  } catch (error) {
    console.error("[CRUD ASISTENCIAS] pendientes", error);
    return res.status(500).json({ ok: false, code: "ERROR_PENDIENTES", message: "No pudimos consultar las asistencias pendientes." });
  }
});

router.patch("/pendientes/:idAgenda/inactivar", async (req, res) => {
  if (!esAdminDirectivo(req)) {
    return res.status(403).json({ ok: false, code: "ROL_NO_AUTORIZADO", message: "Sólo Administración puede inactivar pendientes." });
  }
  const idAgenda = String(req.params.idAgenda || "").trim();
  if (!idAgenda) return res.status(400).json({ ok: false, code: "AGENDA_REQUERIDA", message: "Selecciona un pendiente." });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query(
      "SELECT IdAgenda, IdGrupo, Fecha, Activo FROM \`AGENDA GRUPOS\` WHERE IdAgenda = ? FOR UPDATE",
      [idAgenda]
    );
    if (!rows.length || Number(rows[0].Activo ?? 1) !== 1) {
      await conn.rollback();
      return res.status(404).json({ ok: false, code: "PENDIENTE_NO_DISPONIBLE", message: "El pendiente ya no está disponible." });
    }
    const agenda = rows[0];
    const [asistencias] = await conn.query("SELECT 1 FROM ASISTENCIAS WHERE IdGrupo = ? AND FechaClase = ? LIMIT 1", [agenda.IdGrupo, agenda.Fecha]);
    if (asistencias.length) {
      await conn.rollback();
      return res.status(409).json({ ok: false, code: "ASISTENCIA_YA_REGISTRADA", message: "La asistencia ya fue registrada." });
    }
    await conn.query("UPDATE \`AGENDA GRUPOS\` SET Activo = 0 WHERE IdAgenda = ?", [idAgenda]);
    await conn.commit();
    return res.json({ ok: true, message: "Pendiente inactivado.", data: { id_agenda: idAgenda } });
  } catch (error) {
    await conn.rollback().catch(() => {});
    console.error("[CRUD ASISTENCIAS] inactivar pendiente", error);
    return res.status(500).json({ ok: false, code: "ERROR_INACTIVANDO_PENDIENTE", message: "No pudimos inactivar el pendiente." });
  } finally {
    conn.release();
  }
});

router.get("/contexto", async (req, res) => {
  if (!puedeRegistrar(req)) {
    return res.status(403).json({ ok: false, code: "ASISTENCIA_NO_AUTORIZADA", message: "No tienes permiso para registrar asistencias." });
  }

  const idGrupo = String(req.query.id_grupo || "").trim();
  const fecha = String(req.query.fecha || "").trim();

  if (!idGrupo) {
    return res.status(400).json({ ok: false, code: "GRUPO_REQUERIDO", message: "Selecciona un grupo." });
  }

  try {
    const grupo = await obtenerGrupo(pool, idGrupo);
    if (!grupo || String(grupo.Status || "").trim().toLowerCase() !== "activo") {
      return res.status(404).json({ ok: false, code: "GRUPO_NO_DISPONIBLE", message: "El grupo no está disponible." });
    }
    if (!validarGrupoMaestro(req, grupo)) {
      return res.status(403).json({ ok: false, code: "GRUPO_NO_AUTORIZADO", message: "Sólo puedes registrar tus grupos regulares." });
    }

    const [ultimaRows, maestros, cursos] = await Promise.all([
      pool.query(
        `SELECT FechaClase, Curso, Capitulo, Pagina
         FROM ASISTENCIAS
         WHERE IdGrupo = ?
         ORDER BY FechaClase DESC, IdInterno DESC
         LIMIT 1`,
        [idGrupo]
      ),
      pool.query(
        `SELECT \`ID Usuario\` AS id, CONCAT_WS(' ', Nombre, Apellidos) AS nombre
         FROM USUARIOS
         WHERE Status = 'Activo'
           ${esMaestro(req) ? "AND \`ID Usuario\` = ?" : ""}
         ORDER BY Nombre, Apellidos`,
        esMaestro(req) ? [req.auth.id_usuario] : []
      ),
      pool.query(
        `SELECT \`ID CURSO\` AS id, Nombre AS nombre, Color AS color,
                \`Primer Capitulo\` AS primer_capitulo,
                \`Ultimo Capitulo\` AS ultimo_capitulo
         FROM CURSOS
         WHERE Status = 1
         ORDER BY Nombre`
      )
    ]);

    const fechaValida = fecha ? fechaValidaParaGrupo(grupo, fecha) : true;
    let yaRegistrada = false;
    if (fecha) {
      const [rows] = await pool.query(
        "SELECT 1 FROM ASISTENCIAS WHERE IdGrupo = ? AND FechaClase = ? LIMIT 1",
        [idGrupo, fecha]
      );
      yaRegistrada = rows.length > 0;
    }

    let alumnos = [];
    if (Number(grupo.EsExtraHelp || 0) !== 1) {
      const [rows] = await pool.query(
        `SELECT IdAlumno AS id, CONCAT_WS(' ', Nombre, Apellidos) AS nombre, Status AS status, IdGrupo AS id_grupo
         FROM ALUMNOS
         WHERE IdPlantel = ?
           AND IdGrupo = ?
           AND Status IN ('activo', 'en formación')
         ORDER BY Nombre, Apellidos`,
        [grupo.IdPlantel, idGrupo]
      );
      alumnos = rows;
    }

    return res.json({
      ok: true,
      data: {
        grupo,
        ultima_asistencia: ultimaRows[0][0] || null,
        fecha_valida: fechaValida,
        ya_registrada: yaRegistrada,
        alumnos,
        maestros: maestros[0],
        cursos: cursos[0]
      }
    });
  } catch (error) {
    console.error("[CRUD ASISTENCIAS] contexto", error);
    return res.status(500).json({ ok: false, code: "ERROR_CONTEXTO_ASISTENCIA", message: "No pudimos cargar el contexto de asistencia." });
  }
});

router.get("/alumnos", async (req, res) => {
  if (!puedeRegistrar(req)) {
    return res.status(403).json({ ok: false, code: "ASISTENCIA_NO_AUTORIZADA", message: "No tienes permiso para registrar asistencias." });
  }

  const idPlantel = String(req.query.id_plantel || "").trim();
  const idGrupo = String(req.query.id_grupo || "").trim();
  const q = String(req.query.q || "").trim();

  if (esMaestro(req)) {
    if (!idGrupo) {
      return res.status(400).json({ ok: false, code: "GRUPO_REQUERIDO", message: "Selecciona uno de tus grupos." });
    }
    try {
      const grupo = await obtenerGrupo(pool, idGrupo);
      if (!grupo || !validarGrupoMaestro(req, grupo) || String(grupo.IdPlantel) !== idPlantel || String(grupo.Status).toLowerCase() !== "activo") {
        return res.status(403).json({ ok: false, code: "GRUPO_NO_AUTORIZADO", message: "No puedes buscar alumnos fuera de tus grupos regulares." });
      }
    } catch (error) {
      console.error("[CRUD ASISTENCIAS] alcance alumnos", error);
      return res.status(500).json({ ok: false, code: "ERROR_ALUMNOS_ASISTENCIA", message: "No pudimos validar el grupo." });
    }
  }

  if (!idPlantel) {
    return res.status(400).json({ ok: false, code: "PLANTEL_REQUERIDO", message: "Selecciona un plantel." });
  }

  try {
    const params = [idPlantel];
    let sql = `
      SELECT
        a.IdAlumno AS id,
        CONCAT_WS(' ', a.Nombre, a.Apellidos) AS nombre,
        a.Status AS status,
        a.IdGrupo AS id_grupo,
        g.NombreGrupo AS grupo
      FROM ALUMNOS a
      LEFT JOIN GRUPOS g ON g.IdGrupo = a.IdGrupo
      WHERE a.IdPlantel = ?
        AND a.Status IN ('activo', 'en formación')
    `;
    if (esMaestro(req)) {
      sql += " AND a.IdGrupo = ? AND g.IdMaestroTitular = ? AND COALESCE(g.EsExtraHelp, 0) = 0";
      params.push(idGrupo, req.auth.id_usuario);
    }
    if (q) {
      sql += " AND CONCAT_WS(' ', a.Nombre, a.Apellidos) LIKE ?";
      params.push(`%${q}%`);
    }
    sql += " ORDER BY a.Nombre, a.Apellidos LIMIT 50";
    const [rows] = await pool.query(sql, params);
    return res.json({ ok: true, data: rows });
  } catch (error) {
    console.error("[CRUD ASISTENCIAS] alumnos", error);
    return res.status(500).json({ ok: false, code: "ERROR_ALUMNOS_ASISTENCIA", message: "No pudimos buscar alumnos." });
  }
});

router.post("/", async (req, res) => {
  if (!puedeRegistrar(req)) {
    return res.status(403).json({ ok: false, code: "ASISTENCIA_NO_AUTORIZADA", message: "No tienes permiso para registrar asistencias." });
  }

  const body = req.body || {};
  const idGrupo = String(body.id_grupo || "").trim();
  const fecha = String(body.fecha_clase || "").trim();
  const idAgenda = String(body.id_agenda || "").trim();
  const idMaestroQueDioClase = String(body.id_maestro_que_dio_clase || "").trim();
  const cuota = Number(body.cuota);
  const curso = normalizarTexto(body.curso);
  const capitulo = body.capitulo === null || body.capitulo === undefined || body.capitulo === "" ? null : Number(body.capitulo);
  const pagina = body.pagina === null || body.pagina === undefined || body.pagina === "" ? null : Number(body.pagina);
  const comentarios = normalizarTexto(body.comentarios);
  const alumnos = Array.isArray(body.alumnos) ? body.alumnos : [];

  if (!idGrupo || !/^\d{4}-\d{2}-\d{2}$/.test(fecha) || !idMaestroQueDioClase || !Number.isFinite(cuota) || cuota < 0) {
    return res.status(400).json({ ok: false, code: "DATOS_ASISTENCIA_INVALIDOS", message: "Revisa grupo, fecha, maestro y cuota." });
  }

  if (!curso || !Number.isInteger(capitulo) || capitulo < 1 || !Number.isInteger(pagina) || pagina < 1) {
    return res.status(400).json({ ok: false, code: "CONTENIDO_REQUERIDO", message: "Curso, capítulo y página son obligatorios." });
  }
  if (!alumnos.length && !puedeRegistrarSinAlumnos(req)) {
    return res.status(409).json({ ok: false, code: "ALUMNOS_REQUERIDOS", message: "Debes registrar al menos un alumno en la asistencia." });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const grupo = await obtenerGrupo(connection, idGrupo);
    if (!grupo || String(grupo.Status || "").trim().toLowerCase() !== "activo") {
      const error = new Error("GRUPO_NO_DISPONIBLE"); error.status = 404; throw error;
    }
    if (!validarGrupoMaestro(req, grupo)) {
      const error = new Error("GRUPO_NO_AUTORIZADO"); error.status = 403; throw error;
    }
    if (esMaestro(req) && fecha !== fechaHoyMexico()) {
      const error = new Error("FECHA_NO_AUTORIZADA"); error.status = 403; throw error;
    }
    if (esMaestro(req) && idMaestroQueDioClase !== String(req.auth.id_usuario)) {
      const error = new Error("MAESTRO_NO_AUTORIZADO"); error.status = 403; throw error;
    }
    let agenda = null;
    if (idAgenda) {
      const [agendas] = await connection.query(
        "SELECT IdAgenda, IdGrupo, IdPlantel, Fecha, HoraInicio, HoraFin, Activo FROM \`AGENDA GRUPOS\` WHERE IdAgenda = ? FOR UPDATE",
        [idAgenda]
      );
      agenda = agendas[0] || null;
      if (!agenda || Number(agenda.Activo ?? 1) !== 1 ||
          String(agenda.IdGrupo) !== idGrupo ||
          String(agenda.Fecha).slice(0, 10) !== fecha) {
        const error = new Error("AGENDA_NO_AUTORIZADA"); error.status = 403; throw error;
      }
    }
    if (esMaestro(req) && !agenda) {
      const error = new Error("AGENDA_REQUERIDA"); error.status = 403; throw error;
    }
    if (!agenda && !fechaValidaParaGrupo(grupo, fecha)) {
      const error = new Error("DIA_NO_VALIDO"); error.status = 409; throw error;
    }
    const duracion = duracionHoras(agenda?.HoraInicio || grupo.HoraInicio, agenda?.HoraFin || grupo.HoraFin);
    if (duracion === null) {
      const error = new Error("HORARIO_INVALIDO"); error.status = 409; throw error;
    }
    // La cuota se muestra en el cliente, pero el cálculo del maestro siempre usa GRUPOS.
    const cuotaAplicada = esMaestro(req) ? Number(grupo.CuotaHora) : cuota;
    if (!Number.isFinite(cuotaAplicada) || cuotaAplicada < 0) {
      const error = new Error("CUOTA_INVALIDA"); error.status = 400; throw error;
    }
    const pago = Math.round((cuotaAplicada * duracion) * 100) / 100;

    if (curso) {
      const [cursoRows] = await connection.query(
        `SELECT \`Primer Capitulo\` AS primero, \`Ultimo Capitulo\` AS ultimo
         FROM CURSOS WHERE \`ID CURSO\` = ? AND Status = 1 LIMIT 1`,
        [curso]
      );
      if (!cursoRows.length) {
        const error = new Error("CURSO_INVALIDO"); error.status = 400; throw error;
      }
      if (capitulo < Number(cursoRows[0].primero) || capitulo > Number(cursoRows[0].ultimo)) {
        const error = new Error("CAPITULO_INVALIDO"); error.status = 400; throw error;
      }
    }

    const idsAlumnos = [...new Set(alumnos.map((a) => String(a.id_alumno || "").trim()).filter(Boolean))];
    let alumnosDb = [];
    if (esMaestro(req) && idsAlumnos.length !== alumnos.length) {
      const error = new Error("ALUMNOS_INVALIDOS"); error.status = 400; throw error;
    }
    if (idsAlumnos.length) {
      const placeholders = idsAlumnos.map(() => "?").join(",");
      const [rows] = await connection.query(
        `SELECT IdAlumno, IdPlantel, IdGrupo, Nombre, Apellidos, Status
         FROM ALUMNOS
         WHERE IdAlumno IN (${placeholders})
           AND IdPlantel = ?
           AND Status IN ('activo', 'en formación')`,
        [...idsAlumnos, grupo.IdPlantel]
      );
      if (rows.length !== idsAlumnos.length) {
        const error = new Error("ALUMNOS_INVALIDOS"); error.status = 400; throw error;
      }
      if (Number(grupo.EsExtraHelp || 0) !== 1 && rows.some((a) => String(a.IdGrupo || "") !== idGrupo)) {
        const error = new Error("ALUMNOS_FUERA_DE_GRUPO"); error.status = 400; throw error;
      }
      alumnosDb = rows;
    }

    // Evita duplicados aunque una asistencia histórica no use el IdAsistencia estándar.
    const [existentes] = await connection.query(
      "SELECT IdInterno FROM ASISTENCIAS WHERE IdGrupo = ? AND FechaClase = ? LIMIT 1 FOR UPDATE",
      [idGrupo, fecha]
    );
    if (existentes.length) {
      const error = new Error("ASISTENCIA_YA_REGISTRADA"); error.status = 409; throw error;
    }

    const idInterno = crypto.randomUUID();
    const idAsistencia = `${idGrupo}-${fecha.replace(/-/g, "")}`;
    const sustitucion = String(idMaestroQueDioClase) === String(grupo.IdMaestroTitular || "") ? 0 : 1;

    await connection.query(
      `INSERT INTO ASISTENCIAS (
        IdInterno, UsuarioApp, IdUsuarioRegistro, IdAsistencia,
        IdMaestroQueDioClase, IdMaestroTitular, IdPlantel, IdGrupo,
        FechaClase, Comentarios, Curso, Capitulo, Pagina,
        Cuota, Duracion, Pago, \`En ejecucion\`, Sustitucion
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
      [
        idInterno,
        req.auth.correo || null,
        req.auth.id_usuario || null,
        idAsistencia,
        idMaestroQueDioClase,
        grupo.IdMaestroTitular || null,
        grupo.IdPlantel,
        idGrupo,
        fecha,
        comentarios,
        curso,
        capitulo,
        pagina,
        cuotaAplicada,
        duracion,
        pago,
        sustitucion
      ]
    );

    const alumnosPorId = new Map(alumnosDb.map((a) => [String(a.IdAlumno), a]));
    for (const item of alumnos) {
      const idAlumno = String(item.id_alumno || "").trim();
      const alumno = alumnosPorId.get(idAlumno);
      const presente = String(item.presente || "").trim();
      const justificada = String(item.justificada || "No").trim();
      const tituloComentario = normalizarTexto(item.titulo_comentario);
      const comentarioAlumno = normalizarTexto(item.comentario);
      const esOtro = item.es_otro === true;

      if (!alumno || !["Asistio", "Falto"].includes(presente) || !["Si", "No"].includes(justificada)) {
        const error = new Error("ESTADO_ASISTENCIA_INVALIDO"); error.status = 400; throw error;
      }
      if (presente === "Asistio" && justificada === "Si") {
        const error = new Error("ASISTENCIA_INCONSISTENTE"); error.status = 400; throw error;
      }
      if (esMaestro(req) && justificada === "Si") {
        const error = new Error("JUSTIFICACION_NO_AUTORIZADA"); error.status = 403; throw error;
      }
      const motivos = ["Por enfermedad", "Por carga laboral", "Por asuntos personales", "Por vacaciones", "Por fallas técnicas"];
      if (justificada === "Si" && (!esAdminDirectivo(req) || !tituloComentario ||
          tituloComentario.length > 100 || (!esOtro && !motivos.includes(tituloComentario)))) {
        const error = new Error("MOTIVO_JUSTIFICACION_INVALIDO"); error.status = 400; throw error;
      }

      await connection.query(
        `INSERT INTO DETALLE_ASISTENCIAS (
          IdDetalle, IdAsistenciaInterno, IdAsistencia, IdGrupo, IdAlumno, Fecha,
          NombreAlumno, Presente, Justificada, DiasClase, TituloComentario, Comentario
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          crypto.randomUUID(),
          idInterno,
          idAsistencia,
          idGrupo,
          idAlumno,
          fecha,
          [alumno.Nombre, alumno.Apellidos].filter(Boolean).join(" "),
          presente,
          justificada,
          grupo.DiasClase || null,
          justificada === "Si" ? tituloComentario : null,
          justificada === "Si" ? comentarioAlumno : null
        ]
      );
    }

    await connection.commit();
    return res.status(201).json({
      ok: true,
      message: "Asistencia registrada correctamente.",
      data: { id_interno: idInterno, id_asistencia: idAsistencia, duracion, pago }
    });
  } catch (error) {
    await connection.rollback();

    if (error?.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ ok: false, code: "ASISTENCIA_YA_REGISTRADA", message: "Ya se tomó asistencia para este grupo en este día." });
    }

    const mensajes = {
      GRUPO_NO_DISPONIBLE: "El grupo no está disponible.",
      GRUPO_NO_AUTORIZADO: "Sólo puedes registrar asistencia de tus grupos regulares.",
      FECHA_NO_AUTORIZADA: "No registraste esta asistencia a tiempo. Comunícate con Administración.",
      AGENDA_REQUERIDA: "Selecciona una clase pendiente de hoy para registrar asistencia.",
      AGENDA_NO_AUTORIZADA: "Este pendiente ya no está disponible o no corresponde al grupo y la fecha.",
      ASISTENCIA_YA_REGISTRADA: "Ya existe una asistencia registrada para este grupo y fecha.",
      JUSTIFICACION_NO_AUTORIZADA: "Los maestros no pueden justificar faltas.",
      MOTIVO_JUSTIFICACION_INVALIDO: "Selecciona un motivo de justificación válido.",
      MAESTRO_NO_AUTORIZADO: "El maestro debe registrar la clase a su propio nombre.",
      CUOTA_INVALIDA: "No se encontró una cuota válida para el grupo.",
      DIA_NO_VALIDO: "Este no es un día válido para el grupo seleccionado.",
      HORARIO_INVALIDO: "El horario del grupo no permite calcular la duración.",
      CURSO_INVALIDO: "Selecciona un curso válido.",
      CAPITULO_INVALIDO: "El capítulo está fuera del rango del curso.",
      ALUMNOS_INVALIDOS: "Uno o más alumnos no están disponibles.",
      ALUMNOS_FUERA_DE_GRUPO: "Uno o más alumnos no pertenecen al grupo regular.",
      ESTADO_ASISTENCIA_INVALIDO: "Revisa los estados de asistencia.",
      ASISTENCIA_INCONSISTENTE: "Un alumno que asistió no puede quedar como falta justificada."
    };
    if (mensajes[error.message]) {
      return res.status(error.status || 400).json({ ok: false, code: error.message, message: mensajes[error.message] });
    }

    console.error("[CRUD ASISTENCIAS] registrar", error);
    return res.status(500).json({ ok: false, code: "ERROR_REGISTRANDO_ASISTENCIA", message: "No pudimos registrar la asistencia." });
  } finally {
    connection.release();
  }
});

module.exports = router;
