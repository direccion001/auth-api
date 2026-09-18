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
    && ["admin", "administrador", "directivo", "maestro"].includes(rolInterno(req));
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
         ORDER BY Nombre, Apellidos`
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
    const idAsistencia = fecha ? `${idGrupo}-${fecha.replace(/-/g, "")}` : null;
    let yaRegistrada = false;
    if (idAsistencia) {
      const [rows] = await pool.query("SELECT 1 FROM ASISTENCIAS WHERE IdAsistencia = ? LIMIT 1", [idAsistencia]);
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
  const q = String(req.query.q || "").trim();

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
    if (!fechaValidaParaGrupo(grupo, fecha)) {
      const error = new Error("DIA_NO_VALIDO"); error.status = 409; throw error;
    }

    const duracion = duracionHoras(grupo.HoraInicio, grupo.HoraFin);
    if (duracion === null) {
      const error = new Error("HORARIO_INVALIDO"); error.status = 409; throw error;
    }
    const pago = Math.round((cuota * duracion) * 100) / 100;

    if (curso) {
      const [cursoRows] = await connection.query(
        `SELECT \`Primer Capitulo\` AS primero, \`Ultimo Capitulo\` AS ultimo
         FROM CURSOS WHERE \`ID CURSO\` = ? AND Status = 1 LIMIT 1`,
        [curso]
      );
      if (!cursoRows.length) {
        const error = new Error("CURSO_INVALIDO"); error.status = 400; throw error;
      }
      if (capitulo !== null && (capitulo < Number(cursoRows[0].primero) || capitulo > Number(cursoRows[0].ultimo))) {
        const error = new Error("CAPITULO_INVALIDO"); error.status = 400; throw error;
      }
    }

    const idsAlumnos = [...new Set(alumnos.map((a) => String(a.id_alumno || "").trim()).filter(Boolean))];
    let alumnosDb = [];
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
        cuota,
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

      if (!alumno || !["Asistio", "Falto"].includes(presente) || !["Si", "No"].includes(justificada)) {
        const error = new Error("ESTADO_ASISTENCIA_INVALIDO"); error.status = 400; throw error;
      }
      if (presente === "Asistio" && justificada === "Si") {
        const error = new Error("ASISTENCIA_INCONSISTENTE"); error.status = 400; throw error;
      }

      await connection.query(
        `INSERT INTO DETALLE_ASISTENCIAS (
          IdDetalle, IdAsistenciaInterno, IdAsistencia, IdGrupo, IdAlumno, Fecha,
          NombreAlumno, Presente, Justificada, DiasClase
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
          grupo.DiasClase || null
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
