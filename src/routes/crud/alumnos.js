const express = require("express");

const pool = require("../../db/pool");
const requireAuth = require("../../middleware/requireAuth");
const requireInterno = require("../../middleware/requireInterno");

const router = express.Router();

router.use(requireAuth, requireInterno);

function permitirAlumnos(req, res) {
  if (!req.auth.modulos.includes("alumnos")) {
    res.status(403).json({
      ok: false,
      code: "MODULO_NO_AUTORIZADO",
      message: "No tienes acceso al módulo de alumnos."
    });
    return false;
  }
  return true;
}

function texto(value) {
  if (value === null || value === undefined) return null;
  return String(value).trim() || null;
}

router.patch("/:id_alumno/comentarios", async (req, res) => {
  if (!permitirAlumnos(req, res)) return;

  const idAlumno = String(req.params.id_alumno || "").trim();
  if (!idAlumno) {
    return res.status(400).json({
      ok: false,
      code: "ALUMNO_REQUERIDO",
      message: "El alumno indicado no es válido."
    });
  }

  if (!Object.prototype.hasOwnProperty.call(req.body || {}, "comentarios")) {
    return res.status(400).json({
      ok: false,
      code: "COMENTARIOS_REQUERIDOS",
      message: "No hay cambios para guardar."
    });
  }

  const comentarios = texto(req.body.comentarios);
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [rows] = await connection.query(
      "SELECT IdAlumno, Comentarios FROM ALUMNOS WHERE IdAlumno = ? LIMIT 1 FOR UPDATE",
      [idAlumno]
    );

    if (!rows.length) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        code: "ALUMNO_NO_ENCONTRADO",
        message: "No encontramos ese alumno."
      });
    }

    const antes = rows[0].Comentarios ?? null;

    await connection.query(
      "UPDATE ALUMNOS SET Comentarios = ? WHERE IdAlumno = ?",
      [comentarios, idAlumno]
    );

    await connection.query(
      `
      INSERT INTO auditoria_eventos (
        actor_tipo, actor_id, evento, entidad, id_registro, antes_json, despues_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      [
        "INTERNO",
        String(req.auth.id_usuario),
        "ALUMNO_COMENTARIOS_ACTUALIZADOS",
        "ALUMNOS",
        idAlumno,
        JSON.stringify({ Comentarios: antes }),
        JSON.stringify({ Comentarios: comentarios })
      ]
    );

    const [vista] = await connection.query(
      "SELECT * FROM vw_company_viewer_alumnos WHERE IdAlumno = ? LIMIT 1",
      [idAlumno]
    );

    await connection.commit();

    return res.json({
      ok: true,
      message: "Comentario actualizado correctamente.",
      data: vista[0] || { IdAlumno: idAlumno, Comentarios: comentarios }
    });
  } catch (error) {
    try { await connection.rollback(); } catch {}
    console.error("[CRUD ALUMNOS] Error actualizando comentarios", {
      id_alumno: idAlumno,
      id_usuario: req.auth?.id_usuario,
      message: error?.message,
      code: error?.code
    });

    return res.status(500).json({
      ok: false,
      code: "ERROR_ACTUALIZANDO_COMENTARIOS_ALUMNO",
      message: "No pudimos actualizar el comentario del alumno."
    });
  } finally {
    connection.release();
  }
});

module.exports = router;
