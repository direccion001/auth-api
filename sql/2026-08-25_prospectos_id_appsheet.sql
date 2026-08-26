-- NOVA Reports / Company Viewer
-- Corrige la relación Prospecto <-> Contactos para usar la clave estable id_appsheet.
--
-- Relación oficial:
--   Examenes_Evaluacion.id_appsheet
--   contactos_examenes_evaluacion.id_appsheet
--
-- Esta migración mantiene id_evaluacion como dato informativo/legacy, pero deja de
-- utilizarlo para enlazar contactos o calcular el número de contactos del prospecto.

CREATE OR REPLACE ALGORITHM=UNDEFINED
SQL SECURITY DEFINER
VIEW `vw_company_viewer_prospecto_contactos` AS
SELECT
  c.id_contacto AS id_contacto,
  c.id_evaluacion AS id_evaluacion,
  c.id_appsheet AS id_appsheet,
  e.id_plantel AS id_plantel,
  c.fecha_hora_contacto AS fecha_hora_contacto,
  CAST(c.fecha_hora_contacto AS DATE) AS fecha_contacto,
  c.forma_contacto AS forma_contacto,
  c.resultado_contacto AS resultado_contacto,
  c.descripcion AS descripcion,
  c.fecha_proximo_seguimiento AS fecha_proximo_seguimiento,
  c.id_usuario AS id_usuario,
  CONCAT_WS(' ', u.Nombre, u.Apellidos) AS usuario_contacto
FROM contactos_examenes_evaluacion c
INNER JOIN Examenes_Evaluacion e
  ON e.id_appsheet = c.id_appsheet
LEFT JOIN USUARIOS u
  ON u.`ID Usuario` = c.id_usuario;

CREATE OR REPLACE ALGORITHM=UNDEFINED
SQL SECURITY DEFINER
VIEW `vw_company_viewer_prospectos` AS
SELECT
  e.id_evaluacion AS id_evaluacion,
  e.id_appsheet AS id_appsheet,
  e.id_plantel AS id_plantel,
  p.NombrePlantel AS plantel,
  e.fecha_hora_creacion AS fecha_hora_creacion,
  CAST(e.fecha_hora_creacion AS DATE) AS fecha_creacion,
  e.nombre AS nombre,
  e.apellido AS apellido,
  CONCAT_WS(' ', e.nombre, e.apellido) AS nombre_completo,
  e.telefono AS telefono,
  e.correo AS correo,
  e.status_contacto AS status_contacto,
  e.status AS status_evaluacion,
  e.comentarios AS comentarios,
  e.id_grupo_propuesto AS id_grupo_propuesto,
  e.id_otras_opciones_grupo AS id_otras_opciones_grupo,
  e.nivel_sugerido AS nivel_sugerido_ids,
  (
    SELECT GROUP_CONCAT(
      c.Nombre
      ORDER BY FIND_IN_SET(c.`ID CURSO`, REPLACE(e.nivel_sugerido, ' ', '')) ASC
      SEPARATOR ','
    )
    FROM CURSOS c
    WHERE FIND_IN_SET(c.`ID CURSO`, REPLACE(e.nivel_sugerido, ' ', '')) > 0
  ) AS nivel_sugerido_nombres,
  (
    SELECT GROUP_CONCAT(
      c.Color
      ORDER BY FIND_IN_SET(c.`ID CURSO`, REPLACE(e.nivel_sugerido, ' ', '')) ASC
      SEPARATOR ','
    )
    FROM CURSOS c
    WHERE FIND_IN_SET(c.`ID CURSO`, REPLACE(e.nivel_sugerido, ' ', '')) > 0
  ) AS nivel_sugerido_colores,
  e.promedio_total AS promedio_total,
  e.fecha_hora_evaluacion AS fecha_hora_examen_escrito,
  e.fecha_hora_audio AS fecha_hora_examen_oral,
  e.origen_lead AS origen_lead,
  e.horario_preferido AS horario_preferido,
  e.etiqueta_prospecto AS etiqueta_prospecto,
  (
    SELECT COUNT(*)
    FROM contactos_examenes_evaluacion ce
    WHERE ce.id_appsheet = e.id_appsheet
  ) AS numero_contactos
FROM Examenes_Evaluacion e
LEFT JOIN PLANTELES p
  ON p.IdPlantel = e.id_plantel;
