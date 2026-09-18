-- Registro de asistencias + Extra Help
-- Aplicar una sola vez en ipr_db.

ALTER TABLE GRUPOS
  ADD COLUMN EsExtraHelp TINYINT(1) NOT NULL DEFAULT 0 AFTER Tipo;

ALTER TABLE ASISTENCIAS
  ADD COLUMN IdUsuarioRegistro VARCHAR(50) NULL AFTER UsuarioApp,
  ADD CONSTRAINT fk_asistencias_usuario_registro
    FOREIGN KEY (IdUsuarioRegistro)
    REFERENCES USUARIOS (`ID Usuario`)
    ON DELETE SET NULL
    ON UPDATE CASCADE;

CREATE OR REPLACE VIEW vw_company_viewer_grupos AS
SELECT
  g.IdGrupo AS IdGrupo,
  g.IdPlantel AS IdPlantel,
  g.NombreGrupo AS Grupo,
  g.Status AS StatusGrupo,
  g.Modalidad AS Modalidad,
  g.Tipo AS TipoGrupo,
  COALESCE(g.EsExtraHelp, 0) AS EsExtraHelp,
  g.ClasePrivada AS ClasePrivada,
  COALESCE(g.TieneCupoMaximo, 0) AS TieneCupoMaximo,
  g.CupoMaximo AS CupoMaximo,
  COALESCE(alu.AlumnosActuales, 0) AS AlumnosActuales,
  CASE
    WHEN COALESCE(g.TieneCupoMaximo, 0) = 1
      AND g.CupoMaximo IS NOT NULL
      AND g.CupoMaximo > 0
    THEN CAST(ROUND((COALESCE(alu.AlumnosActuales, 0) / g.CupoMaximo) * 100, 0) AS UNSIGNED)
    ELSE NULL
  END AS PorcentajeOcupacion,
  g.`DíasClase` AS DiasClase,
  g.HoraInicio AS HoraInicio,
  g.HoraFin AS HoraFin,
  g.Materia AS Materia,
  g.IdMaestroTitular AS IdMaestroTitular,
  CONCAT_WS(' ', u.Nombre, u.Apellidos) AS Titular,
  ult.FechaClase AS FechaUltimaAsistencia,
  ult.Curso AS IdCursoActual,
  c.Nombre AS CursoActual,
  c.Color AS ColorCursoActual,
  ult.Capitulo AS CapituloActual,
  ult.Pagina AS PaginaActual,
  p.NombrePlantel AS Plantel,
  p.Status AS StatusPlantel,
  p.LogoUrl AS LogoUrl,
  p.LogoCliente AS LogoCliente
FROM GRUPOS g
LEFT JOIN USUARIOS u ON u.`ID Usuario` = g.IdMaestroTitular
LEFT JOIN PLANTELES p ON p.IdPlantel = g.IdPlantel
LEFT JOIN (
  SELECT ranked.IdGrupo, ranked.FechaClase, ranked.Curso, ranked.Capitulo, ranked.Pagina
  FROM (
    SELECT
      a.IdGrupo,
      a.FechaClase,
      a.Curso,
      a.Capitulo,
      a.Pagina,
      ROW_NUMBER() OVER (
        PARTITION BY a.IdGrupo
        ORDER BY a.FechaClase DESC, a.IdInterno DESC
      ) AS rn
    FROM ASISTENCIAS a
    WHERE a.IdGrupo IS NOT NULL
  ) ranked
  WHERE ranked.rn = 1
) ult ON ult.IdGrupo = g.IdGrupo
LEFT JOIN CURSOS c ON c.`ID CURSO` = ult.Curso
LEFT JOIN (
  SELECT a.IdGrupo, COUNT(*) AS AlumnosActuales
  FROM ALUMNOS a
  WHERE a.Status = 'Activo'
    AND a.IdGrupo IS NOT NULL
  GROUP BY a.IdGrupo
) alu ON alu.IdGrupo = g.IdGrupo;

CREATE OR REPLACE VIEW vw_company_viewer_asistencias AS
SELECT
  v.IdDetalle AS IdDetalle,
  v.IdAsistenciaInterno AS IdAsistenciaInterno,
  v.IdAsistencia AS IdAsistencia,
  v.IdAlumno AS IdAlumno,
  v.Fecha AS Fecha,
  v.UsuarioApp AS UsuarioApp,
  v.Sustitucion AS Sustitucion,
  v.ComentarioClase AS ComentarioClase,
  v.ComentarioAlumno AS ComentarioAlumno,
  v.Nombre AS Nombre,
  v.NombreAlumno AS NombreAlumno,
  v.ApellidosAlumno AS ApellidosAlumno,
  v.StatusAlumno AS StatusAlumno,
  v.FechaRegistroAlumno AS FechaRegistroAlumno,
  v.FechaBajaAlumno AS FechaBajaAlumno,
  v.AsistenciaAlumno AS AsistenciaAlumno,
  v.EnSeguimiento AS EnSeguimiento,
  v.Presente AS Presente,
  v.Justificada AS Justificada,
  v.IdGrupo AS IdGrupo,
  v.IdPlantel AS IdPlantel,
  v.Grupo AS Grupo,
  v.StatusGrupo AS StatusGrupo,
  v.Modalidad AS Modalidad,
  v.TipoGrupo AS TipoGrupo,
  COALESCE(g.EsExtraHelp, 0) AS EsExtraHelp,
  v.ClasePrivada AS ClasePrivada,
  v.DiasClase AS DiasClase,
  v.HoraInicio AS HoraInicio,
  v.HoraFin AS HoraFin,
  v.IdMaestroTitular AS IdMaestroTitular,
  v.Titular AS Titular,
  v.IdMaestroQueDioClase AS IdMaestroQueDioClase,
  v.Maestro AS Maestro,
  v.IdCurso AS IdCurso,
  v.Curso AS Curso,
  v.ColorCurso AS ColorCurso,
  v.Cap AS Cap,
  v.Pagina AS Pagina,
  v.Duracion AS Duracion,
  v.Plantel AS Plantel,
  v.CorreoCliente AS CorreoCliente,
  v.LogoUrl AS LogoUrl,
  al.CuotaMensual AS CuotaMensual,
  ROUND(al.CuotaMensual * 0.90, 2) AS CuotaMensualConDescuento,
  a.Pago AS PagoMaestro
FROM vw_detalle_asistencias_completo_renovado v
LEFT JOIN ALUMNOS al ON al.IdAlumno = v.IdAlumno
LEFT JOIN ASISTENCIAS a ON a.IdInterno = v.IdAsistenciaInterno
LEFT JOIN GRUPOS g ON g.IdGrupo = v.IdGrupo;
