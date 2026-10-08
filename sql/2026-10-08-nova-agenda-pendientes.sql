-- NOVA Company Viewer / Registrar asistencias desde AGENDA GRUPOS
-- Ejecutar una sola vez en ipr_db antes de desplegar el backend.
-- Verificar previamente SHOW CREATE TABLE `AGENDA GRUPOS`.
ALTER TABLE `AGENDA GRUPOS`
  ADD COLUMN `Activo` TINYINT(1) NOT NULL DEFAULT 1;

-- Se crea una nueva vista; VW_AGENDA_CLASES_PENDIENTES no se modifica.
-- IdMaestroTitularAgenda se conserva sólo como histórico.
-- El API aplicará el alcance del Maestro usando IdMaestroTitularActual.
CREATE OR REPLACE VIEW `vw_nova_asistencias_pendientes` AS
SELECT
  ag.IdAgenda,
  ag.Fecha,
  ag.IdPlantel,
  ag.IdGrupo,
  ag.IdMaestroTitular AS IdMaestroTitularAgenda,
  g.IdMaestroTitular AS IdMaestroTitularActual,
  ag.HoraInicio,
  ag.HoraFin,
  ag.Activo,
  g.NombreGrupo AS Grupo,
  g.Status AS StatusGrupo,
  COALESCE(g.EsExtraHelp, 0) AS EsExtraHelp,
  g.CuotaHora,
  p.NombrePlantel AS Plantel
FROM `AGENDA GRUPOS` ag
INNER JOIN GRUPOS g ON g.IdGrupo = ag.IdGrupo
LEFT JOIN PLANTELES p ON p.IdPlantel = ag.IdPlantel
WHERE ag.Activo = 1
  AND ag.Fecha IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM ASISTENCIAS a
    WHERE a.IdGrupo = ag.IdGrupo
      AND a.FechaClase = ag.Fecha
  );

-- Verificar después de aplicar:
-- SHOW CREATE TABLE `AGENDA GRUPOS`;
-- SHOW CREATE VIEW vw_nova_asistencias_pendientes;
-- SELECT Fecha, IdGrupo, COUNT(*) AS n
--   FROM vw_nova_asistencias_pendientes
--   GROUP BY Fecha, IdGrupo HAVING n > 1;
