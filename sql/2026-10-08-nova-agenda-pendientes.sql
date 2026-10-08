-- NOVA Company Viewer / Registrar asistencias desde AGENDA GRUPOS
-- Ejecutar en ipr_db antes de desplegar el backend.
-- Compatible tanto con una BD nueva como con el ALTER que ya pudo ejecutarse.
-- AppSheet puede omitir Activo (default 1) o enviar NULL (la vista lo trata como activo).
SET @agenda_activo_existe = (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'AGENDA GRUPOS'
    AND COLUMN_NAME = 'Activo'
);
SET @agenda_activo_ddl = IF(
  @agenda_activo_existe = 0,
  'ALTER TABLE `AGENDA GRUPOS` ADD COLUMN `Activo` TINYINT(1) NULL DEFAULT 1',
  'ALTER TABLE `AGENDA GRUPOS` MODIFY COLUMN `Activo` TINYINT(1) NULL DEFAULT 1'
);
PREPARE agenda_activo_stmt FROM @agenda_activo_ddl;
EXECUTE agenda_activo_stmt;
DEALLOCATE PREPARE agenda_activo_stmt;

-- Se crea una nueva vista; VW_AGENDA_CLASES_PENDIENTES no se modifica.
-- IdMaestroTitularAgenda se conserva sólo como histórico.
-- El API aplicará el alcance del Maestro usando IdMaestroTitularActual.
CREATE OR REPLACE VIEW `vw_company_viewer_asistencias_pendientes` AS
SELECT
  ag.IdAgenda,
  ag.Fecha,
  g.IdPlantel,
  ag.IdPlantel AS IdPlantelAgenda,
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
LEFT JOIN PLANTELES p ON p.IdPlantel = g.IdPlantel
WHERE COALESCE(ag.Activo, 1) = 1
  AND ag.Fecha IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM ASISTENCIAS a
    WHERE a.IdGrupo = ag.IdGrupo
      AND a.FechaClase = ag.Fecha
  );

-- Verificar después de aplicar:
-- SHOW CREATE TABLE `AGENDA GRUPOS`;
-- SHOW CREATE VIEW vw_company_viewer_asistencias_pendientes;
-- SELECT Fecha, IdGrupo, COUNT(*) AS n
--   FROM vw_company_viewer_asistencias_pendientes
--   GROUP BY Fecha, IdGrupo HAVING n > 1;
