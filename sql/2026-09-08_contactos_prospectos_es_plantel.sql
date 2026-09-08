-- Contactos de prospectos registrados desde Company Viewer.
-- Los contactos internos conservan es_plantel = 0 e id_usuario obligatorio por aplicación.
-- Los contactos creados por un plantel usan es_plantel = 1 e id_usuario = NULL.

ALTER TABLE contactos_examenes_evaluacion
  MODIFY COLUMN id_usuario varchar(40) NULL,
  ADD COLUMN es_plantel tinyint(1) NOT NULL DEFAULT 0 AFTER id_usuario,
  ADD KEY idx_contacto_es_plantel (es_plantel),
  ADD CONSTRAINT chk_contacto_actor
    CHECK (
      (es_plantel = 1 AND id_usuario IS NULL)
      OR
      (es_plantel = 0 AND id_usuario IS NOT NULL)
    );
