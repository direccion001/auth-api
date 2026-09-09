CREATE OR REPLACE VIEW vw_company_viewer_asistencias AS
SELECT
  v.*,
  al.CuotaMensual AS CuotaMensual,
  ROUND(al.CuotaMensual * 0.90, 2) AS CuotaMensualConDescuento,
  a.Pago AS PagoMaestro
FROM vw_detalle_asistencias_completo_renovado v
LEFT JOIN ALUMNOS al
  ON al.IdAlumno = v.IdAlumno
LEFT JOIN ASISTENCIAS a
  ON a.IdInterno = v.IdAsistenciaInterno;
