const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRouter = require("./routes/auth");
const viewerRouter = require("./routes/viewer");
const viewerProspectosPrivacyRouter = require("./routes/viewer-prospectos-privacy");
const seguimientosViewerRouter = require("./routes/viewer-seguimientos");
const alumnosAsistenciasViewerRouter = require("./routes/viewer-alumnos-asistencias");
const alumnoInfoViewerRouter = require("./routes/viewer-alumno-info");
const alumnosViewerRouter = require("./routes/viewer-alumnos");
const usuariosInternosViewerRouter = require("./routes/viewer-usuarios-internos");
const graduacionesViewerRouter = require("./routes/viewer-graduaciones");
const alumnosCrudRouter = require("./routes/crud/alumnos");
const detallesSeguimientosProximoRouter = require("./routes/crud/detalles-seguimientos-proximo");
const crudRouter = require("./routes/crud");

const app = express();

app.use(cors());
app.use(express.json());

// Health check
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "company-viewer-api"
  });
});

// Rutas
app.use("/auth", authRouter);
app.use("/viewer/seguimientos", seguimientosViewerRouter);
// Rutas especializadas de alumnos deben montarse antes del router interno general.
app.use("/viewer/alumnos", alumnosAsistenciasViewerRouter);
app.use("/viewer/alumnos", alumnoInfoViewerRouter);
app.use("/viewer/alumnos", alumnosViewerRouter);
app.use("/viewer/usuarios-internos", usuariosInternosViewerRouter);
app.use("/viewer/graduaciones", graduacionesViewerRouter);
app.use("/viewer", viewerProspectosPrivacyRouter);
app.use("/viewer", viewerRouter);
app.use("/crud/alumnos", alumnosCrudRouter);
app.use("/crud/detalles-seguimientos", detallesSeguimientosProximoRouter);
app.use("/crud", crudRouter);

// 404
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    code: "RUTA_NO_ENCONTRADA",
    message: "La ruta solicitada no existe."
  });
});

// Error general
app.use((error, req, res, next) => {
  console.error("[SERVER ERROR]", error);

  res.status(500).json({
    ok: false,
    code: "ERROR_INTERNO",
    message: "Ocurrió un error interno."
  });
});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`Company Viewer API escuchando en puerto ${PORT}`);
});
