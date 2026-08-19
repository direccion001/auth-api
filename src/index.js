const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRouter = require("./routes/auth");
const viewerRouter = require("./routes/viewer");
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
app.use("/viewer", viewerRouter);

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