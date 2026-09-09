const MODULOS = {
  PLANTEL: [
    "asistencias",
    "calificaciones",
    "prospectos"
  ],

  Admin: [
    "asistencias",
    "calificaciones",
    "prospectos",
    "seguimientos",
    "graduaciones",
    "dashboard"
  ],

  Directivo: [
    "asistencias",
    "calificaciones",
    "prospectos",
    "seguimientos",
    "graduaciones",
    "dashboard"
  ],

  // Preparado para habilitar acceso de maestros más adelante.
  Maestro: []
};

const POLITICAS = {
  PLANTEL: {
    alcance: "PLANTEL",
    acceso_global: false,
    modulos: MODULOS.PLANTEL,
    capacidades: {
      ver_finanzas: false
    }
  },

  Admin: {
    alcance: "GLOBAL",
    acceso_global: true,
    modulos: MODULOS.Admin,
    capacidades: {
      ver_finanzas: true
    }
  },

  Directivo: {
    alcance: "GLOBAL",
    acceso_global: true,
    modulos: MODULOS.Directivo,
    capacidades: {
      ver_finanzas: true
    }
  },

  Maestro: {
    alcance: "MAESTRO",
    acceso_global: false,
    modulos: MODULOS.Maestro,
    capacidades: {
      ver_finanzas: false
    }
  }
};

function obtenerPolitica(clave) {
  return POLITICAS[clave] || null;
}

module.exports = {
  ...MODULOS,
  POLITICAS,
  obtenerPolitica
};
