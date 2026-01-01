const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendSetPasswordEmail(to, token) {
  const link = `${process.env.FRONTEND_URL}/set-password?token=${token}`;

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject: "Activa tu cuenta",
    html: `
      <div style="font-family: Arial, sans-serif; font-size: 14px; color: #333;">
        <p>Hola,</p>

        <p>
          Recibimos una solicitud para crear o restablecer la contraseña de tu cuenta
          en <strong>Inglés por Resultados</strong>.
        </p>

        <p>
          Para continuar, haz clic en el siguiente enlace:
        </p>

        <p style="margin: 20px 0;">
          <a href="${link}" target="_blank"
             style="background:#b91c1c;color:#fff;padding:12px 18px;
                    text-decoration:none;border-radius:4px;display:inline-block;">
            Crear contraseña
          </a>
        </p>

        <p>
          No compartas este correo con nadie. Si el botón no funciona, copia y pega este enlace en tu navegador:
        </p>

        <p style="word-break: break-all;">
          ${link}
        </p>

        <hr style="margin:30px 0;border:none;border-top:1px solid #ddd;">

        <p style="font-size:12px;color:#666;">
          Si no solicitaste este correo, puedes ignorarlo con seguridad.
          <br>
          Este enlace expirará automáticamente.
        </p>

        <p style="font-size:12px;color:#666;">
          — Equipo de Inglés por Resultados
        </p>
      </div>
    `
  });
}


module.exports = { sendSetPasswordEmail };


