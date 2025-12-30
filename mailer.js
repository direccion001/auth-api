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
      <p>Para activar tu cuenta crea tu contraseña:</p>
      <p><a href="${link}">Crear contraseña</a></p>
    `
  });
}

module.exports = { sendSetPasswordEmail };
