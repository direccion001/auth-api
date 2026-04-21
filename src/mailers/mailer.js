const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// 🔥 cargar template
function loadTemplate(templateName) {
  const filePath = path.join(__dirname, "templates", templateName);
  return fs.readFileSync(filePath, "utf-8");
}

// 🔥 reemplazar variables
function renderTemplate(template, variables) {
  let html = template;

  for (const key in variables) {
    html = html.replace(new RegExp(`{{${key}}}`, "g"), variables[key]);
  }

  return html;
}

// 🔥 función genérica
async function sendEmail({ to, subject, templateName, variables }) {
  const rawTemplate = loadTemplate(templateName);
  const html = renderTemplate(rawTemplate, variables);

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject,
    html
  });
}

module.exports = { sendEmail };