const nodemailer = require('nodemailer');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { name, email, company, phone, engagementModel, service, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, email and message are required.' });
  }

  const transporter = nodemailer.createTransport({
    host: 'smtp.zoho.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.ZOHO_EMAIL,
      pass: process.env.ZOHO_PASSWORD,
    },
  });

  const html = `
    <div style="font-family:sans-serif;max-width:620px;margin:auto;padding:32px;border:1px solid #e2e8f0;border-radius:12px;">
      <h2 style="color:#00d4ff;margin-bottom:24px;">New Enquiry via Rapdfly Website</h2>
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:10px 0;color:#64748b;width:160px;">Name</td><td style="padding:10px 0;font-weight:600;">${name}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Email</td><td style="padding:10px 0;"><a href="mailto:${email}">${email}</a></td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Phone</td><td style="padding:10px 0;">${phone || 'Not provided'}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Company</td><td style="padding:10px 0;">${company || 'Not provided'}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Engagement Model</td><td style="padding:10px 0;">${engagementModel || 'Not specified'}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Service of Interest</td><td style="padding:10px 0;">${service || 'Not specified'}</td></tr>
      </table>
      <div style="margin-top:24px;padding:20px;background:#f8fafc;border-radius:8px;">
        <p style="color:#64748b;margin:0 0 8px;">Message</p>
        <p style="white-space:pre-wrap;color:#1e293b;margin:0;">${message}</p>
      </div>
      <p style="margin-top:24px;font-size:12px;color:#94a3b8;">Sent from rapdfly.com contact form</p>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"Rapdfly Website" <${process.env.ZOHO_EMAIL}>`,
      to: process.env.ZOHO_EMAIL,
      replyTo: email,
      subject: `New Enquiry from ${name} | ${service || 'General'}`,
      html,
    });
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('Mail error:', err.message);
    return res.status(500).json({ error: 'Failed to send email. Please try again.' });
  }
};
