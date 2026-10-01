const nodemailer = require('nodemailer');

const ALLOWED_ORIGINS = [
  'https://www.rapdfly.com',
  'https://rapdfly.com',
];

const RATE_LIMIT_MAX = 3;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const MIN_FILL_TIME_MS = 3000;

const FIELD_LIMITS = {
  name: 120,
  email: 160,
  company: 160,
  phone: 40,
  engagementModel: 80,
  service: 120,
  message: 5000,
};

const SPAM_PATTERNS = [
  /\b(seo|backlink|link ?building|guest post)\b.{0,40}\b(service|offer|package|rank)\b/i,
  /\b(casino|poker|betting|gambling)\b/i,
  /\b(viagra|cialis|pharmacy)\b/i,
  /\b(crypto|bitcoin|forex|binary option)\b.{0,40}\b(invest|profit|earn|double)\b/i,
  /\b(loan|credit)\b.{0,30}\b(approve|guarantee|bad credit)\b/i,
  /\b(work from home|make money fast|earn \$\d+)\b/i,
  /\b(telegram|whatsapp)\b.{0,20}(\+?\d{8,})/i,
];

const hits = new Map();

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.headers['x-real-ip'] || 'unknown';
}

function rateLimited(ip) {
  const now = Date.now();
  const log = (hits.get(ip) || []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (log.length >= RATE_LIMIT_MAX) {
    hits.set(ip, log);
    return true;
  }
  log.push(now);
  hits.set(ip, log);
  if (hits.size > 5000) {
    for (const [key, times] of hits) {
      if (!times.some((t) => now - t < RATE_LIMIT_WINDOW_MS)) hits.delete(key);
    }
  }
  return false;
}

function validEmail(email) {
  if (typeof email !== 'string') return false;
  if (email.length > FIELD_LIMITS.email) return false;
  if (/[\r\n]/.test(email)) return false;
  return /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(email);
}

function spamScore(payload) {
  const message = String(payload.message || '');
  const blob = [payload.name, payload.company, message].join(' ');
  let score = 0;

  const urls = message.match(/https?:\/\/|www\./gi) || [];
  if (urls.length >= 3) score += 2;
  else if (urls.length === 2) score += 1;

  if (/\[url=|\[link=|<a\s+href/i.test(message)) score += 3;

  for (const pattern of SPAM_PATTERNS) {
    if (pattern.test(blob)) score += 2;
  }

  const letters = message.replace(/[^A-Za-z]/g, '');
  if (letters.length > 25) {
    const caps = message.replace(/[^A-Z]/g, '').length;
    if (caps / letters.length > 0.6) score += 2;
  }

  if (message.trim().length < 15 && urls.length > 0) score += 2;

  return score;
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0]);
  }
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body = req.body || {};
  const { name, email, company, phone, engagementModel, service, message } = body;

  // Layer 1: honeypot. Bots fill hidden fields; humans never see them.
  // Respond with success so the bot has no signal to retry differently.
  if (typeof body.website === 'string' && body.website.trim() !== '') {
    console.warn('Blocked: honeypot filled from', clientIp(req));
    return res.status(200).json({ success: true });
  }

  // Layer 2: submission speed. Real people need time to type.
  const elapsed = Number(body.elapsed);
  if (!Number.isFinite(elapsed) || elapsed < MIN_FILL_TIME_MS) {
    console.warn('Blocked: submitted in', elapsed, 'ms from', clientIp(req));
    return res.status(200).json({ success: true });
  }

  // Layer 3: request must come from our own pages.
  const referer = req.headers.referer || '';
  const fromOurSite =
    (origin && ALLOWED_ORIGINS.includes(origin)) ||
    ALLOWED_ORIGINS.some((allowed) => referer.startsWith(allowed));
  if (!fromOurSite) {
    console.warn('Blocked: bad origin/referer', origin, referer);
    return res.status(403).json({ error: 'Request not allowed from this origin.' });
  }

  // Layer 4: per-IP rate limit.
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    console.warn('Blocked: rate limit for', ip);
    return res.status(429).json({ error: 'Too many messages. Please try again later.' });
  }

  // Layer 5: validation.
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, email and message are required.' });
  }
  if (!validEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  for (const [field, max] of Object.entries(FIELD_LIMITS)) {
    if (body[field] && String(body[field]).length > max) {
      return res.status(400).json({ error: 'One of the fields is too long.' });
    }
  }
  if (String(message).trim().length < 10) {
    return res.status(400).json({ error: 'Please tell us a little more about your enquiry.' });
  }
  if (/[\r\n]/.test(String(name))) {
    return res.status(400).json({ error: 'Please enter a valid name.' });
  }

  // Layer 6: content heuristics.
  const score = spamScore(body);
  if (score >= 4) {
    console.warn('Blocked: spam score', score, 'from', ip);
    return res.status(200).json({ success: true });
  }

  const transporter = nodemailer.createTransport({
    host: 'smtp.zoho.in',
    port: 465,
    secure: true,
    auth: {
      user: process.env.ZOHO_EMAIL,
      pass: process.env.ZOHO_PASSWORD,
    },
  });

  const safe = {
    name: escapeHtml(name),
    email: escapeHtml(email),
    phone: phone ? escapeHtml(phone) : 'Not provided',
    company: company ? escapeHtml(company) : 'Not provided',
    engagementModel: engagementModel ? escapeHtml(engagementModel) : 'Not specified',
    service: service ? escapeHtml(service) : 'Not specified',
    message: escapeHtml(message),
  };

  const flagged = score > 0 ? `<p style="margin:0 0 16px;padding:10px 14px;background:#fef3c7;border-radius:6px;color:#92400e;font-size:13px;">Possible spam (score ${score}) — review before replying.</p>` : '';

  const html = `
    <div style="font-family:sans-serif;max-width:620px;margin:auto;padding:32px;border:1px solid #e2e8f0;border-radius:12px;">
      <h2 style="color:#00d4ff;margin-bottom:24px;">New Enquiry via Rapdfly Website</h2>
      ${flagged}
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:10px 0;color:#64748b;width:160px;">Name</td><td style="padding:10px 0;font-weight:600;">${safe.name}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Email</td><td style="padding:10px 0;"><a href="mailto:${safe.email}">${safe.email}</a></td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Phone</td><td style="padding:10px 0;">${safe.phone}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Company</td><td style="padding:10px 0;">${safe.company}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Engagement Model</td><td style="padding:10px 0;">${safe.engagementModel}</td></tr>
        <tr><td style="padding:10px 0;color:#64748b;">Service of Interest</td><td style="padding:10px 0;">${safe.service}</td></tr>
      </table>
      <div style="margin-top:24px;padding:20px;background:#f8fafc;border-radius:8px;">
        <p style="color:#64748b;margin:0 0 8px;">Message</p>
        <p style="white-space:pre-wrap;color:#1e293b;margin:0;">${safe.message}</p>
      </div>
      <p style="margin-top:24px;font-size:12px;color:#94a3b8;">Sent from rapdfly.com contact form &middot; ${ip}</p>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"Rapdfly Website" <${process.env.ZOHO_EMAIL}>`,
      to: process.env.ZOHO_EMAIL,
      replyTo: email,
      subject: `New Enquiry from ${String(name).replace(/[\r\n]/g, ' ').slice(0, 80)} | ${String(service || 'General').slice(0, 60)}`,
      html,
    });
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('Mail error:', err.message);
    return res.status(500).json({ error: 'Failed to send email. Please try again.' });
  }
};
