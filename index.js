// Corrected coupon app (derives host for QR so image won't break)
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const QRCode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const ENV_BASE_URL = process.env.BASE_URL || ''; // optional env override
const API_KEY = process.env.API_KEY || 'devkey';
const TOKEN_EXPIRY_DAYS = parseInt(process.env.TOKEN_EXPIRY_DAYS || '90', 10);

const DATA_FILE = path.join(__dirname, 'passes.json');

// Ensure data file exists
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ passes: [] }, null, 2), 'utf8');

function readData() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return { passes: [] };
  }
}
function writeData(obj) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(obj, null, 2), 'utf8');
}

function sha256hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}
function createToken() {
  return crypto.randomBytes(12).toString('base64url'); // short readable token
}

function deriveHost(req) {
  // Use explicit env BASE_URL if set, otherwise derive from incoming request
  if (ENV_BASE_URL && ENV_BASE_URL.trim() !== '') return ENV_BASE_URL.replace(/\/$/, '');
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}`;
}

// Landing page - issues a token and shows QR + code
app.get('/coupon', (req, res) => {
  const token = createToken();
  const tokenHash = sha256hex(token);
  const id = uuidv4();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + TOKEN_EXPIRY_DAYS * 24 * 60 * 60;

  const data = readData();
  data.passes.push({
    id,
    token_hash: tokenHash,
    status: 'issued',
    issued_at: now,
    expires_at: expiresAt,
    redeemed_at: null,
    redeemed_by: null
  });
  writeData(data);

  // NOTE: the QR image itself is served from /api/qrcode/:token,
  // so we just reference that relative path here (works over HTTPS).
  res.send(`
    <!doctype html><html><head><meta charset="utf-8"><title>Save Coupon</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body { font-family: Arial, sans-serif; padding: 24px; max-width:520px; margin:auto; text-align:center; }
      .btn { background:#0070c9;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none;display:inline-block;margin-top:12px;}
      .code { font-family: monospace; font-size: 20px; margin-top:12px; }
      .small { font-size: 12px; color: #666; margin-top: 10px; }
    </style>
    </head><body>
      <h1>Save your one-time coupon</h1>
      <p class="small">Show this to the cashier to redeem. One redemption per coupon.</p>
      <img src="/api/qrcode/${encodeURIComponent(token)}" style="max-width:260px" alt="QR code">
      <div class="code">Code: ${token}</div>
      <p class="small">Expires: ${new Date(expiresAt*1000).toLocaleDateString()}</p>
      <p class="small">If the QR doesn't work, show the code above to staff.</p>
    </body></html>
  `);
});

// QR generator for the token (PNG) - uses deriveHost so QR encodes correct validation URL
app.get('/api/qrcode/:token', async (req, res) => {
  const rawToken = req.params.token;
  if (!rawToken) return res.status(400).send('token required');

  // Build the validation URL including the correct host (derives from request if needed)
  try {
    const host = deriveHost(req);
    const redeemUrl = `${host}/validate?token=${encodeURIComponent(rawToken)}`;

    res.setHeader('Content-Type', 'image/png');
    const png = await QRCode.toBuffer(redeemUrl, { type: 'png', width: 512, margin: 1 });
    res.send(png);
  } catch (err) {
    console.error('QR error', err && err.stack ? err.stack : err);
    res.status(500).send('QR generation failed');
  }
});

// POST /api/redeem -> used by POS (requires API key header x-api-key)
app.post('/api/redeem', (req, res) => {
  const key = req.header('x-api-key');
  if (key !== API_KEY) return res.status(401).json({ ok:false, error: 'unauthorized' });

  const { token, store_id, staff_id } = req.body || {};
  if (!token) return res.status(400).json({ ok:false, error: 'token required' });

  const tokenHash = sha256hex(token);
  const now = Math.floor(Date.now() / 1000);
  const data = readData();
  const idx = data.passes.findIndex(p => p.token_hash === tokenHash);
  if (idx === -1) return res.status(400).json({ ok:false, reason:'invalid' });

  const row = data.passes[idx];
  if (row.status !== 'issued') return res.status(400).json({ ok:false, reason:'already_used' });
  if (row.expires_at < now) return res.status(400).json({ ok:false, reason:'expired' });

  // mark redeemed
  data.passes[idx].status = 'redeemed';
  data.passes[idx].redeemed_at = now;
  data.passes[idx].redeemed_by = store_id || staff_id || 'unknown';
  writeData(data);
  return res.json({ ok:true, message: 'Redeemed' });
});

// Convenience web validate page (staff can redeem via form) and shows QR too
app.get('/validate', (req, res) => {
  const token = req.query.token || '';
  const qrImg = token ? `<img src="/api/qrcode/${encodeURIComponent(token)}" style="max-width:220px; display:block; margin:12px auto;">` : '<p style="color:#666">No token provided</p>';
  res.send(`
    <!doctype html><html><head><meta charset="utf-8"><title>Validate Coupon</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{font-family:Arial,Helvetica,sans-serif;padding:20px;max-width:520px;margin:auto}
      label{display:block;margin-top:8px}
      .code{font-family:monospace;font-size:18px;margin-top:8px}
      button{margin-top:12px;padding:8px 12px;border-radius:6px;background:#0070c9;color:#fff;border:none}
    </style>
    </head><body>
      <h2>Validate Coupon</h2>
      ${qrImg}
      <p class="code">Token: <b>${token}</b></p>
      <form method="post" action="/redeem-via-web">
        <input type="hidden" name="token" value="${token}">
        <label>Store ID: <input name="store_id"></label>
        <label>Staff ID: <input name="staff_id"></label>
        <button type="submit">Redeem</button>
      </form>
      <p style="color:#666;margin-top:12px">Or use the POS to POST /api/redeem with header x-api-key.</p>
    </body></html>
  `);
});

// Helper endpoint for the form (no API key needed; convenience)
app.post('/redeem-via-web', (req, res) => {
  const { token, store_id, staff_id } = req.body;
  const tokenHash = sha256hex(token);
  const data = readData();
  const idx = data.passes.findIndex(p => p.token_hash === tokenHash);
  const now = Math.floor(Date.now()/1000);
  if (idx === -1) return res.send('<p>Invalid token. <a href="/coupon">Back</a></p>');
  const row = data.passes[idx];
  if (row.status !== 'issued') return res.send('<p>Already used. <a href="/coupon">Back</a></p>');
  if (row.expires_at < now) return res.send('<p>Expired. <a href="/coupon">Back</a></p>');
  data.passes[idx].status = 'redeemed';
  data.passes[idx].redeemed_at = now;
  data.passes[idx].redeemed_by = store_id || staff_id || 'unknown';
  writeData(data);
  return res.send('<p>Redeemed. <a href="/coupon">Back</a></p>');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
