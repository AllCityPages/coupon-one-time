// index.js (strict store matching + dropdown + protected CSV report)
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
const ENV_BASE_URL = process.env.BASE_URL || '';
const API_KEY = process.env.API_KEY || 'devkey'; // required for /api/redeem and CSV access
const TOKEN_EXPIRY_DAYS = parseInt(process.env.TOKEN_EXPIRY_DAYS || '90', 10);

const DATA_FILE = path.join(__dirname, 'passes.json');
const OFFERS_FILE = path.join(__dirname, 'offers.json');
const STORES_FILE = path.join(__dirname, 'stores.json');

// Ensure files exist
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ passes: [] }, null, 2), 'utf8');
if (!fs.existsSync(OFFERS_FILE)) fs.writeFileSync(OFFERS_FILE, JSON.stringify({ offers: [] }, null, 2), 'utf8');
if (!fs.existsSync(STORES_FILE)) fs.writeFileSync(STORES_FILE, JSON.stringify({ stores: {} }, null, 2), 'utf8');

function readData() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (e) { return { passes: [] }; }
}
function writeData(obj) { fs.writeFileSync(DATA_FILE, JSON.stringify(obj, null, 2), 'utf8'); }
function readOffers() {
  try { return JSON.parse(fs.readFileSync(OFFERS_FILE, 'utf8')).offers || []; }
  catch (e) { return []; }
}
function readStores() {
  try { return JSON.parse(fs.readFileSync(STORES_FILE, 'utf8')).stores || {}; }
  catch (e) { return {}; }
}

function sha256hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}
function createToken() {
  return crypto.randomBytes(12).toString('base64url');
}

function deriveHost(req) {
  if (ENV_BASE_URL && ENV_BASE_URL.trim() !== '') return ENV_BASE_URL.replace(/\/$/, '');
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}`;
}

// Helper: find offer by id
function getOfferById(id) {
  if (!id) return null;
  const offers = readOffers();
  return offers.find(o => o.id === id) || null;
}

// Helper: check store mapping
function checkStoreForOffer(store_id, offer) {
  if (!store_id) return { ok: false, reason: 'missing_store_id' };
  const stores = readStores();
  const mappedRestaurant = stores[store_id];
  if (!mappedRestaurant) return { ok: false, reason: 'unknown_store' };
  if (mappedRestaurant.trim().toLowerCase() !== (offer.restaurant || '').trim().toLowerCase()) {
    return { ok: false, reason: 'mismatch', mappedRestaurant };
  }
  return { ok: true, restaurant: mappedRestaurant };
}

// ------------------ Coupon issuance ------------------
app.get('/coupon', (req, res) => {
  const offerId = req.query.offer;
  const offers = readOffers();

  if (!offerId) {
    // show list of offers and preview links
    const listHtml = offers.map(o => {
      const link = `/coupon?offer=${encodeURIComponent(o.id)}`;
      return `<li style="margin-bottom:18px"><strong>${o.restaurant} — ${o.title}</strong><br>${o.description}<br><a href="${link}">Preview this offer</a></li>`;
    }).join('');
    return res.send(`
      <!doctype html><html><head><meta charset="utf-8"><title>Offers</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="font-family:Arial;max-width:760px;margin:auto;padding:20px">
        <h1>Available Offers</h1>
        <p>For printed mail, encode a link with the offer parameter: <code>/coupon?offer=offer-id</code></p>
        <ul style="list-style:none;padding-left:0">${listHtml}</ul>
      </body></html>
    `);
  }

  const offer = getOfferById(offerId);
  if (!offer) return res.status(404).send('Offer not found');

  // Validity window check
  const now = Math.floor(Date.now()/1000);
  const start = offer.valid_from ? Math.floor(new Date(offer.valid_from).getTime()/1000) : 0;
  const end = offer.valid_until ? Math.floor(new Date(offer.valid_until).getTime()/1000) : now + TOKEN_EXPIRY_DAYS*24*60*60;
  if (now < start || now > end) {
    return res.send(`<p>This offer is not currently valid.</p><p><a href="/coupon">Back</a></p>`);
  }

  // create token (we store only hash)
  const token = createToken();
  const tokenHash = sha256hex(token);
  const id = uuidv4();
  const expiresAt = now + TOKEN_EXPIRY_DAYS * 24 * 60 * 60;

  const data = readData();
  data.passes.push({
    id,
    token_hash: tokenHash,
    status: 'issued',
    issued_at: now,
    expires_at: expiresAt,
    redeemed_at: null,
    redeemed_by: null,
    offer_id: offer.id,
    restaurant: offer.restaurant
  });
  writeData(data);

  res.send(`
    <!doctype html><html><head><meta charset="utf-8"><title>${offer.title}</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{font-family:Arial;padding:20px;max-width:600px;margin:auto;text-align:center}.code{font-family:monospace;font-size:20px;margin-top:10px}.small{color:#666}</style>
    </head><body>
      <h1>${offer.title}</h1>
      <p><em>${offer.restaurant}</em></p>
      <p>${offer.description}</p>
      <img src="/api/qrcode/${encodeURIComponent(token)}" style="max-width:260px" alt="QR code">
      <div class="code">Code (hashed in DB): ${tokenHash}</div>
      <p class="small">Expires: ${new Date(expiresAt*1000).toLocaleDateString()}</p>
    </body></html>
  `);
});

// ------------------ QR image endpoint ------------------
app.get('/api/qrcode/:token', async (req, res) => {
  const rawToken = req.params.token;
  if (!rawToken) return res.status(400).send('token required');
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

// ------------------ Redeem endpoint (POS) ------------------
app.post('/api/redeem', (req, res) => {
  const key = req.header('x-api-key');
  if (key !== API_KEY) return res.status(401).json({ ok:false, error: 'unauthorized' });

  const { token, store_id, staff_id } = req.body || {};
  if (!token) return res.status(400).json({ ok:false, error: 'token required' });

  const tokenHash = sha256hex(token);
  const now = Math.floor(Date.now()/1000);
  const data = readData();
  const idx = data.passes.findIndex(p => p.token_hash === tokenHash);
  if (idx === -1) return res.status(400).json({ ok:false, reason:'invalid' });

  const row = data.passes[idx];

  // Check offer validity
  const offer = getOfferById(row.offer_id);
  if (!offer) return res.status(400).json({ ok:false, reason:'offer_not_found' });
  const start = offer.valid_from ? Math.floor(new Date(offer.valid_from).getTime()/1000) : 0;
  const end = offer.valid_until ? Math.floor(new Date(offer.valid_until).getTime()/1000) : now + TOKEN_EXPIRY_DAYS*24*60*60;
  if (now < start || now > end) return res.status(400).json({ ok:false, reason:'offer_expired' });

  if (row.status !== 'issued') return res.status(400).json({ ok:false, reason:'already_used' });
  if (row.expires_at < now) return res.status(400).json({ ok:false, reason:'expired' });

  // Strict store check
  const storeCheck = checkStoreForOffer(store_id, offer);
  if (!storeCheck.ok) {
    if (storeCheck.reason === 'missing_store_id') return res.status(400).json({ ok:false, reason:'missing_store_id', message:'Please provide Store ID.' });
    if (storeCheck.reason === 'unknown_store') return res.status(400).json({ ok:false, reason:'unknown_store', message:'Store ID not recognized.' });
    if (storeCheck.reason === 'mismatch') return res.status(400).json({ ok:false, reason:'mismatch', message:`This coupon is for ${offer.restaurant}. The store code provided belongs to ${storeCheck.mappedRestaurant}.` });
  }

  // mark redeemed
  data.passes[idx].status = 'redeemed';
  data.passes[idx].redeemed_at = now;
  data.passes[idx].redeemed_by = store_id || staff_id || 'unknown';
  writeData(data);

  return res.json({ ok:true, message: 'Redeemed', offer: { id: offer.id, title: offer.title, restaurant: offer.restaurant } });
});

// ------------------ Validate page (staff) with dropdown ------------------
app.get('/validate', (req, res) => {
  const token = req.query.token || '';
  const data = readData();
  const tokenHash = token ? sha256hex(token) : null;
  const row = tokenHash ? data.passes.find(p => p.token_hash === tokenHash) : null;
  const offer = row ? getOfferById(row.offer_id) : null;
  const qrImg = token ? `<img src="/api/qrcode/${encodeURIComponent(token)}" style="max-width:220px; display:block; margin:12px auto;">` : '<p style="color:#666">No token provided</p>';

  // allowed store codes for this offer
  const stores = readStores();
  let allowedListHtml = '<p style="color:#666">No store codes available</p>';
  let selectHtml = '<input name="store_id" placeholder="Enter store code">'; // fallback simple input
  if (offer) {
    const allowed = Object.keys(stores).filter(k => stores[k].trim().toLowerCase() === offer.restaurant.trim().toLowerCase());
    if (allowed.length) {
      allowedListHtml = `<p style="font-size:13px;color:#333">Allowed store codes for this offer: <strong>${allowed.join(', ')}</strong></p>`;
      // build select dropdown
      const options = allowed.map(s => `<option value="${s}">${s}</option>`).join('');
      selectHtml = `<select name="store_id">${options}</select>`;
    }
  }

  res.send(`
    <!doctype html><html><head><meta charset="utf-8"><title>Validate Coupon</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{font-family:Arial;padding:20px;max-width:520px;margin:auto}label{display:block;margin-top:8px}.code{font-family:monospace;font-size:18px;margin-top:8px}button{margin-top:12px;padding:8px 12px;border-radius:6px;background:#0070c9;color:#fff;border:none}</style>
    </head><body>
      <h2>Validate Coupon</h2>
      ${qrImg}
      <p class="code">Token: <b>${token}</b></p>
      ${offer ? `<p><strong>${offer.title}</strong><br><em>${offer.restaurant}</em><br>${offer.description}</p>` : '<p style="color:#666">No offer info</p>'}
      ${allowedListHtml}
      <form method="post" action="/redeem-via-web">
        <input type="hidden" name="token" value="${token}">
        <label>Store ID: ${selectHtml}</label>
        <label>Staff ID: <input name="staff_id"></label>
        <button type="submit">Redeem</button>
      </form>
      <p style="color:#666;margin-top:12px">Or use the POS to POST /api/redeem with header x-api-key.</p>
    </body></html>
  `);
});

// ------------------ Redeem helper for the web form ------------------
app.post('/redeem-via-web', (req, res) => {
  const { token, store_id, staff_id } = req.body;
  try {
    if (!token) return res.send('<p>Token missing. <a href="/coupon">Back</a></p>');
    const tokenHash = sha256hex(token);
    const data = readData();
    const idx = data.passes.findIndex(p => p.token_hash === tokenHash);
    const now = Math.floor(Date.now()/1000);
    if (idx === -1) return res.send('<p>Invalid token. <a href="/coupon">Back</a></p>');
    const row = data.passes[idx];
    const offer = getOfferById(row.offer_id);
    if (!offer) return res.send('<p>Offer not found. <a href="/coupon">Back</a></p>');

    const start = offer.valid_from ? Math.floor(new Date(offer.valid_from).getTime()/1000) : 0;
    const end = offer.valid_until ? Math.floor(new Date(offer.valid_until).getTime()/1000) : now + TOKEN_EXPIRY_DAYS*24*60*60;
    if (now < start || now > end) return res.send('<p>Offer expired. <a href="/coupon">Back</a></p>');
    if (row.status !== 'issued') return res.send('<p>Already used. <a href="/coupon">Back</a></p>');

    // strict store check
    const storeCheck = checkStoreForOffer(store_id, offer);
    if (!storeCheck.ok) {
      if (storeCheck.reason === 'missing_store_id') return res.send('<p>Please provide Store ID. Ask the manager for the store code. <a href="/coupon">Back</a></p>');
      if (storeCheck.reason === 'unknown_store') return res.send('<p>Store code not recognized. Ask manager for the correct store code. <a href="/coupon">Back</a></p>');
      if (storeCheck.reason === 'mismatch') return res.send(`<p>This coupon is for ${offer.restaurant}. The store code you entered belongs to ${storeCheck.mappedRestaurant}. <a href="/coupon">Back</a></p>`);
    }

    data.passes[idx].status = 'redeemed';
    data.passes[idx].redeemed_at = now;
    data.passes[idx].redeemed_by = store_id || staff_id || 'unknown';
    writeData(data);
    return res.send('<p>Redeemed. <a href="/coupon">Back</a></p>');
  } catch (err) {
    console.error(err);
    return res.send('<p>Error redeeming. <a href="/coupon">Back</a></p>');
  }
});

// ------------------ REPORT: UI page with one-click download ------------------
// GET /report -> shows a small admin form that allows selection of offer and a place to enter API key
app.get('/report', (req, res) => {
  const offers = readOffers();
  const options = offers.map(o => `<option value="${o.id}">${o.restaurant} — ${o.title}</option>`).join('');
  // Simple page: choose offer or "all", enter API key, click Download CSV
  res.send(`
    <!doctype html><html><head><meta charset="utf-8"><title>Download Redemption Report</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{font-family:Arial;padding:20px;max-width:720px;margin:auto}label{display:block;margin-top:12px}button{margin-top:12px;padding:8px 12px;border-radius:6px;background:#0070c9;color:#fff;border:none}</style>
    </head><body>
      <h2>Download Redemption Report</h2>
      <p>Choose an offer (or leave blank for all offers). Enter the API key below (same x-api-key used by POS) and click "Download CSV".</p>
      <form id="reportForm" method="post" action="/report.csv">
        <label>Offer:
          <select name="offer">
            <option value="">-- All offers --</option>
            ${options}
          </select>
        </label>
        <label>API Key: <input type="password" name="api_key" placeholder="Enter API key (required)"></label>
        <button type="submit">Download CSV</button>
      </form>
      <p style="color:#666;margin-top:12px">Note: The CSV file will contain token_hash (not raw token), offer info, issued/redeemed dates, store codes and status.</p>
    </body></html>
  `);
});

// Helper to escape CSV fields
function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (s.indexOf('"') !== -1 || s.indexOf(',') !== -1 || s.indexOf('\n') !== -1) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

// POST /report.csv -> returns CSV (protected by API key)
// Accepts API via header x-api-key OR form body api_key (for browser form)
// Optional form field "offer" to filter by offer id
app.post('/report.csv', (req, res) => {
  const headerKey = req.header('x-api-key');
  const bodyKey = req.body && req.body.api_key;
  const usedKey = headerKey || bodyKey;
  if (!usedKey || usedKey !== API_KEY) {
    return res.status(401).send('Unauthorized: provide valid API key (x-api-key header or api_key form field).');
  }

  const offerFilter = req.body && req.body.offer ? String(req.body.offer).trim() : '';
  const data = readData();
  const offers = readOffers();

  // Build CSV header
  const headers = ['token_hash','offer_id','offer_title','restaurant','issued_at','redeemed_at','redeemed_by','status'];
  const rows = [headers.map(csvEscape).join(',')];

  // Filter records
  const recs = data.passes.filter(p => {
    if (!offerFilter) return true;
    return p.offer_id === offerFilter;
  });

  // sort by issued_at ascending
  recs.sort((a,b) => (a.issued_at || 0) - (b.issued_at || 0));

  recs.forEach(r => {
    const offer = offers.find(o => o.id === r.offer_id) || {};
    const issuedAt = r.issued_at ? new Date(r.issued_at * 1000).toISOString() : '';
    const redeemedAt = r.redeemed_at ? new Date(r.redeemed_at * 1000).toISOString() : '';
    const row = [
      r.token_hash || '',
      r.offer_id || '',
      offer.title || '',
      r.restaurant || '',
      issuedAt,
      redeemedAt,
      r.redeemed_by || '',
      r.status || ''
    ];
    rows.push(row.map(csvEscape).join(','));
  });

  const csv = rows.join('\r\n');
  const fname = `report-${offerFilter || 'all'}-${new Date().toISOString().slice(0,10)}.csv`;
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
  res.send(csv);
});

// Fallback root
app.get('/', (req, res) => {
  res.send('<p>Coupon app. Visit <a href="/coupon">/coupon</a> or the admin report at <a href="/report">/report</a>.</p>');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
