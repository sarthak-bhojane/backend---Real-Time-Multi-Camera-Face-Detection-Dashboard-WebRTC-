// server.js
// Backend: Express + Postgres + JWT + WebSocket + FFmpeg HLS per-camera + simulated alert worker
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const multer = require('multer');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const upload = multer();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || JWT_SECRET;

// Postgres pool - adjust credentials if needed (no .env)
// const pool = new Pool({
//   user: process.env.PGUSER || 'postgres',
//   host: process.env.PGHOST || 'localhost',
//   database: process.env.PGDATABASE || 'webrtc_dashboard',
//   password: process.env.PGPASSWORD || 'Sarthak@2002',
//   port: Number(process.env.PGPORT || 5432),
// });


const pool = new Pool({
  user: "postgres",
  host: process.env.RAILWAY_TCP_PROXY_DOMAIN || "switchback.proxy.rlwy.net",
  database: "railway",
  password: "zlzDsSaoDjxCZDKViaCHmepaokvEPuMS",
  port: process.env.RAILWAY_TCP_PROXY_PORT || 53992, // Replace with your actual proxy port
  ssl: {
    rejectUnauthorized: false,
  },
});


// create streams folder for HLS outputs
const STREAMS_DIR = path.join(__dirname, 'streams');
if (!fs.existsSync(STREAMS_DIR)) fs.mkdirSync(STREAMS_DIR, { recursive: true });

// Ensure DB tables
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS cameras (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      rtsp_url TEXT,
      location TEXT,
      status TEXT,
      enabled BOOLEAN DEFAULT TRUE,
      processing BOOLEAN DEFAULT FALSE,
      fps INTEGER DEFAULT 5,
      detection_enabled BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id SERIAL PRIMARY KEY,
      camera_id INTEGER REFERENCES cameras(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      detected_at TIMESTAMP DEFAULT NOW(),
      bbox JSONB,
      metadata JSONB,
      snapshot BYTEA,
      snapshot_mime TEXT
    );
  `);
  console.log('DB tables ready');
}
ensureTables().catch(err => { console.error('Failed to ensure tables', err); process.exit(1); });

const app = express();
app.use(cors());
app.use(express.json({ limit: '30mb' }));

// Auth middleware
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = h.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization format' });
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- AUTH endpoints ---
app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query('INSERT INTO users (username, password_hash) VALUES ($1,$2) RETURNING id, username, created_at', [username, hash]);
    const user = r.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'username already exists' });
    console.error('register err', err);
    res.status(500).json({ error: 'internal' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const r = await pool.query('SELECT id, username, password_hash FROM users WHERE username=$1', [username]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username }});
  } catch (err) {
    console.error('login err', err);
    res.status(500).json({ error: 'internal' });
  }
});

// --- Cameras CRUD ---
app.post('/api/cameras', authMiddleware, async (req, res) => {
  const { name, rtsp_url, location, fps, detection_enabled } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    const r = await pool.query(
      `INSERT INTO cameras (user_id, name, rtsp_url, location, fps, detection_enabled) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.user.id, name, rtsp_url || '', location || '', fps || 5, detection_enabled !== undefined ? detection_enabled : true]
    );
    res.json({ camera: r.rows[0] });
  } catch (err) {
    console.error('create camera err', err);
    res.status(500).json({ error: 'internal' });
  }
});

app.get('/api/cameras', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM cameras WHERE user_id=$1 ORDER BY id DESC', [req.user.id]);
    res.json({ cameras: r.rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

app.put('/api/cameras/:id', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  const allowed = ['name','rtsp_url','location','enabled','fps','detection_enabled'];
  const sets = [];
  const vals = [];
  let idx = 1;
  for (const k of allowed) {
    if (req.body[k] !== undefined) {
      sets.push(`${k}=$${idx++}`);
      vals.push(req.body[k]);
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'no fields to update' });
  vals.push(id); vals.push(req.user.id);
  const sql = `UPDATE cameras SET ${sets.join(', ')} WHERE id=$${idx++} AND user_id=$${idx} RETURNING *`;
  try {
    const r = await pool.query(sql, vals);
    if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
    res.json({ camera: r.rows[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

app.delete('/api/cameras/:id', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const r = await pool.query('DELETE FROM cameras WHERE id=$1 AND user_id=$2 RETURNING *', [id, req.user.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
    // stop any running processes
    stopFFmpeg(id);
    stopWorker(id);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

// --- Alerts endpoints ---
app.get('/api/alerts', authMiddleware, async (req, res) => {
  const camera_id = req.query.camera_id ? Number(req.query.camera_id) : null;
  const limit = Math.min(200, Number(req.query.limit || 50));
  const offset = Number(req.query.offset || 0);
  try {
    const vals = [req.user.id];
    let sql = `SELECT id, camera_id, detected_at, bbox, metadata, snapshot IS NOT NULL AS has_snapshot FROM alerts WHERE user_id=$1`;
    if (camera_id) { vals.push(camera_id); sql += ` AND camera_id = $${vals.length}`; }
    vals.push(limit); vals.push(offset);
    sql += ` ORDER BY detected_at DESC LIMIT $${vals.length-1} OFFSET $${vals.length}`;
    const r = await pool.query(sql, vals);
    res.json({ alerts: r.rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

app.get('/api/alerts/:id/snapshot', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const r = await pool.query('SELECT snapshot, snapshot_mime, user_id FROM alerts WHERE id=$1', [id]);
    const row = r.rows[0];
    if (!row) return res.status(404).json({ error: 'not found' });
    if (row.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
    if (!row.snapshot) return res.status(404).json({ error: 'no snapshot' });
    res.setHeader('Content-Type', row.snapshot_mime || 'image/png');
    res.send(row.snapshot);
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

// --- Internal ingestion endpoint (for external worker) ---
app.post('/api/internal/alerts', upload.none(), async (req, res) => {
  const secret = req.headers['x-internal-secret'];
  if (!secret || secret !== INTERNAL_SECRET) return res.status(403).json({ error: 'forbidden' });
  try {
    const camera_id = Number(req.body.camera_id);
    const user_id = Number(req.body.user_id);
    const bbox = req.body.bbox ? JSON.parse(req.body.bbox) : null;
    const metadata = req.body.metadata ? JSON.parse(req.body.metadata) : null;
    let snapshot = null;
    if (req.body.snapshot_base64) snapshot = Buffer.from(req.body.snapshot_base64, 'base64');
    const snapshot_mime = req.body.snapshot_mime || null;
    const r = await pool.query(
      `INSERT INTO alerts (camera_id, user_id, bbox, metadata, snapshot, snapshot_mime) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, detected_at`,
      [camera_id, user_id, bbox, metadata, snapshot, snapshot_mime]
    );
    const inserted = r.rows[0];
    const alert = { id: inserted.id, camera_id, user_id, detected_at: inserted.detected_at, bbox, metadata, has_snapshot: !!snapshot };
    broadcastAlert(alert);
    res.json({ ok: true, alert });
  } catch (err) {
    console.error('internal alert err', err);
    res.status(500).json({ error: 'internal' });
  }
});

// --- WebSocket server ---
const server = app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: '/ws' });
const wsClients = new Map();

wss.on('connection', (ws, req) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    if (!token) { ws.send(JSON.stringify({ type: 'error', message: 'missing token' })); ws.close(); return; }
    const payload = jwt.verify(token, JWT_SECRET);
    wsClients.set(ws, { userId: payload.id, username: payload.username });
    ws.send(JSON.stringify({ type: 'hello', now: new Date().toISOString() }));
    ws.on('close', () => wsClients.delete(ws));
  } catch (e) {
    try { ws.send(JSON.stringify({ type: 'error', message: 'invalid token' })); } catch(e){}
    ws.close();
  }
});

function broadcast(msg, userId = null) {
  for (const [ws, meta] of wsClients.entries()) {
    if (!userId || meta.userId === userId) {
      try { ws.send(JSON.stringify(msg)); } catch (e) {}
    }
  }
}
function broadcastAlert(alert) { broadcast({ type: 'alert', alert }, alert.user_id); }

// Serve HLS streams statically under /streams with proper mime types for .m3u8 and .ts
app.use('/streams', (req, res, next) => {
  const ext = path.extname(req.url).toLowerCase();
  if (ext === '.m3u8') res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
  else if (ext === '.ts') res.setHeader('Content-Type', 'video/MP2T');
  next();
}, express.static(STREAMS_DIR));

// ---------------- FFmpeg HLS management ----------------
const ffmpegProcesses = new Map(); // cameraId -> { proc, dir, restartCount }

function startFFmpeg(cameraId, rtspUrl) {
  if (!rtspUrl) return;
  if (ffmpegProcesses.has(cameraId)) {
    const info = ffmpegProcesses.get(cameraId);
    if (info && info.proc && !info.proc.killed) return; // already running
  }
  const outDir = path.join(STREAMS_DIR, `cam_${cameraId}`);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  // remove old files (but leave directory)
  try {
    fs.readdirSync(outDir).forEach(f => {
      try { fs.unlinkSync(path.join(outDir, f)); } catch (e) {}
    });
  } catch (e) {}

  const playlist = path.join(outDir, 'index.m3u8');
  const segmentPattern = path.join(outDir, 'segment_%03d.ts');

  // use libx264 to maximize browser compatibility (Firefox + Chrome)
  const args = [
    '-rtsp_transport', 'tcp',
    '-i', rtspUrl,
    '-c:v', 'libx264',
    '-preset', 'ultrafast',
    '-tune', 'zerolatency',
    '-c:a', 'aac',
    '-ac', '1',
    '-ar', '44100',
    '-f', 'hls',
    '-hls_time', '2',
    '-hls_list_size', '5',
    '-hls_flags', 'delete_segments+append_list',
    '-hls_allow_cache', '0',
    '-fflags', '+genpts',
    '-hls_segment_filename', segmentPattern,
    playlist
  ];

  console.log(`Starting ffmpeg for camera ${cameraId}: ffmpeg ${args.join(' ')}`);

  const proc = spawn('ffmpeg', args, { stdio: ['ignore', 'pipe', 'pipe'] });

  proc.stdout && proc.stdout.on('data', d => {
    // optional: console.log(`[ffmpeg ${cameraId} stdout] ${d.toString().trim()}`);
  });
  proc.stderr && proc.stderr.on('data', d => {
    const text = d.toString();
    // show only relevant lines (reduce noise)
    if (text.match(/frame=|error|Stream mapping|Opening|Failed|Invalid data|Immediate exit requested/i)) {
      console.log(`ffmpeg[${cameraId}] ${text.split('\n').slice(0,3).join(' | ')}`);
    }
  });

  proc.on('exit', (code, sig) => {
    console.log(`ffmpeg for camera ${cameraId} exited (${code}, ${sig})`);
    const info = ffmpegProcesses.get(cameraId) || {};
    ffmpegProcesses.delete(cameraId);
    // notify clients camera stream stopped
    broadcast({ type: 'cam_error', camera_id: cameraId, error: 'ffmpeg stopped' });

    // auto-retry unless explicitly killed (SIGKILL means user stopped)
    if (sig !== 'SIGKILL') {
      const restartCount = (info.restartCount || 0) + 1;
      if (restartCount <= 5) {
        console.log(`Retrying ffmpeg for camera ${cameraId} in 2s (count ${restartCount})`);
        setTimeout(() => startFFmpeg(cameraId, rtspUrl), 2000);
      } else {
        console.warn(`ffmpeg for camera ${cameraId} failed repeatedly, giving up`);
      }
    }
  });

  ffmpegProcesses.set(cameraId, { proc, dir: outDir, restartCount: 0 });
}

function stopFFmpeg(cameraId) {
  if (!ffmpegProcesses.has(cameraId)) return;
  const info = ffmpegProcesses.get(cameraId);
  try {
    if (info.proc && !info.proc.killed) {
      // SIGKILL ensures process stops (on windows, kill() works)
      info.proc.kill('SIGKILL');
    }
  } catch (e) { /* ignore */ }
  ffmpegProcesses.delete(cameraId);
}

// ---------------- Simulated Worker (keeps alert features alive) ----------------
const simulatedWorkers = new Map();
const tinyPNGBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAASsJTYQAAAAASUVORK5CYII=';

class SimulatedWorker {
  constructor(camera) {
    this.camera = camera;
    this.running = false;
    this.intervalId = null;
    this.currentFps = camera.fps || 5;
    this.detectionEnabled = camera.detection_enabled !== false;
  }
  async start() {
    if (this.running) return;
    this.running = true;
    console.log(`SimulatedWorker started for camera ${this.camera.id}`);
    this.loop();
  }
  stop() {
    this.running = false;
    if (this.intervalId) clearTimeout(this.intervalId);
    this.intervalId = null;
    console.log(`SimulatedWorker stopped for camera ${this.camera.id}`);
  }
  loop() {
    if (!this.running) return;
    const ms = Math.max(200, Math.round(1000 / Math.max(1, this.currentFps)));
    this.intervalId = setTimeout(async () => {
      if (this.detectionEnabled && Math.random() < 0.25) {
        const bbox = { x: Math.random()*0.7, y: Math.random()*0.7, w: 0.1 + Math.random()*0.3, h: 0.1 + Math.random()*0.3 };
        const metadata = { confidence: 0.6 + Math.random()*0.4, type: 'face' };
        const snapshot = Buffer.from(tinyPNGBase64, 'base64');
        try {
          const r = await pool.query(
            `INSERT INTO alerts (camera_id, user_id, bbox, metadata, snapshot, snapshot_mime) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, detected_at`,
            [this.camera.id, this.camera.user_id, bbox, metadata, snapshot, 'image/png']
          );
          const ins = r.rows[0];
          const alert = { id: ins.id, camera_id: this.camera.id, user_id: this.camera.user_id, detected_at: ins.detected_at, bbox, metadata, has_snapshot: true };
          broadcastAlert(alert);
        } catch (err) {
          console.error('SimWorker DB insert err', err);
        }
      }
      this.loop();
    }, ms);
  }
}

// worker control
async function startWorker(cameraId, userId) {
  if (simulatedWorkers.has(cameraId)) {
    const w = simulatedWorkers.get(cameraId);
    if (!w.running) await w.start();
    return;
  }
  // load camera details (fps, detection_enabled)
  const r = await pool.query('SELECT * FROM cameras WHERE id=$1', [cameraId]);
  if (!r.rows[0]) return;
  const camera = { ...r.rows[0] };
  const w = new SimulatedWorker(camera);
  simulatedWorkers.set(cameraId, w);
  w.start();
}

function stopWorker(cameraId) {
  if (!simulatedWorkers.has(cameraId)) return;
  const w = simulatedWorkers.get(cameraId);
  w.stop();
  simulatedWorkers.delete(cameraId);
}

// On server start, resume cameras marked as processing=true
(async () => {
  try {
    const r = await pool.query('SELECT id, user_id, rtsp_url FROM cameras WHERE processing = true');
    for (const cam of r.rows) {
      if (cam.rtsp_url) startFFmpeg(cam.id, cam.rtsp_url);
      startWorker(cam.id, cam.user_id);
    }
  } catch (e) { console.error('resume processing err', e); }
})();

// --- Start / Stop camera processing endpoints (update DB + start ffmpeg/worker) ---
app.post('/api/cameras/:id/start', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const r = await pool.query('UPDATE cameras SET processing=true WHERE id=$1 AND user_id=$2 RETURNING *', [id, req.user.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
    const cam = r.rows[0];
    if (cam.rtsp_url) startFFmpeg(cam.id, cam.rtsp_url);
    startWorker(cam.id, cam.user_id);
    res.json({ camera: cam });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

app.post('/api/cameras/:id/stop', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const r = await pool.query('UPDATE cameras SET processing=false WHERE id=$1 AND user_id=$2 RETURNING *', [id, req.user.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
    stopFFmpeg(id);
    stopWorker(id);
    res.json({ camera: r.rows[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

// Debug endpoint
app.get('/internal/workers', async (req,res) => {
  const list = [];
  for (const [id, w] of simulatedWorkers.entries()) list.push({ cameraId: id, running: w.running, fps: w.currentFps, detection: w.detectionEnabled });
  const procs = [];
  for (const [id, info] of ffmpegProcesses.entries()) procs.push({ cameraId: id, dir: info.dir, running: !!info.proc });
  res.json({ workers: list, ffmpeg: procs });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down server');
  for (const [id, info] of ffmpegProcesses.entries()) {
    try { info.proc.kill('SIGKILL'); } catch (e) {}
  }
  server.close();
  process.exit(0);
});
