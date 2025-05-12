require('dotenv').config();
console.log('▶︎ JWT_SECRET:', typeof process.env.JWT_SECRET, process.env.JWT_SECRET);

const path    = require('path');
const express = require('express');
const http    = require('http');
const { Server } = require('socket.io');
const pool    = require('./db');
const bcrypt  = require('bcrypt');
const { signJWT, verifyJWT } = require('./jwt');

const AWS = require('aws-sdk');
const s3  = new AWS.S3({ region: process.env.AWS_REGION });

const app = express();
app.use(express.json());

function requireFields(fields, req, res) {
  for (let f of fields) {
    if (!req.body[f]) {
      res.status(400).json({ error: `Missing field: ${f}` });
      return false;
    }
  }
  return true;
}


app.get('/api/ping', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1+1 AS result');
    res.json({ success: true, result: rows[0].result });
  } catch (err) {
    console.error('DB ping error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});


app.post('/api/register', async (req, res) => {
  if (!requireFields(['username','password'], req, res)) return;
  const { username, password, publicKey, encryptedPrivateKey } = req.body;

  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      'INSERT INTO users (username, hashed_password, public_key, encrypted_private_key) VALUES (?, ?, ?, ?)',
      [username, hash, publicKey || null, encryptedPrivateKey || null]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({
      error: err.code === 'ER_DUP_ENTRY'
        ? 'Username already taken'
        : 'Database error'
    });
  }
});


app.post('/api/login', async (req, res) => {
  if (!requireFields(['username','password'], req, res)) return;
  const { username, password } = req.body;

  try {
    const [rows] = await pool.query(
      'SELECT id, hashed_password, public_key, encrypted_private_key FROM users WHERE username = ?',
      [username]
    );
    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user  = rows[0];
    const valid = await bcrypt.compare(password, user.hashed_password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signJWT(
      { userId: user.id },
      process.env.JWT_SECRET,
      24 * 3600 
    );

    res.json({
      success: true,
      token,
      userId: user.id,
      publicKey: user.public_key,
      encryptedPrivateKey: user.encrypted_private_key
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});


function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }
  const token = auth.slice(7);
  try {
    const payload = verifyJWT(token, process.env.JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: err.message });
  }
}

app.get('/api/users', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, username, public_key FROM users WHERE id <> ?',
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});


app.post('/api/upload-url', requireAuth, async (req, res) => {
  const { fileName, contentType } = req.body;
  if (!fileName || !contentType) {
    return res.status(400).json({ error: 'Missing fileName or contentType' });
  }

  const key = `${req.userId}/${Date.now()}-${fileName}`;

  try {
    const uploadUrl = s3.getSignedUrl('putObject', {
      Bucket: process.env.S3_BUCKET,
      Key: key,
      ContentType: contentType,
      Expires: 300
    });

    const fileUrl = s3.getSignedUrl('getObject', {
      Bucket: process.env.S3_BUCKET,
      Key: key,
      Expires: 3600
    });

    res.json({ uploadUrl, fileUrl });
  } catch (err) {
    console.error('Presign error:', err);
    res.status(500).json({ error: 'Could not create presigned URL' });
  }
});

app.use(express.static(path.join(__dirname, '..', 'public')));

const httpServer = http.createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));
  try {
    const payload = verifyJWT(token, process.env.JWT_SECRET);
    socket.userId = payload.userId;
    return next();
  } catch {
    return next(new Error('Authentication error'));
  }
});

io.on('connection', socket => {
  const uid = socket.userId;
  console.log(`User ${uid} connected`);

  pool.query(
    'REPLACE INTO presence (user_id, last_seen) VALUES (?, NOW())',
    [uid]
  );
  io.emit('user_online', { userId: uid });

  socket.join(String(uid));

  socket.on('ping', () => socket.emit('pong'));

  socket.on('encrypted_message', async ({ to, ciphertext, iv }) => {
    await pool.query(
      'INSERT INTO messages (sender_id, recipient_id, ciphertext, iv) VALUES (?, ?, ?, ?)',
      [uid, to, ciphertext, iv]
    );
    socket.to(String(to)).emit('encrypted_message', { from: uid, ciphertext, iv });
  });

  socket.on('file_message', ({ to, fileUrl, fileName }) => {
    socket.to(String(to)).emit('file_message', { from: uid, fileUrl, fileName });
  });

  socket.on('disconnect', () => {
    console.log(`User ${uid} disconnected`);
    pool.query(
      'UPDATE presence SET last_seen = NOW() WHERE user_id = ?',
      [uid]
    );
    io.emit('user_offline', { userId: uid });
  });
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
