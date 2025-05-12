const authDiv       = document.getElementById('auth');
const chatDiv       = document.getElementById('chat');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const registerBtn   = document.getElementById('registerBtn');
const loginBtn      = document.getElementById('loginBtn');
const authMsg       = document.getElementById('authMsg');
const meSpan        = document.getElementById('me');
const peerSelect    = document.getElementById('peerSelect');
const messagesList  = document.getElementById('messages');
const messageInput  = document.getElementById('messageInput');
const sendBtn       = document.getElementById('sendBtn');
const fileInput     = document.getElementById('fileInput');
const sendFileBtn   = document.getElementById('sendFileBtn');

let socket         = null;
let myUserId       = null;
let privKeyArmored = null;
let pubKeyArmored  = null;
let privKeyObj     = null;

async function apiRegister(u, p, publicKey, encryptedPrivateKey) {
  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p, publicKey, encryptedPrivateKey })
  });
  return res.json();
}

async function apiLogin(u, p) {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  });
  return res.json();
}

async function loadHistory(peerId) {
  messagesList.innerHTML = '';
  const res = await fetch(`/api/messages/${peerId}`, {
    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt') }
  });
  const msgs = await res.json();
  for (let { from, ciphertext } of msgs) {
    try {
      const message = await openpgp.readMessage({ armoredMessage: ciphertext });
      const { data: cleartext } = await openpgp.decrypt({ message, decryptionKeys: privKeyObj });
      addMessage({ from, body: cleartext });
    } catch (e) {
      console.error('History decrypt error:', e);
    }
  }
}

async function loadPeers() {
  const res = await fetch('/api/users', {
    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt') }
  });
  const users = await res.json();
  peerSelect.innerHTML = '';
  users.forEach(u => {
    const opt = document.createElement('option');
    opt.value = u.id;
    opt.textContent    = u.username;
    opt.dataset.pubkey = u.public_key || '';
    peerSelect.appendChild(opt);
  });
  if (peerSelect.options.length) {
    loadHistory(Number(peerSelect.value));
  }
}

peerSelect.addEventListener('change', () => {
  const pid = Number(peerSelect.value);
  if (pid && pid !== myUserId) loadHistory(pid);
});

function addMessage({ from, body }) {
  const li = document.createElement('li');
  li.textContent = `User ${from}: ${body}`;
  messagesList.appendChild(li);
}

function addFileMessage({ from, fileUrl, fileName }) {
  const li = document.createElement('li');
  li.textContent = `User ${from}: `;
  const a = document.createElement('a');
  a.href = fileUrl;
  a.download = fileName;
  a.textContent = fileName;
  li.appendChild(a);
  messagesList.appendChild(li);
}

registerBtn.addEventListener('click', async () => {
  const u = usernameInput.value.trim();
  const p = passwordInput.value;
  if (!u || !p) {
    authMsg.textContent = 'Enter both username and password';
    return;
  }
  authMsg.textContent = 'Registering…';
  try {
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'ecc', curve: 'curve25519', userIDs: [{ name: u }], passphrase: p
    });
    privKeyArmored = privateKey;
    pubKeyArmored  = publicKey;
    localStorage.setItem('privKey', privKeyArmored);
    localStorage.setItem('pubKey', pubKeyArmored);
    const r = await apiRegister(u, p, pubKeyArmored, privKeyArmored);
    authMsg.textContent = r.success
      ? 'Registered! Please log in.'
      : (r.error || 'Registration failed.');
  } catch (err) {
    console.error('Registration error:', err);
    authMsg.textContent = 'Registration failed—see console';
  }
});

loginBtn.addEventListener('click', async () => {
  const u = usernameInput.value.trim();
  const p = passwordInput.value;
  if (!u || !p) {
    authMsg.textContent = 'Enter both username and password';
    return;
  }
  authMsg.textContent = 'Logging in…';
  try {
    const r = await apiLogin(u, p);
    if (!r.success) {
      authMsg.textContent = r.error || 'Login failed.';
      return;
    }
    localStorage.setItem('jwt', r.token);
    myUserId = r.userId;
    meSpan.textContent = u;
    pubKeyArmored  = r.publicKey  ?? localStorage.getItem('pubKey');
    privKeyArmored = r.encryptedPrivateKey ?? localStorage.getItem('privKey');
    privKeyObj = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: privKeyArmored }),
      passphrase: p
    });
    authDiv.style.display = 'none';
    chatDiv.style.display = 'block';
    await loadPeers();
    startSocket();
  } catch (err) {
    console.error('Login error:', err);
    authMsg.textContent = 'Login or key unlock failed—see console';
  }
});

function startSocket() {
  socket = io({ auth: { token: localStorage.getItem('jwt') } });
  socket.on('connect', () => console.log('WS connected'));
  socket.on('pong', () => console.log('Pong'));
  socket.on('encrypted_message', async ({ from, ciphertext }) => {
    try {
      const message = await openpgp.readMessage({ armoredMessage: ciphertext });
      const { data: cleartext } = await openpgp.decrypt({ message, decryptionKeys: privKeyObj });
      addMessage({ from, body: cleartext });
    } catch (e) {
      console.error('Decrypt error:', e);
    }
  });

  socket.on('file_message', async ({ from, fileUrl, fileName }) => {
    try {
      const armored = await fetch(fileUrl).then(r => r.text());
      const message = await openpgp.readMessage({ armoredMessage: armored });
      const { data: binary } = await openpgp.decrypt({ message, decryptionKeys: privKeyObj, format: 'binary' });
      const blob = new Blob([binary], { type: 'application/octet-stream' });
      const url  = URL.createObjectURL(blob);
      addFileMessage({ from, fileUrl: url, fileName });
    } catch (e) {
      console.error('File decrypt error:', e);
    }
  });

  setInterval(() => socket.emit('ping'), 30000);
}

sendBtn.addEventListener('click', async () => {
  try {
    const text = messageInput.value.trim();
    const to   = Number(peerSelect.value);
    if (!text || !to || to === myUserId) return;
    const peerKey = await openpgp.readKey({ armoredKey: peerSelect.selectedOptions[0].dataset.pubkey });
    const encrypted = await openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: peerKey });
    addMessage({ from: myUserId, body: '(encrypted) ' + text });
    socket.emit('encrypted_message', { to, ciphertext: encrypted, iv: '' });
    messageInput.value = '';
  } catch (e) {
    console.error('Send error:', e);
  }
});

sendFileBtn.addEventListener('click', async () => {
  try {
    const file = fileInput.files[0];
    const to   = Number(peerSelect.value);
    if (!file || !to || to === myUserId) return;
    const arrayBuffer = await file.arrayBuffer();
    const uint8 = new Uint8Array(arrayBuffer);
    const peerKey = await openpgp.readKey({ armoredKey: peerSelect.selectedOptions[0].dataset.pubkey });
    const message = await openpgp.createMessage({ binary: uint8 });
    const encrypted = await openpgp.encrypt({ message, encryptionKeys: peerKey });
    const blob = new Blob([encrypted], { type: 'text/plain' });
    const { uploadUrl, fileUrl } = await fetch('/api/upload-url', {
      method: 'POST',
      headers: {
        'Content-Type':'application/json',
        'Authorization':'Bearer ' + localStorage.getItem('jwt')
      },
      body: JSON.stringify({ fileName: file.name, contentType: 'text/plain' })
    }).then(r => r.json());
    await fetch(uploadUrl, { method:'PUT', headers:{ 'Content-Type':'text/plain' }, body: blob });
    socket.emit('file_message', { to, fileUrl, fileName: file.name });
  } catch (e) {
    console.error('Send file error:', e);
  }
});