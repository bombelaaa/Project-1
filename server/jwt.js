const crypto = require('crypto');

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function signJWT(payload, secret, expiresInSec = 24*3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + expiresInSec;
  const encHeader  = base64url(JSON.stringify(header));
  const encPayload = base64url(JSON.stringify({ ...payload, iat, exp }));
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${encHeader}.${encPayload}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${encHeader}.${encPayload}.${signature}`;
}

function verifyJWT(token, secret) {
  const [encHeader, encPayload, sig] = token.split('.');
  if (!encHeader || !encPayload || !sig) {
    throw new Error('Malformed token');
  }
  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`${encHeader}.${encPayload}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  if (sig !== expectedSig) {
    throw new Error('Invalid signature');
  }

  const { exp, ...rest } = JSON.parse(
    Buffer.from(encPayload, 'base64').toString()
  );
  if (Math.floor(Date.now() / 1000) > exp) {
    throw new Error('Token expired');
  }
  return rest;
}

module.exports = { signJWT, verifyJWT };