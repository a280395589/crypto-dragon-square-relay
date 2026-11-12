// Authentication only: callers must atomically claim the verified nonce before
// any queue mutation or external effect. A valid MAC alone does not stop replay.
export const RELAY_PATHS = Object.freeze([
  '/v1/square-relay/claim',
  '/v1/square-relay/arm',
  '/v1/square-relay/result',
]);
export const MAX_RELAY_BODY_BYTES = 16 * 1024;
const MAX_CLOCK_SKEW_SECONDS = 300;
const encoder = new TextEncoder();
const noncePattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const macPattern = /^[0-9a-f]{64}$/i;
const authFailure = () => new Error('RELAY_AUTH_FAILED');
const invalidInput = () => new Error('RELAY_SIGN_INPUT_INVALID');
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

function secretBytes(secret) {
  if (typeof secret !== 'string' || secret.length > 4096) throw new Error('RELAY_AUTH_UNAVAILABLE');
  const bytes = encoder.encode(secret);
  if (bytes.byteLength < 32 || bytes.byteLength > 4096) throw new Error('RELAY_AUTH_UNAVAILABLE');
  return bytes;
}

function validTarget(method, path) {
  return method === 'POST' && RELAY_PATHS.includes(path);
}

function validTimestamp(timestamp) {
  return Number.isSafeInteger(timestamp) && timestamp >= 0;
}

function signingBody(body) {
  let bytes;
  if (typeof body === 'string') {
    if (body.length > MAX_RELAY_BODY_BYTES) throw new Error('RELAY_REQUEST_TOO_LARGE');
    bytes = encoder.encode(body);
  } else if (body instanceof ArrayBuffer) {
    bytes = new Uint8Array(body);
  } else if (ArrayBuffer.isView(body)) {
    bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  } else {
    throw invalidInput();
  }
  if (bytes.byteLength > MAX_RELAY_BODY_BYTES) throw new Error('RELAY_REQUEST_TOO_LARGE');
  // Own the bytes across the async digest and signing operations.
  return new Uint8Array(bytes);
}

async function requestBody(request) {
  const length = request.headers.get('content-length');
  if (length !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(length) || !Number.isSafeInteger(Number(length))) throw authFailure();
    if (Number(length) > MAX_RELAY_BODY_BYTES) throw new Error('RELAY_REQUEST_TOO_LARGE');
  }
  let reader;
  try { reader = request.body?.getReader(); } catch { throw new Error('RELAY_BODY_UNREADABLE'); }
  if (!reader) {
    if (length !== null && Number(length) !== 0) throw authFailure();
    return new Uint8Array();
  }
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      let part;
      try { part = await reader.read(); } catch { throw new Error('RELAY_BODY_UNREADABLE'); }
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) throw new Error('RELAY_BODY_UNREADABLE');
      size += part.value.byteLength;
      if (size > MAX_RELAY_BODY_BYTES) {
        try { await reader.cancel(); } catch { /* Already rejected; cancellation errors disclose nothing. */ }
        throw new Error('RELAY_REQUEST_TOO_LARGE');
      }
      if (part.value.byteLength) chunks.push(new Uint8Array(part.value));
    }
  } finally {
    reader.releaseLock();
  }
  if (length !== null && Number(length) !== size) throw authFailure();
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function digest(bytes) {
  try { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))); }
  catch { throw new Error('RELAY_AUTH_UNAVAILABLE'); }
}

async function hmacKey(secret, usage) {
  const bytes = secretBytes(secret);
  try { return await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, [usage]); }
  catch { throw new Error('RELAY_AUTH_UNAVAILABLE'); }
}

function canonical(timestamp, nonce, method, path, bodySha256) {
  return encoder.encode(`${timestamp}\n${nonce}\n${method}\n${path}\n${bodySha256}`);
}

/** Sign the exact outbound bytes; do not serialize the body again afterwards. */
export async function signRelayRequest({ secret, path, body, nonce, timestamp, method = 'POST' }) {
  if (!validTarget(method, path) || !validTimestamp(timestamp) || typeof nonce !== 'string' || !noncePattern.test(nonce)) throw invalidInput();
  const bytes = signingBody(body);
  const key = await hmacKey(secret, 'sign');
  const bodySha256 = await digest(bytes);
  let signature;
  try { signature = await crypto.subtle.sign('HMAC', key, canonical(timestamp, nonce, method, path, bodySha256)); }
  catch { throw new Error('RELAY_AUTH_UNAVAILABLE'); }
  return {
    'x-cca-relay-timestamp': String(timestamp),
    'x-cca-relay-nonce': nonce,
    'x-cca-relay-signature': hex(new Uint8Array(signature)),
  };
}

/** Verify and consume a bounded body. Persist nonce atomically in the caller. */
export async function verifyRelayRequest(request, secret, { nowMs = Date.now() } = {}) {
  const key = await hmacKey(secret, 'verify');
  let url;
  try { url = new URL(request.url); } catch { throw authFailure(); }
  if (!validTarget(request.method, url.pathname) || url.search || url.hash || url.username || url.password) throw authFailure();
  let stamp, nonce, mac;
  try {
    stamp = request.headers.get('x-cca-relay-timestamp');
    nonce = request.headers.get('x-cca-relay-nonce');
    mac = request.headers.get('x-cca-relay-signature');
  } catch { throw authFailure(); }
  if (typeof stamp !== 'string' || !/^(0|[1-9][0-9]*)$/.test(stamp) || !validTimestamp(Number(stamp))
      || typeof nonce !== 'string' || !noncePattern.test(nonce) || typeof mac !== 'string' || !macPattern.test(mac)
      || !Number.isFinite(nowMs) || nowMs < 0) throw authFailure();
  const timestamp = Number(stamp);
  if (Math.abs(Math.floor(nowMs / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS) throw authFailure();
  const bodyBytes = await requestBody(request);
  const bodySha256 = await digest(bodyBytes);
  const signature = Uint8Array.from(mac.match(/../g), part => Number.parseInt(part, 16));
  let valid;
  try { valid = await crypto.subtle.verify('HMAC', key, signature, canonical(timestamp, nonce, request.method, url.pathname, bodySha256)); }
  catch { throw new Error('RELAY_AUTH_UNAVAILABLE'); }
  if (!valid) throw authFailure();
  return { nonce, timestamp, bodySha256, bodyBytes };
}
