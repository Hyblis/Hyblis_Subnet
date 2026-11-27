/* Hyblis site — wallet signing.
 *
 * A report is signed in the browser with a Polkadot-compatible wallet extension
 * (polkadot{.js}, Talisman, SubWallet, ...). The page never sees a private key.
 *
 * What is signed (scheme "wallet-v1", see platform/hyblis_platform/keys.py):
 *     hyblis-submit:v1:<submission_id>
 * where submission_id = sha256(canonical JSON of the package). The wallet shows
 * that short line and wraps it as <Bytes>...</Bytes> before signing. The server
 * recomputes the hash from the package it received, so the signature covers
 * every field of the report.
 *
 * The pure functions (canonical, sha256Hex, buildPackage, submissionId, message)
 * are also exported for Node so tests can compare them with the Python server.
 */
(function (root) {
  'use strict';

  /* ---------- pure: canonical JSON identical to Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) ---------- */
  function isWellFormed(s) {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) { const d = s.charCodeAt(i + 1); if (!(d >= 0xdc00 && d <= 0xdfff)) return false; i++; }
      else if (c >= 0xdc00 && c <= 0xdfff) return false;
    }
    return true;
  }
  function canonical(v) {
    if (v === null) return 'null';
    if (v === true) return 'true';
    if (v === false) return 'false';
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) throw new Error('canonical: only safe integers are allowed');
      return String(v);
    }
    if (typeof v === 'string') {
      if (!isWellFormed(v)) throw new Error('canonical: text is not valid Unicode');
      return JSON.stringify(v);
    }
    if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
    if (typeof v === 'object') {
      const keys = Object.keys(v).sort();
      for (const k of keys) if (!/^[\x20-\x7e]+$/.test(k)) throw new Error('canonical: keys must be printable ASCII');
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
    }
    throw new Error('canonical: unsupported value');
  }

  function utf8(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    return Uint8Array.from(Buffer.from(str, 'utf8'));
  }
  function toHex(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16); return s; }

  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  function sha256Hex(bytes) {
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const l = bytes.length, padLen = ((l + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(padLen); buf.set(bytes); buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, Math.floor((l * 8) / 4294967296)); dv.setUint32(padLen - 4, (l * 8) >>> 0);
    const w = new Uint32Array(64);
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    return [h0, h1, h2, h3, h4, h5, h6, h7].map((x) => (x >>> 0).toString(16).padStart(8, '0')).join('');
  }

  const PREFIX = 'hyblis-submit:v1:';
  const SCHEME = 'wallet-v1';
  function randomHex(nBytes) {
    const b = new Uint8Array(nBytes);
    (root.crypto || require('crypto').webcrypto).getRandomValues(b);
    return toHex(b);
  }
  // f: { task_id, hotkey, title, contract, fn, severity, description, poc } (+ optional nonce, ts for tests)
  function buildPackage(f) {
    const poc = String(f.poc);
    return {
      v: 1,
      task_id: String(f.task_id),
      hotkey: String(f.hotkey),
      nonce: f.nonce || randomHex(16),
      ts: typeof f.ts === 'number' ? f.ts : Math.floor(Date.now() / 1000),
      header: {
        title: String(f.title).trim(),
        contract: String(f.contract).trim().toLowerCase(),
        function: String(f.fn).trim(),
        severity: String(f.severity),
        description: String(f.description).trim(),
      },
      poc: poc,
      poc_sha256: sha256Hex(utf8(poc)),
    };
  }
  const submissionId = (pkg) => sha256Hex(utf8(canonical(pkg)));
  const message = (sid) => PREFIX + sid;

  const pure = { canonical, sha256Hex, utf8, toHex, buildPackage, submissionId, message, isWellFormed, PREFIX, SCHEME };
  if (typeof module !== 'undefined' && module.exports) { module.exports = pure; return; }

  /* ---------- browser: wallet extensions ---------- */
  const H = (root.Hyblis = root.Hyblis || {});
  const KNOWN = { 'polkadot-js': 'Polkadot{.js}', talisman: 'Talisman', 'subwallet-js': 'SubWallet', 'fearless-wallet': 'Fearless', enkrypt: 'Enkrypt', 'nova': 'Nova' };
  const listeners = [];
  const state = { ext: null, extId: null, accounts: [], address: null };
  const emit = () => listeners.forEach((fn) => { try { fn(state); } catch (e) { /* listener error must not break the wallet */ } });

  const DEMO_ACCOUNT = { address: '5FpjvVN9fkYjNvNwzZYxLFNz2UVDmeZ8ZvD47A1dLMnsVgo6', name: 'Preview researcher', type: 'sr25519' };

  function extensions() {
    if (H.cfg && H.cfg.demo) return [{ id: 'demo', title: 'Preview wallet', demo: true }];
    const inj = root.injectedWeb3 || {};
    return Object.keys(inj).filter((k) => inj[k] && typeof inj[k].enable === 'function')
      .map((k) => ({ id: k, title: KNOWN[k] || k }));
  }

  async function connect(id) {
    if (H.cfg && H.cfg.demo) {
      await new Promise((r) => setTimeout(r, 450));
      Object.assign(state, { ext: { demo: true }, extId: 'demo', accounts: [DEMO_ACCOUNT], address: state.address || DEMO_ACCOUNT.address });
    } else {
      const inj = (root.injectedWeb3 || {})[id];
      if (!inj) throw new Error('That wallet extension is not available in this browser.');
      const ext = await inj.enable('Hyblis');
      const all = (await ext.accounts.get()) || [];
      // Bittensor keys are sr25519 (an account without a type is kept). Addresses must be in the
      // generic Substrate format, which the gateway expects (they start with 5).
      const sr = all.filter((a) => a && (!a.type || a.type === 'sr25519'));
      const accounts = sr.filter((a) => /^5[1-9A-HJ-NP-Za-km-z]{46,47}$/.test(a.address))
        .map((a) => ({ address: a.address, name: a.name || 'Account', type: a.type || 'sr25519' }));
      if (!accounts.length) {
        throw new Error(sr.length ? "Your wallet shows these accounts in another network format. In the extension, set the account's network to Bittensor or Substrate (generic), then connect again."
          : all.length ? 'Hyblis needs an sr25519 hotkey. Import your miner hotkey into the wallet.'
            : 'The wallet shared no accounts with this site. Import your miner hotkey, or allow this site to see it, then connect again.');
      }
      const keep = accounts.find((a) => a.address === state.address) || accounts.find((a) => a.address === H.store.get('wallet', {}).address);
      Object.assign(state, { ext, extId: id, accounts, address: (keep || accounts[0]).address });
    }
    H.store.set('wallet', { ext: state.extId, address: state.address });
    emit();
    return state.accounts;
  }

  function select(address) {
    if (!state.accounts.some((a) => a.address === address)) return;
    state.address = address;
    H.store.set('wallet', { ext: state.extId, address });
    emit();
  }

  function disconnect() {
    Object.assign(state, { ext: null, extId: null, accounts: [], address: null });
    H.store.del('wallet');
    emit();
  }

  // Ask the wallet to sign the short message for a submission. Returns a 0x-hex signature.
  async function sign(address, msg) {
    if (!state.ext) throw new Error('Connect a wallet first.');
    if (state.ext.demo) {
      await new Promise((r) => setTimeout(r, 700));
      return '0x' + randomHex(64);
    }
    if (!state.ext.signer || typeof state.ext.signer.signRaw !== 'function') throw new Error('This wallet cannot sign messages.');
    const res = await state.ext.signer.signRaw({ address, data: '0x' + toHex(utf8(msg)), type: 'bytes' });
    if (!res || typeof res.signature !== 'string') throw new Error('The wallet did not return a signature.');
    return res.signature;
  }

  // Reconnect silently when the visitor connected before (the extension remembers the approval).
  // The address is set only once the extension confirms the account (connect() picks the saved one),
  // so no page shows a signer that may be gone; a failure is announced so pages redraw.
  async function restore() {
    const saved = H.store.get('wallet', null);
    if (!saved || !saved.ext) return false;
    try { await connect(saved.ext); return true; } catch (e) { state.address = null; emit(); return false; }
  }

  H.wallet = Object.assign({}, pure, {
    state, extensions, connect, select, disconnect, sign, restore,
    onChange(fn) { listeners.push(fn); return () => { const i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1); }; },
    account() { return state.accounts.find((a) => a.address === state.address) || null; },
  });
})(typeof window !== 'undefined' ? window : globalThis);
