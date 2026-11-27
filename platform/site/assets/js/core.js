/* Hyblis site — core helpers. Everything hangs off window.Hyblis (no modules, no build step). */
(function () {
  'use strict';
  const H = (window.Hyblis = window.Hyblis || {});

  H.cfg = { apiBase: '', demo: false, network: 'mainnet', netuid: null };
  H.reduced = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  H.finePointer = !!(window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches);

  /* ---------- safe HTML templating: every ${value} is escaped unless wrapped in raw() ---------- */
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  H.esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ESC[c]);
  function Raw(s) { this.s = s; }
  Raw.prototype.toString = function () { return this.s; };
  H.raw = (s) => new Raw(String(s == null ? '' : s));
  function render(v) {
    if (v == null || v === false || v === true) return '';
    if (Array.isArray(v)) return v.map(render).join('');
    if (v instanceof Raw) return v.s;
    return H.esc(v);
  }
  H.html = function (strings) {
    let out = '';
    for (let i = 0; i < strings.length; i++) {
      out += strings[i];
      if (i + 1 < arguments.length) out += render(arguments[i + 1]);
    }
    return new Raw(out);
  };
  const html = H.html;

  /* ---------- formatting ---------- */
  H.short = (s, a, b) => { s = String(s || ''); a = a || 6; b = b == null ? 6 : b; return s.length <= a + b + 1 ? s : s.slice(0, a) + '…' + (b ? s.slice(-b) : ''); };
  H.ago = (ts) => {
    if (!ts) return '—';
    const d = Math.max(0, Date.now() / 1000 - ts);
    if (d < 60) return 'just now';
    if (d < 3600) return Math.round(d / 60) + ' min ago';
    if (d < 86400) return Math.round(d / 3600) + ' h ago';
    if (d < 86400 * 60) return Math.round(d / 86400) + ' d ago';
    return H.date(ts);
  };
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  H.toDate = (v) => (v == null ? null : typeof v === 'number' ? new Date(v * 1000) : new Date(String(v).length <= 10 ? v + 'T00:00:00Z' : v));
  H.date = (v) => { const d = H.toDate(v); return !d || isNaN(d) ? '—' : d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()] + ' ' + d.getUTCFullYear(); };
  H.dateTime = (v) => { const d = H.toDate(v); if (!d || isNaN(d)) return '—'; const p = (n) => String(n).padStart(2, '0'); return H.date(v) + ' ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) + ' UTC'; };
  // Relative times are rendered as <time data-ago> so one global timer (app.js) keeps them fresh
  // without redrawing the tables they sit in.
  H.timeAgo = (ts) => { const d = H.toDate(ts); return ts && !isNaN(d) ? html`<time data-ago="${ts}" datetime="${d.toISOString()}">${H.ago(ts)}</time>` : H.ago(ts); };
  H.tickAgo = (root) => H.$$('time[data-ago]', root).forEach((el) => { const s = H.ago(+el.dataset.ago); if (el.textContent !== s) el.textContent = s; });
  H.num = (n, dec) => Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: dec || 0, maximumFractionDigits: dec || 0 });
  H.cap = (s) => { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); };
  H.countdown = (target) => {
    let s = Math.max(0, Math.floor((H.toDate(target) - Date.now()) / 1000));
    const d = Math.floor(s / 86400); s -= d * 86400;
    const h = Math.floor(s / 3600); s -= h * 3600;
    const m = Math.floor(s / 60); s -= m * 60;
    return { d, h, m, s, done: d + h + m + s === 0 };
  };

  // Shown wherever a date or a countdown would be while report intake is closed (launch mode).
  H.LAUNCH = 'Opens at mainnet launch';

  /* ---------- small shared pieces of UI ---------- */
  const SEV = ['critical', 'high', 'medium', 'low'];
  H.SEV = SEV;
  H.sev = (s) => html`<span class="sev sev-${SEV.includes(s) ? s : 'none'}">${s || 'n/a'}</span>`;
  const STATUS_LABEL = { received: 'Received', screening: 'Screening', reproducing: 'Reproducing', validated: 'Validated',
    under_review: 'Under review', accepted: 'Accepted', duplicate: 'Duplicate', rejected: 'Rejected', expired: 'Expired' };
  H.statusLabel = (s) => STATUS_LABEL[s] || H.cap(String(s || '').replace(/_/g, ' '));
  H.status = (s) => html`<span class="st st-${STATUS_LABEL[s] ? s : 'received'}"><i></i>${H.statusLabel(s)}</span>`;
  const IMPACT = { funds_loss: 'Direct loss of user funds', funds_freeze: 'Freezing of funds', insolvency: 'Protocol insolvency',
    unauthorized_mint: 'Unauthorised minting', accounting_error: 'Accounting error with measured impact', griefing: 'Griefing', dos: 'Denial of service' };
  H.impactLabel = (i) => IMPACT[i] || H.cap(String(i || '').replace(/_/g, ' '));
  H.icon = (id, size) => html`<svg class="ic" width="${size || 16}" height="${size || 16}" aria-hidden="true"><use href="#${id}"/></svg>`;

  // Deterministic identicon for a hotkey: a flat-topped hexagon (the logo's orientation) cut into six
  // wedges from the centre, each dim, mid or bright in the key's brand gradient. Nothing is mirrored,
  // so no face or creature can appear. Only computed numbers go into the SVG.
  function fnv(str) { let h = 0x811c9dc5; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; }
  function prng(a) { return function () { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  const TONES = [['#f43f73', '#a91ee6'], ['#d91e8f', '#7c3aed'], ['#fb7185', '#c026d3'], ['#e879f9', '#6d28d9'], ['#f472b6', '#9333ea'], ['#fda4af', '#be185d']];
  const HEX = [0, 1, 2, 3, 4, 5].map((k) => [Math.cos(k * Math.PI / 3), Math.sin(k * Math.PI / 3)].map((v) => +(12 + 8.6 * v).toFixed(2)));
  const LEVELS = [0.16, 0.42, 0.95];
  H.identicon = (key, size) => {
    key = String(key || '?'); size = +size || 32;
    const r = prng(fnv(key)); const tone = TONES[fnv(key + 't') % TONES.length]; const id = 'g' + fnv(key).toString(36);
    const lv = HEX.map(() => Math.floor(r() * 3));
    // at least one bright and one dim wedge, so every mark has contrast
    if (lv.indexOf(2) < 0) lv[Math.floor(r() * 6)] = 2;
    if (lv.indexOf(0) < 0) { let j = Math.floor(r() * 6); if (lv[j] === 2 && lv.filter((x) => x === 2).length === 1) j = (j + 3) % 6; lv[j] = 0; }
    const wedges = HEX.map((p, k) => { const q = HEX[(k + 1) % 6]; return '<path d="M12 12L' + p[0] + ' ' + p[1] + 'L' + q[0] + ' ' + q[1] + 'Z" fill-opacity="' + LEVELS[lv[k]] + '"/>'; }).join('');
    return H.raw('<svg class="idn" width="' + size + '" height="' + size + '" viewBox="0 0 24 24" aria-hidden="true"><defs><linearGradient id="' + id + '" gradientUnits="userSpaceOnUse" x1="3.4" y1="4.55" x2="20.6" y2="19.45"><stop offset="0" stop-color="' + tone[0] + '"/><stop offset="1" stop-color="' + tone[1] + '"/></linearGradient></defs><rect width="24" height="24" rx="5" fill="#15151a"/><g fill="url(#' + id + ')" stroke="#15151a" stroke-width="0.6" stroke-linejoin="round">' + wedges + '</g></svg>');
  };

  /* ---------- storage (never throws) ---------- */
  const mem = {};
  H.store = {
    get(k, d) { try { const v = localStorage.getItem('hyblis.' + k); return v == null ? (k in mem ? mem[k] : d) : JSON.parse(v); } catch (e) { return k in mem ? mem[k] : d; } },
    set(k, v) { mem[k] = v; try { localStorage.setItem('hyblis.' + k, JSON.stringify(v)); } catch (e) { /* private mode: memory only */ } },
    del(k) { delete mem[k]; try { localStorage.removeItem('hyblis.' + k); } catch (e) { /* ignore */ } },
  };

  /* ---------- toasts + clipboard ---------- */
  H.toast = (msg, kind) => {
    const root = document.getElementById('toasts'); if (!root) return;
    const el = document.createElement('div');
    el.className = 'toast toast-' + (kind || 'info');
    el.textContent = msg;
    root.appendChild(el);
    requestAnimationFrame(() => el.classList.add('in'));
    setTimeout(() => { el.classList.remove('in'); setTimeout(() => el.remove(), 320); }, 3600);
  };
  H.copy = async (text, okMsg) => {
    try { await navigator.clipboard.writeText(text); H.toast(okMsg || 'Copied', 'ok'); return true; }
    catch (e) {
      const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.cssText = 'position:fixed;left:-9999px;top:0';
      document.body.appendChild(ta); ta.select();
      let ok = false; try { ok = document.execCommand('copy'); } catch (e2) { ok = false; }
      ta.remove(); H.toast(ok ? (okMsg || 'Copied') : 'Copy failed. Select the text and copy it by hand.', ok ? 'ok' : 'bad'); return ok;
    }
  };

  /* ---------- DOM helpers ---------- */
  H.$ = (sel, root) => (root || document).querySelector(sel);
  H.$$ = (sel, root) => Array.prototype.slice.call((root || document).querySelectorAll(sel));
  // Delegated listener; returns an unsubscribe function.
  H.on = (root, type, sel, fn, opts) => {
    const h = (e) => { const t = e.target && e.target.closest ? e.target.closest(sel) : null; if (t && root.contains(t)) fn(e, t); };
    root.addEventListener(type, h, opts); return () => root.removeEventListener(type, h, opts);
  };
  H.debounce = (fn, ms) => { let t; return function () { const a = arguments; clearTimeout(t); t = setTimeout(() => fn.apply(null, a), ms); }; };
  H.clamp = (x, a, b) => Math.max(a, Math.min(b, x));
  H.go = (route) => { if (location.hash !== '#' + route) location.hash = route; else window.dispatchEvent(new Event('hashchange')); };
})();
