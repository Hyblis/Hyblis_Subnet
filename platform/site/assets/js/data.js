/* Hyblis site — data layer.
 * Real mode: reads the exported public JSON from this site (data/*.json) and talks to the gateway
 *            (H.cfg.apiBase) only to submit a signed report, to look up a submission's status, and
 *            to fetch the visitor's own receipt by its secret token (with the result once decided).
 * Demo mode: when window.HYBLIS_DEMO is present (the design preview), everything runs on that sample
 *            data and nothing leaves the page.
 */
(function () {
  'use strict';
  const H = window.Hyblis;
  // programs has no prototype, so a route such as #program-constructor finds nothing
  const cache = { ok: false, loadedAt: 0, summary: null, tasks: [], leaderboard: [], ledger: [], programs: Object.create(null), policy: null };
  const subs = [], eventSubs = [];
  let timer = null, prevStatus = null, lastSig = null;

  async function getJSON(url, opts) {
    const r = await fetch(url, Object.assign({ cache: 'no-store' }, opts || {}));
    if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
    return r.json();
  }

  /* ---------- demo data: keep the sample feeling current whenever the preview is opened ---------- */
  let demo = null;
  function iso(d) { return d.toISOString().slice(0, 10); }
  function prepareDemo() {
    const src = window.HYBLIS_DEMO;
    const now = Math.floor(Date.now() / 1000);
    const newest = src.ledger.reduce((m, r) => Math.max(m, r.t), 0);
    const shift = now - 260 - newest;
    const day = 86400000, today = new Date();
    demo = JSON.parse(JSON.stringify(src));
    demo.ledger.forEach((r) => { r.t += shift; });
    const closed = demo.summary.releases && demo.summary.releases.intake_open === false;
    demo.tasks.forEach((t) => {
      if (closed) return;   // launch mode: programs open at launch, so they keep their (empty) dates
      if (t.status === 'featured') { t.opened_at = iso(new Date(today - 2 * day)); t.featured_until = iso(new Date(+today + 5 * day)); }
      else t.opened_at = iso(new Date(today - 9 * day));
    });
    Object.keys(demo.programs || {}).forEach((k) => { const t = demo.tasks.find((x) => x.task_id === k); if (t) Object.assign(demo.programs[k], { opened_at: t.opened_at, featured_until: t.featured_until }); });
    demo.summary.generated_at = now;
    if (!closed) demo.summary.releases.next_release_on = iso(new Date(+today + 5 * day));
    demo.summary.settlement.next_at = now + 19 * 86400;
    // A sample report of the visitor's own, so the dashboard shows what a rejection looks like.
    const rj = demo.ledger.filter((r) => r.status === 'rejected').sort((a, b) => b.t - a.t)[0];
    const t0 = demo.tasks[0];
    demo.sampleReceipt = rj && t0 ? { id: rj.hash, token: 'preview-sample', task_id: t0.task_id, label: t0.label, title: 'Sample report: storage write in the proof',
      severity: rj.severity, hotkey: '', t: rj.t, status: 'rejected', history: [{ status: 'rejected', at: rj.t }], sample: true } : null;
  }
  // The receipt the gateway would return for a preview token, with a sample result (built by
  // scripts/build_preview.py from the platform's own code, so the texts are the real ones).
  function demoReceipt(token) {
    const S = demo.samples || {};
    const sr = demo.sampleReceipt;
    let row = null;
    if (sr && token === sr.token) row = demo.ledger.find((r) => r.hash === sr.id);
    else if (/^preview-[0-9a-f]{12}$/.test(token)) row = demo.ledger.find((r) => r.hash.indexOf(token.slice(8)) === 0);
    if (!row) return null;
    const payload = { submission_id: row.hash, received_at: row.t, task_id: (demo.tasks[0] || {}).task_id || '', poc_sha256: '', hotkey: '' };
    let result = null;
    if (row.status === 'rejected') result = S.rejected || { status: 'rejected', error: 'no_impact', explanation: '', detail: '', policy: [] };
    else if (['validated', 'under_review', 'accepted', 'duplicate', 'expired'].indexOf(row.status) >= 0) {
      result = Object.assign({}, S[row.status === 'duplicate' ? 'duplicate' : 'validated'] || {}, { status: row.status });
      if (!result.measured_severity) result.measured_severity = row.severity;
    }
    return { payload, server_sig: null, result };
  }
  function demoCounts() {
    const l = demo.ledger;
    demo.summary.counts = {
      submissions: l.length,
      validated: l.filter((r) => ['validated', 'under_review', 'accepted'].includes(r.status)).length,
      accepted: l.filter((r) => r.status === 'accepted').length,
      researchers: demo.leaderboard.length,
      open_programs: demo.tasks.length,
    };
  }
  // A report sent from the preview walks through the pipeline so the dashboard can be reviewed.
  function demoAdvance(id, hotkey) {
    const step = (status, ms) => setTimeout(() => {
      const row = demo.ledger.find((r) => r.hash === id); if (!row) return;
      row.status = status;
      demo.summary.generated_at = Math.floor(Date.now() / 1000);
      if (status === 'validated') {
        row.hotkey = hotkey;
        const lb = demo.leaderboard.find((x) => x.hotkey === hotkey);
        if (lb) { lb.validated += 1; lb.score = Math.round((lb.score + 6) * 100) / 100; }
      }
      refresh();
    }, ms);
    step('reproducing', 7000); step('validated', 19000);
  }

  /* ---------- load + refresh ---------- */
  async function init() {
    if (window.HYBLIS_DEMO) { H.cfg.demo = true; prepareDemo(); return; }
    try {
      const c = await getJSON('config.json');
      H.cfg.apiBase = String(c.api_base || '').replace(/\/$/, '');
      H.cfg.network = c.network === 'testnet' ? 'testnet' : 'mainnet';
      H.cfg.netuid = Number.isInteger(c.netuid) ? c.netuid : null;
      if (H.cfg.network === 'testnet') document.documentElement.setAttribute('data-network', 'testnet');
    } catch (e) { /* same origin */ }
  }

  function diffEvents(ledger) {
    const now = {}; const events = [];
    ledger.forEach((r) => { now[r.hash] = r.status; });
    if (prevStatus) {
      ledger.forEach((r) => {
        const was = prevStatus[r.hash];
        if (was !== r.status) events.push({ type: was ? 'status' : 'new', row: r, from: was || null });
      });
    }
    prevStatus = now;
    return events;
  }

  // A program's cached details go stale when it opens for intake or its status changes.
  function dropStalePrograms() {
    Object.keys(cache.programs).forEach((id) => {
      const t = cache.tasks.find((x) => x.task_id === id), p = cache.programs[id];
      if (!t || t.status !== p.status || t.open_for_intake !== p.open_for_intake) delete cache.programs[id];
    });
  }

  async function refresh() {
    let events = [];
    try {
      if (H.cfg.demo) {
        demoCounts();
        Object.assign(cache, { summary: demo.summary, tasks: demo.tasks, leaderboard: demo.leaderboard.slice().sort((a, b) => b.score - a.score).map((r, i) => Object.assign(r, { rank: i + 1 })), ledger: demo.ledger, policy: demo.policy });
      } else {
        const [summary, tasks, leaderboard, ledger] = await Promise.all(['summary', 'tasks', 'leaderboard', 'ledger'].map((n) => getJSON('data/' + n + '.json')));
        Object.assign(cache, { summary, tasks, leaderboard, ledger });
      }
      cache.ok = true; cache.loadedAt = Date.now();
      events = diffEvents(cache.ledger);
      dropStalePrograms();
    } catch (e) { cache.ok = false; }
    // Pages redraw only when the data changed, so a poll never takes keyboard focus away for nothing.
    // The status bar ({ always: true }) still hears every poll.
    const sig = JSON.stringify([cache.ok, cache.summary, cache.tasks, cache.leaderboard, cache.ledger]);
    const changed = sig !== lastSig; lastSig = sig;
    subs.slice().forEach((s) => { if (changed || s.always) { try { s.fn(cache); } catch (e) { console.error(e); } } });
    if (events.length) eventSubs.slice().forEach((fn) => { try { fn(events); } catch (e) { console.error(e); } });
    return cache;
  }

  function start() {
    if (timer) return;
    timer = setInterval(() => { if (!document.hidden) refresh(); }, 20000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden && Date.now() - cache.loadedAt > 20000) refresh(); });
  }

  /* ---------- lookups ---------- */
  // Resolves to null when there is no such program (404). Rejects when it could not be loaded.
  async function program(id) {
    if (cache.programs[id]) return cache.programs[id];
    let p = null;
    if (H.cfg.demo) p = demo.programs && Object.prototype.hasOwnProperty.call(demo.programs, id) ? demo.programs[id] : null;
    else { try { p = await getJSON('data/programs/' + encodeURIComponent(id) + '.json'); } catch (e) { if (e.status === 404) return null; throw e; } }
    if (p) cache.programs[id] = p;
    return p;
  }
  async function policy() {
    if (cache.policy) return cache.policy;
    try { cache.policy = await getJSON('data/scoring-policy.json'); } catch (e) { cache.policy = null; }
    return cache.policy;
  }
  // The visitor's own receipt, by the secret token from the submit response: the signed arrival proof
  // and, once the report is decided, its result. Resolves to null when the gateway has no receipt for
  // that token (404: an old token, or one from another gateway). Rejects when it could not be loaded.
  async function receipt(token) {
    if (H.cfg.demo) return demoReceipt(String(token || ''));
    try { return await getJSON(H.cfg.apiBase + '/api/receipt/' + encodeURIComponent(token)); }
    catch (e) { if (e.status === 404) return null; throw e; }
  }
  async function submissionStatus(id) {
    if (H.cfg.demo) {
      const r = demo.ledger.find((x) => x.hash === id || x.hash.indexOf(id) === 0);
      return r ? { hash: r.hash, status: r.status, severity: r.severity, t: r.t } : null;
    }
    try { return await getJSON(H.cfg.apiBase + '/api/submission/' + encodeURIComponent(id)); }
    catch (e) { if (e.status === 404) return null; throw e; }
  }
  // envelope: { package, sig, sig_scheme, submission_id }
  async function submit(envelope) {
    if (H.cfg.demo) {
      await new Promise((r) => setTimeout(r, 900));
      const pkg = envelope.package, id = envelope.submission_id, now = Math.floor(Date.now() / 1000);
      demo.ledger.push({ id: id.slice(0, 16), hash: id, t: now, status: 'screening', severity: pkg.header.severity });
      demo.summary.generated_at = now;
      demoAdvance(id, pkg.hotkey);
      refresh();
      return { submission_id: id, received_at: now, status: 'screening', poc_sha256: pkg.poc_sha256, receipt_token: 'preview-' + id.slice(0, 12), server_sig: null };
    }
    let r;
    try {
      r = await fetch(H.cfg.apiBase + '/api/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) });
    } catch (e) { throw new Error('The gateway could not be reached. Check your connection and try again.'); }
    let body = null; try { body = await r.json(); } catch (e) { body = null; }
    if (!r.ok) {
      const reason = (body && body.error) || r.statusText || ('HTTP ' + r.status);
      const err = new Error(friendly(r.status, reason)); err.status = r.status; throw err;
    }
    refresh();
    return body;
  }
  function friendly(status, reason) {
    if (status === 401) return 'The signature did not verify for that hotkey. Sign with the same account you selected.';
    if (status === 409) return 'This exact report was already received.';
    if (status === 413) return 'The report is too large. Keep the proof under 256 KB.';
    if (status === 429) return 'Too many submissions in the last hour. Try again later.';
    return String(reason).replace(/^package: /, '');
  }

  /* ---------- derived views ---------- */
  const CRED = ['validated', 'under_review', 'accepted'];
  function findings(hotkey) { return cache.ledger.filter((r) => r.hotkey === hotkey).sort((a, b) => b.t - a.t); }
  function sevCounts(hotkey) {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    cache.ledger.forEach((r) => { if (r.hotkey === hotkey && CRED.includes(r.status) && c[r.severity] != null) c[r.severity]++; });
    return c;
  }
  const stored = () => H.store.get('receipts', []);
  const receipts = {
    all() {
      const list = stored();
      // the preview adds one sample report (never stored) so the dashboard shows a rejection reason
      const sr = H.cfg.demo && demo && demo.sampleReceipt;
      return sr && !list.some((x) => x.id === sr.id) ? list.concat([sr]) : list;
    },
    add(r) { const list = stored().filter((x) => x.id !== r.id); list.unshift(r); H.store.set('receipts', list.slice(0, 200)); },
    update(id, patch) { H.store.set('receipts', stored().map((x) => (x.id === id ? Object.assign({}, x, patch) : x))); },
    remove(id) { H.store.set('receipts', stored().filter((x) => x.id !== id)); },
  };

  H.data = {
    cache, init, refresh, start, program, policy, submissionStatus, receipt, submit, findings, sevCounts, receipts,
    // fn runs when the data changes; with { always: true } it runs after every poll.
    subscribe(fn, opts) { const s = { fn, always: !!(opts && opts.always) }; subs.push(s); return () => { const i = subs.indexOf(s); if (i >= 0) subs.splice(i, 1); }; },
    // false until the public data has loaded once
    loaded() { return cache.loadedAt > 0; },
    onEvents(fn) { eventSubs.push(fn); return () => { const i = eventSubs.indexOf(fn); if (i >= 0) eventSubs.splice(i, 1); }; },
    task(id) { return cache.tasks.find((t) => t.task_id === id) || null; },
    // Launch mode: the export says whether report intake is open (summary.releases.intake_open). An export
    // without that field predates launch mode, so intake follows the programs' own open_for_intake.
    intakeOpen() { const r = cache.summary && cache.summary.releases; return !(r && r.intake_open === false); },
    intakeMessage() { const r = cache.summary && cache.summary.releases; return (r && r.intake_message) || 'Intake opens at mainnet launch.'; },
    researcher(hotkey) { return cache.leaderboard.find((r) => r.hotkey === hotkey) || null; },
  };
})();
