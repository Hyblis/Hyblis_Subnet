/* Hyblis site — submit a report (signed in the browser wallet) and the researcher dashboard. */
(function () {
  'use strict';
  const H = window.Hyblis, html = H.html, $ = H.$, $$ = H.$$;
  H.pages = H.pages || {};

  const NEXT = {
    received: 'Policy screen', screening: 'Queued for the sandbox', reproducing: 'Verdict expected within the hour',
    validated: 'Filing with the platform within 12 hours', under_review: 'Waiting for the platform’s decision',
    accepted: 'Accepted: bonus paid through weights', duplicate: 'An earlier proof of this bug was received first',
    rejected: 'Did not pass validation', expired: 'No platform outcome before the cut-off',
  };
  const OPEN = ['received', 'screening', 'reproducing', 'validated', 'under_review'];
  // Rows whose result the dashboard can show (from the visitor's own receipt, by its secret token).
  const DECIDED = ['rejected', 'validated', 'duplicate', 'under_review', 'accepted', 'expired'];
  const ADDR = /^0x[0-9a-fA-F]{40}$/;
  const MAX_POC = 256 * 1024;
  const PREPARED_TTL = 60 * 60 * 1000;   // a prepared package older than an hour gets a fresh nonce and time before signing
  const SIGNED_TTL = 23 * 3600;          // the gateway refuses packages more than a day old, so an older signed copy is signed again

  // Redraws replace markup with innerHTML, which drops keyboard focus. keepFocus() remembers the
  // focused control inside scope by a stable attribute, runs the redraw and focuses the new copy.
  const FOCUS_KEYS = ['id', 'data-sev', 'data-task', 'data-k', 'data-f', 'data-copy', 'data-forget', 'data-action', 'data-detail', 'data-detail-retry'];
  function focusSel(el) {
    for (const k of FOCUS_KEYS) {
      const v = el.getAttribute && el.getAttribute(k);
      if (v && /^[\w-]+$/.test(v)) return k === 'id' ? '#' + v : '[' + k + '="' + v + '"]';
    }
    return null;
  }
  function keepFocus(scope, redraw) {
    const was = document.activeElement;
    const sel = was && was !== scope && scope.contains(was) ? focusSel(was) : null;
    let caret = null;
    try { if (sel && typeof was.selectionStart === 'number') caret = [was.selectionStart, was.selectionEnd, was.scrollTop]; } catch (e) { caret = null; }
    redraw();
    if (!sel || document.activeElement === was) return;
    const el = $(sel, scope);
    if (!el) return;
    el.focus({ preventScroll: true });
    if (caret) { try { el.setSelectionRange(caret[0], caret[1]); } catch (e) { /* not a text field */ } el.scrollTop = caret[2]; }
  }

  // The proof rules when a program publishes none of its own (the runner's rules, runner/README.md).
  const RULES = ['One file: contract HyblisPoC is HyblisBase, with setUp() and test_exploit()', 'Fork once in setUp(), at the pinned block, through HYBLIS_ETH_RPC',
    'Act only as accounts from makeAddr or makeAddrAndKey', 'Capital only through _fund(); separate transactions as step1() … stepN()',
    'Only the listed cheatcodes, checked call by call', 'Asserts and logs are ignored; the protocol is measured', 'The file must also pass in plain forge test'];

  // What happens to a report, shown beside the form and beside the launch notice.
  const TIMELINE = html`<ol class="timeline">
      <li class="on"><b>Received</b><span>Hash and time committed instantly</span></li><li><b>Policy screen</b><span>Seconds</span></li>
      <li><b>Reproduced twice</b><span>Verdict target under 1 hour</span></li><li><b>Validated</b><span>Shows on the public ledger</span></li>
      <li><b>Filed with the platform</b><span>Target within 12 hours</span></li><li><b>Accepted</b><span>Bonus paid in α through weights</span></li></ol>`;

  /* ---------- launch mode: intake opens at mainnet launch; nothing to sign until then ---------- */
  function launchNotice(root) {
    const tasks = H.data.cache.tasks, first = tasks.find((t) => t.status === 'featured') || tasks[0];
    const msg = H.data.intakeMessage();
    const NOW = [
      ['Read the programs', 'Scope, the impacts that count, trusted roles and the proof rules of every released program.', '#programs', 'Explore programs'],
      ['Prepare with hyblis check', 'Where a program offers it, download the runner\u2019s own check and run your proof on your machine, with the verdict the runner would give.', first ? '#program-' + first.task_id : '#programs', first ? first.label + ' program' : 'Program pages'],
      ['Follow the leaderboard', 'Scores come from the published policy, from the first validated finding on the public ledger.', '#leaderboard', 'Leaderboard'],
      ['See how a proof is checked', 'Six automatic checks, from the policy screen to duplicates. No human expert in the loop.', '#home', 'Validation', 'validation'],
    ];
    root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div class="eyebrow" data-scramble>Researchers</div>
  <h1 class="display">Submit a <span class="grad-text">report</span></h1>
  <p class="lede">One finding, one Foundry proof, signed with your hotkey. The earliest valid proof of a bug wins the credit.</p>
</div></section>
<section class="body"><div class="wrap cols">
  <div class="main">
    <div class="card launch-card" id="sb-launch">
      <div class="launch-top"><span class="launch-badge"><i></i>Not open yet</span><span class="label">Hyblis · Bittensor subnet</span></div>
      <h2 class="display h2" id="sb-launch-head" tabindex="-1" style="outline:none">${msg.replace(/\.$/, '')}</h2>
      <p class="lede">Reports are signed and validated automatically from the day the Hyblis subnet launches on mainnet. Until then no report can be sent, and everything you need to prepare is public.</p>
      <h3 class="label launch-now">What you can do now</h3>
      <ol class="launch-grid">${NOW.map((x, i) => html`<li><a class="launch-item spot" href="${x[2]}" ${x[4] ? H.raw('data-jump="' + x[4] + '"') : ''}>
        <b class="eyebrow">0${i + 1}</b><strong>${x[0]}</strong><span>${x[1]}</span><span class="link-arrow">${x[3]} ${H.icon('i-arrow', 14)}</span></a></li>`)}</ol>
    </div>
  </div>
  <aside class="side" aria-label="After launch"><div class="rail" style="display:flex;flex-direction:column;gap:16px">
    <div class="card"><div class="label">After launch, every report</div>${TIMELINE}</div>
    <div class="card"><div class="label">Signing</div><p class="muted" style="margin-top:12px;font-size:14px;line-height:1.6">From launch you sign each report with your miner hotkey (sr25519), in a Polkadot-compatible browser wallet or with the command-line miner. Hyblis never sees your keys.</p></div>
  </div></aside>
</div></section>`;
  }

  /* ================= submit ================= */
  H.pages.submit = {
    title: 'Submit a report — Hyblis',
    mount(root, ctx) {
      if (!H.data.intakeOpen()) {
        // Nothing is signed or sent while intake is closed; a draft kept in this browser stays as it is.
        launchNotice(root);
        // when intake opens, the page becomes the form without a reload
        return H.data.subscribe(() => { if (H.data.intakeOpen()) H.go(H.route ? H.route.hash || 'submit' : 'submit'); });
      }
      const draft = H.store.get('draft', {});
      const st = Object.assign({ step: 0, task: null, title: '', contract: '', fn: '', severity: '', description: '', poc: '', pocTouched: false, signed: null }, draft,
        { busy: false, error: null, reasons: null, result: null, pending: null, confirmDiscard: false });
      if (!(st.signed && st.signed.key && st.signed.env && st.signed.env.package)) st.signed = null;
      if (ctx.params[0]) {
        // A link to one program. Another program's draft restarts at the details step without its
        // contract and proof; a program that is not open for intake starts on the picker.
        const id = ctx.params[0], t = H.data.task(id);
        if (draft.task !== id) Object.assign(st, { task: id, step: 1, contract: '', poc: '', pocTouched: false, signed: null });
        if (!t || !t.open_for_intake) st.step = 0;
      }
      let prog = null, alive = true, shown = null;
      const offs = [];
      const fields = (a) => ({ task_id: st.task, hotkey: a, title: st.title, contract: st.contract, fn: st.fn, severity: st.severity, description: st.description, poc: st.poc });
      // The report as it would be signed (program, every field, signing account): the hash of its package with a fixed nonce and time.
      const keyOf = (a) => { try { return H.wallet.submissionId(H.wallet.buildPackage(Object.assign(fields(a), { nonce: '00'.repeat(16), ts: 1700000001 }))); } catch (e) { return null; } };
      const save = () => {
        if (st.signed && st.signed.key !== keyOf(st.signed.env.package.hotkey)) st.signed = null;   // a field changed after signing
        H.store.set('draft', { step: st.step, task: st.task, title: st.title, contract: st.contract, fn: st.fn, severity: st.severity, description: st.description, poc: st.poc, pocTouched: st.pocTouched, signed: st.signed });
      };
      const LABELS = ['Program', 'Details', 'Proof of concept', 'Review and sign'];

      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div class="eyebrow" data-scramble>Researchers</div>
  <h1 class="display">Submit a <span class="grad-text">report</span></h1>
  <p class="lede">One finding, one Foundry proof. You sign it with your hotkey and get a receipt with its hash and time, so the earliest valid proof always wins.</p>
  <ol class="steps" id="sb-steps" aria-label="Steps"></ol>
</div></section>
<section class="body"><div class="wrap cols">
  <form class="card form-card main" id="sb-form" novalidate></form>
  <aside class="side" aria-label="Summary"><div class="rail" style="display:flex;flex-direction:column;gap:16px">
    <div class="card"><div class="label">Your submission</div><div class="sum" id="sb-sum"></div></div>
    <div class="card"><div class="label">What happens next</div>${TIMELINE}</div>
  </div></aside>
</div></section>`;
      const form = $('#sb-form', root);
      form.addEventListener('submit', (e) => e.preventDefault());

      const task = () => H.data.task(st.task);
      const scope = () => (prog && prog.severity_scope) || (task() && task().severity_scope) || [];
      function problems() {
        const out = [];
        const t = task();
        if (!t || !t.open_for_intake) out.push(['program', 'Choose a program that is open for intake.']);
        if (!st.title.trim()) out.push(['title', 'Add a title.']); else if (st.title.trim().length > 160) out.push(['title', 'Keep the title under 160 characters.']);
        if (!ADDR.test(st.contract.trim())) out.push(['contract', 'Enter the affected contract address (0x followed by 40 hex characters).']);
        if (!st.fn.trim()) out.push(['fn', 'Name the function.']); else if (st.fn.trim().length > 120) out.push(['fn', 'Keep the function name under 120 characters.']);
        if (scope().indexOf(st.severity) < 0) out.push(['severity', 'Choose a severity this program accepts.']);
        if (!st.description.trim()) out.push(['description', 'Describe the finding.']); else if (st.description.trim().length > 4000) out.push(['description', 'Keep the description under 4,000 characters.']);
        if (!st.poc.trim()) out.push(['poc', 'Add the proof of concept.']);
        else if (H.wallet.utf8(st.poc).length > MAX_POC) out.push(['poc', 'The proof is larger than 256 KB.']);
        if (![st.title, st.fn, st.description, st.poc].every(H.wallet.isWellFormed)) out.push(['poc', 'The text contains characters that are not valid Unicode.']);
        return out;
      }

      // The exact package the Sign button sends. It is built once for the current fields and account,
      // so the message on the page is the one the wallet shows. A signed copy that is still kept
      // (its last send got no definite answer) is sent again instead.
      function prepared(a) {
        const key = keyOf(a);
        if (!key) return null;
        if (st.signed && st.signed.key === key) return { key, sid: st.signed.env.submission_id, env: st.signed.env };
        if (!st.pending || st.pending.key !== key) {
          const pkg = H.wallet.buildPackage(fields(a));
          st.pending = { key, pkg, sid: H.wallet.submissionId(pkg), builtAt: Date.now() };
        }
        return st.pending;
      }

      function drawSteps() {
        $('#sb-steps', root).innerHTML = LABELS.map((l, i) => html`<li class="step ${i === st.step ? 'on' : i < st.step ? 'done' : ''}" ${i === st.step ? H.raw('aria-current="step"') : ''}><b>${i < st.step ? H.icon('i-check', 13) : i + 1}</b>${l}</li>`).join('');
      }
      function drawSum() {
        const t = task(), a = H.wallet.state.address;
        $('#sb-sum', root).innerHTML = [['Program', t ? t.label : '—'], ['Severity', st.severity ? H.cap(st.severity) : '—'], ['Contract', ADDR.test(st.contract.trim()) ? H.short(st.contract.trim(), 8, 6) : '—'],
          ['Function', st.fn.trim() || '—'], ['Proof', st.poc.trim() ? st.poc.split('\n').length + ' lines' : '—'], ['Signed by', a ? H.short(a, 6, 5) : 'not connected']]
          .map((x) => html`<div><span class="muted">${x[0]}</span><b>${x[1]}</b></div>`).join('');
      }

      function stepProgram() {
        const tasks = H.data.cache.tasks;
        return html`<fieldset><legend class="display h3" id="sb-head" tabindex="-1" style="outline:none">Choose a program</legend><p class="muted" style="margin-top:-8px">Only programs open for intake can receive reports.</p>
          <div style="display:flex;flex-direction:column;gap:12px">${tasks.length ? tasks.map((t) => html`<button class="pick ${st.task === t.task_id ? 'on' : ''}" type="button" data-task="${t.task_id}" ${t.open_for_intake ? '' : H.raw('disabled')} aria-pressed="${st.task === t.task_id ? 'true' : 'false'}">
            <span class="logo-tile">${t.label.charAt(0)}</span><span class="txt"><b>${t.label}</b><span>${t.open_for_intake ? t.severity_scope.map(H.cap).join(' · ') + ' · PoC required' : 'Opens after scope verification'}</span></span>
            <span class="tag ${t.open_for_intake ? 'tag-ok' : ''}">${t.open_for_intake ? 'Open' : 'Soon'}</span></button>`)
            : H.data.loaded() ? html`<div class="tbl-empty"><b>No program is open yet</b>The first program is being verified.</div>` : H.ui.loadFail('the programs')}</div></fieldset>`;
      }
      function stepDetails() {
        const assets = (prog && prog.assets) || [];
        return html`<fieldset><legend class="display h3" id="sb-head" tabindex="-1" style="outline:none">Describe the finding</legend>
          <div class="field"><label for="f-title">Title</label><input class="input" id="f-title" data-k="title" type="text" maxlength="160" value="${st.title}" placeholder="Short and specific: what breaks, and where"></div>
          <div class="form-row">
            <div class="field" style="flex:2 1 300px"><label for="f-contract">Affected contract</label><input class="input mono" id="f-contract" data-k="contract" type="text" list="f-assets" value="${st.contract}" placeholder="0x…" autocomplete="off" spellcheck="false">
              <datalist id="f-assets">${assets.map((a) => html`<option value="${a.address}">${a.name}</option>`)}</datalist>${assets.length ? html`<span class="hint">Pick one of the ${assets.length} in-scope contracts or paste an address.</span>` : ''}</div>
            <div class="field"><label for="f-fn">Function</label><input class="input mono" id="f-fn" data-k="fn" type="text" maxlength="120" value="${st.fn}" placeholder="borrow" autocomplete="off" spellcheck="false"></div>
          </div>
          <div class="field" role="radiogroup" aria-label="Claimed severity"><span class="lbl">Claimed severity</span>
            <div class="seg">${H.SEV.map((s) => html`<button type="button" role="radio" data-sev="${s}" aria-checked="${st.severity === s ? 'true' : 'false'}" class="${st.severity === s ? 'on' : ''}" ${scope().indexOf(s) >= 0 ? '' : H.raw('disabled title="Not accepted for this program"')}>${s.toUpperCase()}</button>`)}</div>
            <span class="hint">Final severity is the lower of your claim and the measured impact.</span></div>
          <div class="field"><label for="f-desc">Description</label><textarea class="textarea" id="f-desc" data-k="description" rows="6" maxlength="4000" placeholder="Root cause, attack path and impact. Keep it short; the proof carries the detail.">${st.description}</textarea></div></fieldset>`;
      }
      function stepPoc() {
        const rules = (prog && prog.poc_rules && prog.poc_rules.length ? prog.poc_rules : RULES);
        return html`<fieldset><legend class="display h3" id="sb-head" tabindex="-1" style="outline:none">Proof of concept</legend><p class="muted" style="margin-top:-8px">One Foundry test file, built on HyblisBase.sol. Start from the program template; it forks mainnet at the pinned block. Run hyblis check first: it gives you the runner's verdict on your own machine.${st.task ? html` <a class="link-arrow" href="#program-${st.task}">Template and check tool ${H.icon('i-arrow', 14)}</a>` : ''}</p>
          <div class="code"><div class="code-bar"><label for="f-poc">HyblisPoC.t.sol</label><span style="display:flex;gap:8px;align-items:center"><span id="poc-lines"></span>
            <button class="iconbtn" type="button" id="poc-reset">Reset to template</button><label class="iconbtn" style="cursor:pointer">Upload .sol<input type="file" id="poc-file" accept=".sol,text/plain" class="sr-only"></label></span></div>
            <textarea id="f-poc" data-k="poc" rows="18" spellcheck="false" autocapitalize="off" autocomplete="off">${st.poc}</textarea></div>
          <ul class="checks">${rules.map((r) => html`<li>${H.icon('i-check', 15)}${r}</li>`)}</ul></fieldset>`;
      }
      function stepReview(ready) {
        const t = task(), bad = problems(), a = H.wallet.state.address, miss = {}; bad.forEach((b) => { miss[b[0]] = b[1]; });
        if (st.result) {
          const r = st.result;
          return html`<div style="display:flex;flex-direction:column;gap:20px"><h2 class="display h3" id="sb-head" tabindex="-1" style="outline:none">Report received</h2>
            <div class="notice ok" role="status">${H.icon('i-check', 18)}<span>${r.replayed ? 'Your report is on the ledger. It had already reached the gateway, so it was filed only once.' : 'Your report is on the ledger. Its hash and time are committed, so the earliest valid proof of this bug is yours.'}</span></div>
            <dl class="review card">
              <div><dt class="label">Hash</dt><dd class="mono" style="font-size:12.5px">${r.submission_id}</dd></div>
              <div><dt class="label">Received</dt><dd>${H.dateTime(r.received_at)}</dd></div>
              <div><dt class="label">Status</dt><dd>${H.status(r.status)}</dd></div>
              <div><dt class="label">Receipt token</dt><dd style="display:flex;flex-wrap:wrap;align-items:center;gap:10px"><span class="mono" id="sb-token" style="font-size:12.5px">${r.receipt_token}</span><button class="iconbtn" type="button" data-copy="${r.receipt_token}" data-copied="Receipt token copied" aria-label="Copy the receipt token">${H.icon('i-copy', 14)}Copy</button></dd></div></dl>
            ${H.cfg.demo ? html`<p class="faint" style="font-size:13.5px">Design preview: nothing was sent. The report now walks through the pipeline so you can follow it in the dashboard.</p>`
              : html`<p class="faint" style="font-size:13.5px">The dashboard follows this report by its public hash. The receipt token lets you fetch the gateway’s signed receipt later, as proof of when the report arrived: <span class="mono">${(H.cfg.apiBase || location.origin) + '/api/receipt/<token>'}</span>. Keep the token private.</p>`}
            <div class="form-nav"><button class="btn btn-ghost" type="button" id="sb-again">Submit another</button><a class="btn btn-grad" href="#dashboard">Track it in your dashboard</a></div></div>`;
        }
        const rows = [['Program', t ? t.label : '', miss.program], ['Title', st.title.trim(), miss.title], ['Contract', st.contract.trim(), miss.contract], ['Function', st.fn.trim(), miss.fn],
          ['Severity', st.severity ? st.severity.toUpperCase() : '', miss.severity], ['Description', st.description.trim() ? H.short(st.description.trim(), 120, 0) : '', miss.description],
          ['Proof', st.poc.trim() ? 'HyblisPoC.t.sol · ' + st.poc.split('\n').length + ' lines' : '', miss.poc]];
        return html`<div style="display:flex;flex-direction:column;gap:20px"><h2 class="display h3" id="sb-head" tabindex="-1" style="outline:none">Review and sign</h2>
          <dl class="review card">${rows.map((r) => html`<div><dt class="label">${r[0]}</dt><dd class="${r[2] ? 'bad' : ''}">${r[2] ? r[2] : r[1]}</dd></div>`)}</dl>
          ${a ? html`<div class="signbox"><div class="label">Signing account</div><div class="who" style="margin-top:10px">${H.identicon(a, 28)}<span class="mono">${H.short(a, 12, 10)}</span>${st.busy ? '' : html`<button class="iconbtn" type="button" id="sb-change" data-action="wallet">Change</button>`}</div>
              <div class="label" style="margin-top:16px">${ready && ready.env ? 'Your wallet signed this message' : 'Your wallet will show this message'}</div><code id="sb-msg">${ready ? H.wallet.message(ready.sid) : 'hyblis-submit:v1:<hash of this report>'}</code>
              <p class="faint" style="margin-top:10px;font-size:13px">${ready && ready.env ? 'This report is already signed. Sending it again uses the same signed copy, so it cannot be filed twice.' : 'The hash covers every field above, so nothing can be changed after you sign. Check that your wallet shows this exact message.'}</p></div>`
            : html`<div class="notice info">${H.icon('i-wallet', 18)}<span>Connect the wallet that holds your miner hotkey to sign this report. Hyblis never sees your keys.</span></div>`}
          ${st.error ? html`<div class="notice" role="alert">${H.icon('i-x', 18)}<span>${st.error}${st.reasons && st.reasons.length ? html`<ul style="margin:8px 0 0;padding-left:18px">${st.reasons.map((x) => html`<li>${x}</li>`)}</ul>` : ''}</span></div>` : ''}
          <details class="faint" style="font-size:14px"><summary style="cursor:pointer;color:var(--muted)">Sign from the terminal instead</summary>
            <div class="code" style="margin-top:12px"><pre><code>${cli()}</code></pre></div></details></div>`;
      }
      function cli() {
        const q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
        return 'python miner/hyblis_miner.py --gateway ' + (H.cfg.apiBase || location.origin) + ' submit \\\n  --task ' + (st.task || '<task>') + ' --poc HyblisPoC.t.sol \\\n  --title ' + q(st.title.trim() || '<title>') + ' \\\n  --contract ' + q(st.contract.trim() || '0x…') + ' --function ' + q(st.fn.trim() || '<function>') + ' \\\n  --severity ' + (st.severity || 'medium') + ' --desc ' + q(st.description.trim() || '<description>') + ' \\\n  --wallet <wallet> --hotkey <hotkey>';
      }
      function discardCtl() {
        if (st.busy || !(st.title.trim() || st.contract.trim() || st.fn.trim() || st.description.trim() || st.pocTouched || st.signed)) return '';
        return st.confirmDiscard
          ? html`<span role="group" aria-label="Discard draft" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center"><span class="muted" style="font-size:14px">Delete this draft from this browser?</span>
            <button class="iconbtn" type="button" id="sb-discard-yes">Discard</button><button class="iconbtn" type="button" id="sb-discard-no">Keep</button></span>`
          : html`<button class="iconbtn" type="button" id="sb-discard">Discard draft</button>`;
      }

      function draw() {
        if (!alive) return;
        drawSteps(); drawSum();
        const last = st.step === 3, a = H.wallet.state.address;
        const ready = last && !st.result && a && !problems().length ? prepared(a) : null;
        const bodyHtml = [stepProgram, stepDetails, stepPoc, stepReview][st.step](ready);
        const label = st.busy === 'send' ? 'Sending…' : st.busy ? 'Waiting for your wallet…' : ready && ready.env ? 'Send the signed report again' : 'Sign with hotkey and submit';
        const render = () => {
          form.innerHTML = html`${bodyHtml}${st.result ? '' : html`<div class="form-nav">
          <span style="display:flex;flex-wrap:wrap;gap:12px;align-items:center"><button class="btn btn-ghost" type="button" id="sb-back" ${st.step === 0 || st.busy ? H.raw('disabled') : ''}>Back</button>${discardCtl()}</span>
          ${!last ? html`<button class="btn btn-grad" type="button" id="sb-next">Continue</button>`
            : a ? html`<button class="btn btn-grad ${st.busy ? 'is-disabled' : ''}" type="button" id="sb-sign" ${st.busy ? H.raw('aria-disabled="true"') : problems().length ? H.raw('disabled') : ''}>${label}</button>`
              : html`<button class="btn btn-grad" type="button" id="sb-connect">${H.icon('i-wallet', 16)}Connect wallet</button>`}</div>`}`;
        };
        // a new step (or the receipt) takes focus on its heading; any other redraw keeps the focused control
        const view = st.result ? 'done' : st.step, moved = shown !== null && shown !== view;
        shown = view;
        if (moved) { render(); const h = $('#sb-head', form); if (h) h.focus({ preventScroll: true }); } else keepFocus(form, render);
        const pl = $('#poc-lines', form); if (pl) pl.textContent = st.poc.split('\n').length + ' lines';
        const v = $('#view'); if (v) v.setAttribute('data-step', st.step);
      }

      async function loadProgram() {
        prog = null;
        if (!st.task) return;
        const want = st.task;
        let p = null;
        try { p = await H.data.program(want); }
        catch (e) { if (alive && st.task === want) H.toast('Could not load this program’s details. Check your connection, then reload the page.', 'bad'); }
        if (!alive || st.task !== want) return;   // another program was picked meanwhile
        prog = p;
        if (p) {
          if (!st.pocTouched && p.poc_template) st.poc = p.poc_template;
          if (p.severity_scope.indexOf(st.severity) < 0) st.severity = p.severity_scope[0] || '';
        }
        save(); draw();
      }

      // What to tell the researcher when signing or sending did not work.
      function failText(e) {
        const m = String((e && e.message) || '');
        if (e && e.status >= 500) return 'The gateway had a problem (HTTP ' + e.status + '). Try again in a moment.';
        if (/ts too far from server time/i.test(m)) return "Your computer's clock is more than a day off. Set the correct time, then sign again.";
        if (/contract is not in scope/i.test(m)) return 'That contract is not in this program’s scope. Go back, choose one of the in-scope contracts, then sign again.';
        if (/hotkey must be a Bittensor address/i.test(m)) return "This account is not in the Bittensor address format. In the extension, set the account's network to Bittensor or Substrate (generic), then connect again.";
        if (/severity must be one of/i.test(m)) return 'This program does not accept that severity. Go back, choose another one, then sign again.';
        return m || 'Something went wrong. Nothing was sent.';
      }

      async function sign() {
        const a = H.wallet.state.address; if (!a || st.busy) return;
        if (problems().length) { draw(); return; }
        st.confirmDiscard = false;
        if (st.signed && Math.abs(Date.now() / 1000 - st.signed.env.package.ts) > SIGNED_TTL) { st.signed = null; save(); }
        if (st.pending && Math.abs(Date.now() - st.pending.builtAt) > PREPARED_TTL) st.pending = null;   // rebuilt below; the redraw shows its message
        const p = prepared(a);
        if (!p) { st.error = 'Something went wrong. Nothing was sent.'; draw(); return; }
        let env = p.env || null;
        st.busy = env ? 'send' : 'wallet'; st.error = null; st.reasons = null; draw();
        try {
          if (!env) {
            let sig;
            try { sig = await H.wallet.sign(a, H.wallet.message(p.sid)); }
            catch (e) { if (!alive) return; throw new Error(/cancel|reject|denied/i.test(String(e && e.message)) ? 'The signature was cancelled in the wallet. Nothing was sent.' : 'The wallet could not sign: ' + (e && e.message ? e.message : 'unknown error')); }
            if (!alive) return;
            if (H.wallet.state.address !== a) throw new Error('The signing account changed while the wallet was open. Nothing was sent.');
            env = { package: p.pkg, sig: sig, sig_scheme: H.wallet.SCHEME, submission_id: p.sid };
            // Kept (also in the draft) until the gateway answers, so a retry after a lost answer resends
            // this same signed copy: the gateway then returns the stored receipt instead of filing it twice.
            st.signed = { key: p.key, env: env }; save();
            st.busy = 'send'; draw();
          }
          let res;
          try { res = await H.data.submit(env); }
          catch (e) {
            if (!alive) return;
            // A refusal (4xx other than the rate limit) is final for this copy. After a network error,
            // a 5xx or a rate limit it may still arrive, so it is kept for the next try.
            if (e && e.status >= 400 && e.status < 500 && e.status !== 429) { st.signed = null; st.pending = null; save(); }
            throw e;
          }
          if (!alive) return;
          const pkg = env.package, t = H.data.task(pkg.task_id);
          st.signed = null; st.busy = false;
          H.data.receipts.add({ id: res.submission_id, token: res.receipt_token, task_id: pkg.task_id, label: t ? t.label : pkg.task_id, title: pkg.header.title, severity: pkg.header.severity, hotkey: pkg.hotkey, t: res.received_at, status: res.status, history: [{ status: res.status, at: res.received_at }] });
          if (res.status === 'rejected') {
            // Listed in the dashboard, but the draft stays and the review step shows why, so the proof can be fixed and signed again.
            // "policy" comes with every rejection by the intake screen, also on a replay; without it, a replay was rejected later.
            const policy = Array.isArray(res.policy) ? res.policy : null;
            st.error = policy || !res.replayed ? 'The automatic policy screen rejected this proof, so it will not be reproduced. Fix the proof and sign again.'
              : 'This report was already received, and it was rejected. Fix the proof and sign again.';
            st.reasons = (policy || []).filter((x) => x && x.reason).map((x) => String(x.reason) + (x.line != null ? ' (line ' + x.line + ')' : ''));
            save();
          } else {
            st.result = res; st.pending = null;
            H.store.del('draft');
            H.toast('Report received', 'ok');
            if (H.sceneCtl) H.sceneCtl.pulse();
          }
        } catch (e) { st.busy = false; st.error = failText(e); }
        draw();
      }

      offs.push(H.on(form, 'click', '[data-task]', (e, b) => { if (b.disabled) return; if (st.task !== b.dataset.task) { st.task = b.dataset.task; st.pocTouched = false; st.poc = ''; st.contract = ''; } save(); draw(); loadProgram(); }));
      offs.push(H.on(form, 'click', '[data-sev]', (e, b) => { if (b.disabled) return; st.severity = b.dataset.sev; save(); draw(); }));
      offs.push(H.on(form, 'input', '[data-k]', (e, el) => { st[el.dataset.k] = el.value; if (el.dataset.k === 'poc') { st.pocTouched = true; const pl = $('#poc-lines', form); if (pl) pl.textContent = st.poc.split('\n').length + ' lines'; } save(); drawSum(); }));
      offs.push(H.on(form, 'click', '#sb-next', () => {
        if (st.step === 0 && !(task() && task().open_for_intake)) { H.toast('Choose a program that is open for intake', 'bad'); return; }
        st.step = Math.min(3, st.step + 1); st.error = null; st.reasons = null; st.confirmDiscard = false; save(); draw(); window.scrollTo({ top: 0, behavior: H.reduced ? 'auto' : 'smooth' });
      }));
      offs.push(H.on(form, 'click', '#sb-back', () => { if (st.busy) return; st.step = Math.max(0, st.step - 1); st.error = null; st.reasons = null; st.confirmDiscard = false; save(); draw(); }));
      offs.push(H.on(form, 'click', '#sb-connect', () => H.ui.walletDialog()));
      offs.push(H.on(form, 'click', '#sb-sign', sign));
      offs.push(H.on(form, 'click', '#sb-again', () => { Object.assign(st, { step: 0, title: '', contract: '', fn: '', description: '', poc: prog && prog.poc_template ? prog.poc_template : '', pocTouched: false, result: null, error: null, reasons: null, signed: null, pending: null }); save(); draw(); }));
      offs.push(H.on(form, 'click', '#sb-discard', () => { st.confirmDiscard = true; draw(); const b = $('#sb-discard-no', form); if (b) b.focus(); }));
      offs.push(H.on(form, 'click', '#sb-discard-no', () => { st.confirmDiscard = false; draw(); const b = $('#sb-discard', form); if (b) b.focus(); }));
      offs.push(H.on(form, 'click', '#sb-discard-yes', () => {
        // clears the form, the stored draft and any kept signed copy; the chosen program stays selected
        Object.assign(st, { step: 0, title: '', contract: '', fn: '', severity: scope()[0] || '', description: '', poc: prog && prog.poc_template ? prog.poc_template : '', pocTouched: false,
          signed: null, pending: null, error: null, reasons: null, confirmDiscard: false });
        H.store.del('draft');
        draw(); const h = $('#sb-head', form); if (h) h.focus({ preventScroll: true });
        H.toast('Draft discarded');
      }));
      offs.push(H.on(form, 'click', '#poc-reset', () => { if (prog && prog.poc_template) { st.poc = prog.poc_template; st.pocTouched = false; save(); draw(); } else H.toast('This program has no template yet'); }));
      offs.push(H.on(form, 'change', '#poc-file', (e, inp) => {
        const f = inp.files && inp.files[0]; if (!f) return;
        if (f.size > MAX_POC) { H.toast('That file is larger than 256 KB', 'bad'); return; }
        const rd = new FileReader();
        rd.onload = () => { st.poc = String(rd.result || ''); st.pocTouched = true; save(); draw(); H.toast('Loaded ' + f.name, 'ok'); };
        rd.onerror = () => H.toast('The file could not be read', 'bad');
        rd.readAsText(f);
      }));
      offs.push(H.wallet.onChange(() => {
        const a = H.wallet.state.address;
        if (st.signed && a && a !== st.signed.env.package.hotkey) { st.signed = null; save(); }   // the kept signed copy belongs to the previous account
        if (st.step === 3) draw(); else drawSum();
      }));
      offs.push(H.data.subscribe(() => { if (st.step === 0 && !st.busy) draw(); }));

      if (!st.task) { const first = H.data.cache.tasks.find((t) => t.open_for_intake); if (first) st.task = first.task_id; }
      draw(); loadProgram();
      return () => { alive = false; offs.forEach((fn) => fn()); };
    },
  };

  /* ================= dashboard ================= */
  H.pages.dashboard = {
    title: 'Dashboard — Hyblis',
    mount(root) {
      let filter = 'all', alive = true;
      // Results come from the visitor's own receipts (the secret token kept in this browser), one fetch
      // per report and status. details[id] = { key, state: loading|ok|gone|notoken|error, result, at }.
      const details = {}, opened = new Set();
      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:20px">
    <div><div class="eyebrow" data-scramble>Dashboard</div><h1 class="display">Your <span class="grad-text">reports</span></h1></div>
    <div id="db-wallet"></div></div>
  <div class="dash-cards" id="db-cards"></div>
</div></section>
<section class="body"><div class="wrap cols">
  <div class="main" style="display:flex;flex-direction:column;gap:30px">
    <div><h2 class="h4">Pipeline</h2><ol class="card pipeline" id="db-pipe"></ol></div>
    <div><div class="toolbar" style="justify-content:space-between;margin-bottom:14px"><h2 class="h4" id="db-reports" tabindex="-1" style="outline:none">Reports from this browser</h2>
        <div class="chips" role="group" aria-label="Filter">${[['all', 'All'], ['open', 'Open'], ['closed', 'Closed']].map((x) => html`<button class="chip ${x[0] === 'all' ? 'on' : ''}" type="button" data-f="${x[0]}" aria-pressed="${x[0] === 'all' ? 'true' : 'false'}">${x[1]}</button>`)}</div></div>
      <div class="tbl-wrap"><table class="tbl" style="min-width:760px"><thead><tr><th>Report</th><th>Program</th><th>Severity</th><th>Status</th><th>Next</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody id="db-body"></tbody></table></div>
      <p class="faint" style="margin-top:12px;font-size:13px">Reports sent from the terminal or another browser are not listed here. <button class="addr" type="button" data-action="lookup" style="color:var(--muted);text-decoration:underline">Look one up by its hash.</button></p></div>
    <div id="db-credited"></div>
  </div>
  <aside class="side" aria-label="Payouts and activity">
    <div class="card" style="padding:22px;border-color:#3a2333"><div class="label">Payouts</div><div class="display" style="font-size:26px;text-transform:none;margin-top:10px" id="db-settle">—</div>
      <p class="muted" style="margin-top:12px;font-size:14px;line-height:1.6">Rewards are paid in α through the subnet’s weights every epoch (about 72 minutes), straight to the hotkey that signed the report: from validation, with a bonus once the program accepts.</p></div>
    <div class="card" style="padding:20px 22px"><div class="label">Activity</div><ul class="notes" id="db-notes"></ul></div>
  </aside>
</div></section>`;

      function sync() {
        // follow each local report on the public ledger and remember its status changes
        const byHash = {}; H.data.cache.ledger.forEach((r) => { byHash[r.hash] = r; });
        H.data.receipts.all().forEach((r) => {
          const live = byHash[r.id];
          if (live && live.status !== r.status) {
            const hist = (r.history || []).concat([{ status: live.status, at: Math.floor(Date.now() / 1000) }]).slice(-12);
            H.data.receipts.update(r.id, { status: live.status, severity: live.severity, history: hist });
          }
        });
      }
      // Fetch a report's result when it is decided (again when its status changes). A report the public
      // ledger shows as reproducing is checked once a minute: it may be waiting for the runner.
      function loadDetail(r, force) {
        const key = r.status + '|' + (r.token || ''), d = details[r.id];
        if (d && d.state === 'loading') return;
        if (!force && d && d.key === key && !(r.status === 'reproducing' && Date.now() - d.at > 60000)) return;
        if (!r.token) { details[r.id] = { key, state: 'notoken', at: Date.now() }; return; }
        details[r.id] = { key, state: 'loading', at: Date.now(), result: d ? d.result : null };
        const was = JSON.stringify(d ? [d.state, d.result] : null);
        H.data.receipt(r.token).then((rc) => ({ key, state: rc ? 'ok' : 'gone', result: rc ? rc.result || null : null, at: Date.now() }),
          () => ({ key, state: 'error', result: null, at: Date.now() })).then((nd) => {
          details[r.id] = nd;
          if (alive && (force || JSON.stringify([nd.state, nd.result]) !== was)) draw();
        });
      }
      function loadDetails() {
        H.data.receipts.all().forEach((r) => { if (DECIDED.indexOf(r.status) >= 0 || r.status === 'reproducing') loadDetail(r); });
      }
      function waiting(r) {
        const d = details[r.id];
        return r.status === 'reproducing' && !!d && !!d.result && d.result.status === 'waiting';
      }
      function detailPanel(r) {
        const d = details[r.id];
        if (!d || d.state === 'loading') return html`<p class="muted">Loading the result…</p>`;
        if (d.state === 'notoken') return html`<p class="muted">This browser has no receipt token for this report, so its result cannot be loaded. The status shown is the public one.</p>`;
        if (d.state === 'gone') return html`<p class="muted">The gateway has no receipt for the token kept in this browser (an old or reset token), so the result cannot be shown. The status shown is still current.</p>`;
        if (d.state === 'error') return html`<p class="muted">Could not load the result. <button class="iconbtn" type="button" data-detail-retry="${r.id}">Try again</button></p>`;
        const res = d.result;
        if (!res || res.status === 'waiting') return html`<p class="muted">No result yet. It shows here once the report is decided.</p>`;
        const rejected = res.status === 'rejected';
        return html`<div class="dres">
          ${res.error ? html`<div class="dres-head"><span class="label">${rejected ? 'Why it was rejected' : 'Outcome'}</span><code class="dres-code">${res.error}</code></div><p class="dres-why">${res.explanation}</p>` : ''}
          ${res.detail ? html`<p class="dres-note"><span class="label">Runner note</span><span>${res.detail}</span></p>` : ''}
          ${res.policy && res.policy.length ? html`<ul class="dres-lines" aria-label="Lines of your proof">${res.policy.map((x) => html`<li><b>${x.line != null ? 'Line ' + x.line : 'File'}</b><span>${x.reason}</span></li>`)}</ul>` : ''}
          ${res.impact_type ? html`<dl class="dres-kv"><div><dt class="label">Measured impact</dt><dd>${H.impactLabel(res.impact_type)}</dd></div>
            <div><dt class="label">Measured severity</dt><dd>${res.measured_severity ? H.sev(res.measured_severity) : '—'}</dd></div>
            <div><dt class="label">Changed function</dt><dd class="mono">${res.changed_function || '—'}</dd></div></dl>` : ''}
          ${rejected ? html`<p class="faint dres-tip">Fix the proof, run hyblis check from the ${r.task_id ? html`<a href="#program-${r.task_id}">program page</a>` : 'program page'}, then submit it again.</p>` : ''}</div>`;
      }

      function draw() {
        sync();
        loadDetails();
        const list = H.data.receipts.all(), s = H.data.cache.summary, a = H.wallet.state.address, shut = !!s && !H.data.intakeOpen();
        const count = (arr) => list.filter((r) => arr.indexOf(r.status) >= 0).length;
        keepFocus(root, () => {
          $('#db-wallet', root).innerHTML = a ? html`<button class="iconbtn" type="button" data-action="wallet">${H.identicon(a, 20)}<span class="mono">${H.short(a, 8, 6)}</span></button>`
            : html`<button class="btn btn-ghost" type="button" data-action="wallet">${H.icon('i-wallet', 16)}Connect wallet</button>`;
          $('#db-cards', root).innerHTML = [['Reports', list.length, 'Sent from this browser'], ['In progress', count(OPEN), 'Being checked or under review'],
            ['Accepted', count(['accepted']), 'By the bounty platform'], ['Paid out', 'On chain', 'Each epoch, through the subnet’s weights']]
            .map((x) => html`<div class="card"><span class="label">${x[0]}</span><b>${x[1]}</b><span class="muted" style="font-size:13px">${x[2]}</span></div>`).join('');
          $('#db-pipe', root).innerHTML = [['Screening', ['received', 'screening']], ['Reproducing', ['reproducing']], ['Validated', ['validated']], ['Under review', ['under_review']], ['Accepted', ['accepted']], ['Closed', ['duplicate', 'rejected', 'expired']]]
            .map((x) => { const n = count(x[1]); return html`<li><span class="label">${x[0]}</span><b style="${n ? '' : 'color:var(--faint)'}">${n}</b></li>`; }).join('');
          const rows = list.filter((r) => filter === 'all' || (filter === 'open') === (OPEN.indexOf(r.status) >= 0));
          $('#db-body', root).innerHTML = rows.length ? rows.map((r) => {
            const can = DECIDED.indexOf(r.status) >= 0, open = can && opened.has(r.id), pid = 'dd-' + r.id.slice(0, 16);
            return html`<tr class="${open ? 'is-open' : ''}" data-row="${r.id}">
              <td><div style="font-weight:600">${r.title}${r.sample ? html` <span class="tag">Sample</span>` : ''}</div><div class="mono faint" style="font-size:12.5px;margin-top:4px">${H.short(r.id, 12, 0)} · ${H.date(r.t)}</div></td>
              <td class="muted">${r.label}</td><td>${H.sev(r.severity)}</td><td>${H.status(r.status)}</td><td class="muted" style="font-size:13.5px">${waiting(r) ? 'Waiting for the runner' : NEXT[r.status] || ''}${can ? html`<div style="margin-top:8px"><button class="iconbtn db-why" type="button" data-detail="${r.id}" aria-expanded="${open ? 'true' : 'false'}" aria-controls="${pid}">${r.status === 'rejected' ? 'Why?' : 'Result'}</button></div>` : ''}</td>
              <td class="r" style="white-space:nowrap"><button class="iconbtn" type="button" data-copy="${r.id}" data-copied="Hash copied" aria-label="Copy the hash">${H.icon('i-copy', 14)}</button>${r.sample ? '' : html` <button class="iconbtn" type="button" data-forget="${r.id}" aria-label="Remove from this browser">${H.icon('i-x', 14)}</button>`}</td></tr>
              ${open ? html`<tr class="db-detail" id="${pid}"><td colspan="6">${detailPanel(r)}</td></tr>` : ''}`;
          }).join('')
            : String(html`<tr><td colspan="6"><div class="empty"><div class="display h3">${list.length ? 'Nothing in this view' : 'No reports yet'}</div><p>${list.length ? 'Switch the filter to see your other reports.' : shut ? 'Intake opens at mainnet launch. From then on, reports you sign in this browser appear here and update as they move through validation.' : 'Reports you sign in this browser appear here and update as they move through validation.'}</p>${list.length ? '' : shut ? html`<a class="btn btn-grad" href="#programs" id="db-programs">Read the programs</a>` : html`<a class="btn btn-grad" href="#submit" id="db-submit">Submit a report</a>`}</div></td></tr>`);
          const cred = a ? H.data.findings(a) : [];
          $('#db-credited', root).innerHTML = a ? html`<div class="toolbar" style="justify-content:space-between;margin-bottom:14px"><h2 class="h4">Credited to ${H.short(a, 6, 5)}</h2><a class="link-arrow" href="#researcher-${a}" id="db-profile">Public profile ${H.icon('i-arrow', 14)}</a></div>
            <div class="tbl-wrap"><table class="tbl" style="min-width:560px"><thead><tr><th>Submission</th><th>Severity</th><th>Received</th><th>Status</th></tr></thead><tbody>
            ${cred.length ? cred.map((f) => html`<tr><td class="mono" style="font-size:13.5px">${f.id}</td><td>${H.sev(f.severity)}</td><td class="num muted">${H.date(f.t)}</td><td>${H.status(f.status)}</td></tr>`) : html`<tr><td colspan="4"><div class="tbl-empty">No credited findings for this hotkey yet.</div></td></tr>`}</tbody></table></div>` : '';
        });
        $('#db-settle', root).textContent = shut ? 'After launch' : 'Every epoch';
        const notes = [];
        list.forEach((r) => (r.history || []).forEach((h) => notes.push({ at: h.at, text: 'Report ' + H.short(r.id, 8, 0) + ' is ' + H.statusLabel(h.status).toLowerCase() + '.' })));
        if (shut) notes.push({ at: 0, text: H.data.intakeMessage(), fixed: true });
        else if (s && s.releases && s.releases.next_release_on) notes.push({ at: 0, text: 'The next program opens on ' + H.date(s.releases.next_release_on) + '.', fixed: true });
        notes.sort((x, y) => y.at - x.at);
        $('#db-notes', root).innerHTML = notes.length ? notes.slice(0, 7).map((n) => html`<li><i style="${n.fixed ? 'background:var(--faint)' : ''}"></i><span>${n.text}${n.fixed ? '' : H.timeAgo(n.at)}</span></li>`).join('') : String(html`<li><i style="background:var(--faint)"></i><span class="muted">Status changes will show here.</span></li>`);
      }
      // every poll: a reproducing report may now be waiting for the runner (redraws only on a change)
      const offs = [H.data.subscribe(draw), H.wallet.onChange(draw), H.data.subscribe(loadDetails, { always: true })];
      offs.push(H.on(root, 'click', '[data-detail]', (e, b) => {
        const id = b.dataset.detail;
        if (opened.has(id)) opened.delete(id); else opened.add(id);
        draw();
      }));
      offs.push(H.on(root, 'click', '[data-detail-retry]', (e, b) => {
        const r = H.data.receipts.all().find((x) => x.id === b.dataset.detailRetry);
        if (r) { loadDetail(r, true); draw(); }
      }));
      offs.push(H.on(root, 'click', '[data-f]', (e, b) => { filter = b.dataset.f; $$('[data-f]', root).forEach((x) => { const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-pressed', on); }); draw(); }));
      offs.push(H.on(root, 'click', '[data-forget]', (e, b) => {
        const had = document.activeElement === b, i = $$('[data-forget]', root).indexOf(b);
        opened.delete(b.dataset.forget); H.data.receipts.remove(b.dataset.forget); H.toast('Removed from this browser'); draw();
        // the removed row's button is gone: focus the row that took its place, or the list heading
        if (had) { const left = $$('[data-forget]', root); (left[Math.min(i, left.length - 1)] || $('#db-reports', root)).focus(); }
      }));
      draw();
      return () => { alive = false; offs.forEach((fn) => fn()); };
    },
  };
})();
