/* Hyblis site — programs list, program detail, competitions (featured windows). */
(function () {
  'use strict';
  const H = window.Hyblis, html = H.html, $ = H.$, $$ = H.$$;
  H.pages = H.pages || {};

  const PIPE = [
    ['Policy screen', 'Signature, file layout, scope and a static check for forbidden cheatcodes.'],
    ['Isolated rerun', 'A sandbox on the pinned fork runs your proof twice, then once as plain forge test. The runs must agree.'],
    ['Measured impact', 'Every cheatcode call is checked in Foundry\u2019s own trace. Impact is measured against a clean copy of the same block. Your asserts are ignored.'],
    ['Program rules', 'Impact type, known issues and benign entry points are checked automatically.'],
    ['Severity', 'The lower of your claimed severity and the measured impact.'],
    ['Duplicates', 'Same contract, function and impact type: the earliest valid proof wins.'],
  ];
  const kb = (n) => Math.max(1, Math.round((+n || 0) / 1024)) + ' KB';
  function codeBlock(name, text, copied) {
    return html`<div class="code"><div class="code-bar"><span>${name}</span><button class="iconbtn" type="button" data-copy="${text}" data-copied="${copied}" aria-label="Copy ${name}">${H.icon('i-copy', 13)}Copy</button></div><pre><code>${text}</code></pre></div>`;
  }
  // The hyblis check download (a real file on the live site; the preview has no files to serve).
  function checkDownload(p) {
    const ct = p.check_tool;
    if (!ct) return html`<p class="muted" id="check-none">The check tool for this program is published here once its impact spec is verified, together with the runner rules it uses.</p>`;
    const btn = H.cfg.demo
      ? html`<button class="btn btn-grad" type="button" data-demo-download="${ct.file}">${H.icon('i-down', 16)}Download hyblis check · ${kb(ct.bytes)}</button>`
      : html`<a class="btn btn-grad" href="${ct.path}" download="${ct.file}" id="check-dl">${H.icon('i-down', 16)}Download hyblis check · ${kb(ct.bytes)}</a>`;
    return html`<div class="dl-row">${btn}<span class="mono faint dl-sum">${ct.file} · sha256 <button class="addr" type="button" data-copy="${ct.sha256}" data-copied="Checksum copied">${H.short(ct.sha256, 12, 8)}${H.icon('i-copy', 13)}</button></span></div>`;
  }
  function checkCommands(p) {
    const id = p.task_id;
    return 'tar xzf hyblis-check-' + id + '.tar.gz && cd hyblis-check-' + id + '\n' +
      'python3 runner/check.py --task ' + id + ' --poc /path/to/HyblisPoC.t.sol \\\n' +
      '    --project /path/to/the/program/project --rpc <your RPC URL or IPC path>';
  }
  const CONDUCT = ['Test only on your own local fork, never against a live network', 'Do not disclose a finding until it is fixed, paid and cleared', 'One account per researcher', 'Submit only your own work'];

  // launch mode (intake closed until mainnet launch): no dates, no countdowns, one clear line instead
  const closed = () => !H.data.intakeOpen();
  function tags(t, list) {
    const out = [];
    if (t.status === 'featured') out.push(html`<span class="tag tag-hot">Featured</span>`);
    else out.push(html`<span class="tag">Open</span>`);
    out.push(html`<span class="tag">PoC required</span>`);
    // the program list has its own Intake column in launch mode
    if (t.open_for_intake) out.push(html`<span class="tag tag-ok">Intake open</span>`);
    else if (closed()) { if (!list) out.push(html`<span class="tag tag-launch">${H.LAUNCH}</span>`); }
    else out.push(html`<span class="tag tag-warn">Opening soon</span>`);
    (t.tags || []).forEach((x) => out.push(html`<span class="tag">${x}</span>`));
    return out;
  }
  const sevs = (scope) => html`<span class="sevs">${(scope || []).map((s) => H.sev(s))}</span>`;
  function windowState(t) {
    if (!t.featured_until) return 'open';
    return H.toDate(t.featured_until) > Date.now() ? 'live' : 'ended';
  }

  /* ================= programs list ================= */
  H.pages.programs = {
    title: 'Explore programs — Hyblis',
    mount(root) {
      const st = { q: '', status: 'all', sev: {} };
      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div class="eyebrow" data-scramble>Explore</div>
  <h1 class="display">Explore: <span class="grad-text">Programs</span></h1>
  <p class="lede">Live programs, released one at a time. Every proof is reproduced and measured before it counts. Findings stay private until they are fixed, paid and cleared for disclosure.</p>
  <div class="mono faint" style="margin-top:16px;font-size:12.5px" id="pg-updated"></div>
  <div class="chips" style="margin-top:30px">
    <a class="chip on" href="#programs">Programs</a><a class="chip" href="#competitions">Competitions</a>
    <button class="btn btn-ghost" type="button" id="pg-lucky" style="margin-left:auto">Feeling lucky? Roll the dice</button>
  </div>
</div></section>
<section class="body"><div class="wrap">
  <div class="toolbar">
    <label class="search"><span class="sr-only">Search programs</span>${H.icon('i-search', 16)}<input class="input" id="pg-q" type="search" placeholder="Search programs" autocomplete="off"></label>
    <div class="chips" role="group" aria-label="Status">${[['all', 'All'], ['featured', 'Featured'], ['open', 'Open']].map((x) => html`<button class="chip ${x[0] === 'all' ? 'on' : ''}" type="button" data-status="${x[0]}" aria-pressed="${x[0] === 'all' ? 'true' : 'false'}">${x[1]}</button>`)}</div>
    <div class="chips" role="group" aria-label="Severity in scope">${H.SEV.map((s) => html`<button class="chip" type="button" data-sev="${s}" aria-pressed="false">${H.cap(s)}</button>`)}</div>
  </div>
  <div class="tbl-wrap"><table class="tbl" style="min-width:880px">
    <thead id="pg-head"></thead>
    <tbody id="pg-body"></tbody></table></div>
  <div class="tbl-foot"><span id="pg-count"></span><span>Programs are revealed when they open. Reward amounts stay private.</span></div>
</div></section>`;

      function draw() {
        const c = H.data.cache, s = c.summary;
        const sevOn = Object.keys(st.sev).filter((k) => st.sev[k]);
        const rows = c.tasks.filter((t) => (!st.q || t.label.toLowerCase().indexOf(st.q) >= 0) && (st.status === 'all' || t.status === st.status)
          && (!sevOn.length || sevOn.some((x) => t.severity_scope.indexOf(x) >= 0)))
          .sort((a, b) => (a.status === 'featured' ? 0 : 1) - (b.status === 'featured' ? 0 : 1) || a.label.localeCompare(b.label));
        const body = $('#pg-body', root); if (!body) return;
        const shut = closed();
        $('#pg-head', root).innerHTML = html`<tr><th>Name</th><th>In scope</th><th>Max reward</th><th>Paid in</th>${shut ? html`<th>Featured</th><th>Intake</th>` : html`<th>Featured until</th><th>Opened</th>`}<th><span class="sr-only">Open</span></th></tr>`;
        let out = rows.map((t) => html`<tr class="is-link" data-href="program-${t.task_id}">
          <td><div class="pname"><span class="logo-tile">${t.label.charAt(0)}</span><div><b>${t.label}</b><span class="tags">${tags(t, true)}</span></div></div></td>
          <td>${sevs(t.severity_scope)}</td>
          <td class="num"><b>Private</b></td><td class="num muted">α · by severity</td>
          ${shut ? html`<td class="muted">${t.featured_until ? 'Until ' + H.date(t.featured_until) : t.status === 'featured' ? 'From launch' : '—'}</td><td><span class="launch-line">${H.LAUNCH}</span></td>`
            : html`<td class="num muted">${t.featured_until ? H.date(t.featured_until) : t.status === 'featured' ? 'To be announced' : '—'}</td><td class="num muted">${t.opened_at ? H.date(t.opened_at) : 'To be announced'}</td>`}
          <td class="r"><a class="btn btn-ghost btn-sm" href="#program-${t.task_id}">View program</a></td></tr>`).join('');
        const next = s && s.releases && s.releases.next_release_on;
        if (next && st.status !== 'featured' && !st.q && !sevOn.length) {
          const cd = H.countdown(next);
          out += html`<tr><td><div class="pname"><span class="logo-tile ghost">?</span><div><b class="muted">Next release</b><span class="tags"><span class="tag">${cd.done ? 'Opening' : 'Opens in ' + (cd.d ? cd.d + ' d' : cd.h + ' h')}</span></span></div></div></td>
            <td><span class="sev sev-off">Revealed at launch</span></td><td class="num muted">—</td><td class="num muted">—</td><td class="num muted">—</td><td class="num muted">${H.date(next)}</td>
            <td class="r"><a class="btn btn-ghost btn-sm" href="#competitions">See the schedule</a></td></tr>`;
        }
        const ready = H.data.loaded();
        body.innerHTML = out || String(html`<tr><td colspan="7">${!ready ? H.ui.loadFail('the programs') : html`<div class="tbl-empty"><b>${c.tasks.length ? 'No program matches' : 'No program is open yet'}</b>${c.tasks.length ? 'Clear the filters to see every open program.' : shut ? 'The first program is published here before intake opens at mainnet launch.' : 'The first program is being verified. It will appear here the moment it opens.'}</div>`}</td></tr>`);
        $('#pg-count', root).textContent = ready ? 'Showing ' + rows.length + ' of ' + c.tasks.length + (shut ? ' released program' : ' open program') + (c.tasks.length === 1 ? '' : 's') : '';
        $('#pg-updated', root).textContent = s ? 'Last updated on ' + H.dateTime(s.generated_at) : '';
      }
      const offs = [H.data.subscribe(draw)];
      $('#pg-q', root).addEventListener('input', H.debounce((e) => { st.q = e.target.value.trim().toLowerCase(); draw(); }, 120));
      offs.push(H.on(root, 'click', '[data-status]', (e, b) => { st.status = b.dataset.status; $$('[data-status]', root).forEach((x) => { const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-pressed', on); }); draw(); }));
      offs.push(H.on(root, 'click', '[data-sev]', (e, b) => { const k = b.dataset.sev; st.sev[k] = !st.sev[k]; b.classList.toggle('on', st.sev[k]); b.setAttribute('aria-pressed', st.sev[k]); draw(); }));
      offs.push(H.on(root, 'click', 'tr[data-href]', (e, tr) => { if (!e.target.closest('a,button')) H.go(tr.dataset.href); }));
      $('#pg-lucky', root).addEventListener('click', () => { const t = H.data.cache.tasks; if (t.length) H.go('program-' + t[Math.floor(Math.random() * t.length)].task_id); else H.toast(H.data.loaded() ? 'No program is open yet' : 'Could not load the programs. Try again in a moment.'); });
      draw();
      return () => offs.forEach((fn) => fn());
    },
  };

  /* ================= program detail ================= */
  const TABS = [['overview', 'Overview'], ['scope', 'Scope'], ['rewards', 'Rewards'], ['rules', 'Rules'], ['template', 'Template']];
  H.pages.program = {
    title: 'Program — Hyblis',
    mount(root, ctx) {
      const id = ctx.params[0];
      let tab = 'overview', p = null, alive = true;
      const SKEL = html`<span class="skel" style="width:280px;height:54px"></span><span class="skel" style="width:420px;margin-top:18px"></span>`;
      root.innerHTML = html`<section class="phero"><div class="wrap phero-in"><nav class="crumbs" aria-label="Breadcrumb"><a href="#programs">Programs</a><span aria-hidden="true">/</span><span id="crumb">…</span></nav>
        <div id="ph" style="margin-top:28px">${SKEL}</div></div></section>
        <section class="body"><div class="wrap cols"><div class="main" id="pm"></div><aside class="side" id="ps" aria-label="Program facts"></aside></div></section>`;

      function head() {
        $('#crumb', root).textContent = p.label;
        document.title = p.label + ' — Hyblis';
        $('#ph', root).innerHTML = html`<div style="display:flex;flex-wrap:wrap;gap:26px;align-items:center">
          <span class="logo-tile lg">${p.label.charAt(0)}</span>
          <div style="flex:1 1 400px;min-width:0"><h1 class="display" style="margin:0">${p.label}</h1><div class="tags" style="margin-top:16px">${tags(p)}<span class="tag">Paid in <span style="text-transform:none">α</span></span></div>
            <p class="lede" style="margin-top:14px;font-size:16px">${p.scope_summary}</p></div>
          <div class="cta" style="margin:0">${p.open_for_intake ? html`<a class="btn btn-grad btn-lg" href="#submit-${p.task_id}" data-magnetic>Submit a report</a>` : html`<span class="btn btn-grad btn-lg is-disabled" aria-disabled="true">${closed() ? H.LAUNCH : 'Intake opens soon'}</span>`}
            ${p.poc_template ? html`<button class="btn btn-ghost btn-lg" type="button" data-copy="${p.poc_template}" data-copied="PoC template copied">Copy PoC template</button>` : ''}</div></div>
          ${closed() ? html`<div class="notice launch" role="status" style="margin-top:28px">${H.icon('i-arrow', 18)}<span><b>${H.data.intakeMessage()}</b> The program, its rules and how proofs are validated are public now, so you can prepare.${p.verification_pending ? ' The pinned fork block, the verified in-scope contracts and the proof template are published here before launch.' : ''}</span></div>`
            : p.verification_pending ? html`<div class="notice" role="status" style="margin-top:28px">${H.icon('i-search', 18)}<span>Scope verification in progress. Intake opens once the pinned fork block and the verified in-scope contracts are published here.</span></div>` : ''}`;
      }
      function panel() {
        const inScope = p.severity_scope || [];
        if (tab === 'overview') return html`
          <div class="block"><h2 class="display h3">Program overview</h2><p class="lede" style="max-width:46em;font-size:16px;color:var(--fg-2)">Find a vulnerability in the in-scope ${p.label} contracts and submit one Foundry proof of concept. Your proof runs twice in an isolated sandbox, and its impact is measured on the protocol against a clean copy of the same block. The earliest valid proof of a bug wins the credit.</p></div>
          <div class="block"><h2 class="display h3">Impacts in scope</h2>${p.in_scope_impacts && p.in_scope_impacts.length ? html`<div class="grid-2">${p.in_scope_impacts.map((i) => html`<div class="item"><span>${H.impactLabel(i.impact)}</span>${H.sev(i.severity)}</div>`)}</div>` : html`<p class="muted">Published with the scope.</p>`}</div>
          <div class="block"><h2 class="display h3">How your proof is validated</h2><ol class="pipe" style="margin-top:0">${PIPE.map((x, i) => html`<li class="done"><b>0${i + 1}</b><div><strong>${x[0]}</strong><span>${x[1]}</span></div></li>`)}</ol></div>`;
        if (tab === 'scope') return html`
          <div class="block"><h2 class="display h3">Assets in scope</h2>
            ${p.assets && p.assets.length ? html`<div class="tbl-wrap"><table class="tbl" style="min-width:600px"><thead><tr><th>Target</th><th>Type</th><th>Address</th></tr></thead><tbody>
              ${p.assets.map((a) => html`<tr><td><b>${a.name}</b></td><td class="muted">Smart contract · ${p.chain_id === 1 ? 'Ethereum' : 'chain ' + p.chain_id}</td><td><button class="addr" type="button" data-copy="${a.address}" data-copied="Address copied">${H.short(a.address, 10, 8)}${H.icon('i-copy', 13)}</button></td></tr>`)}</tbody></table></div>`
              : closed() ? html`<div class="card"><div class="tbl-empty"><b>Published before launch</b>The verified contract list is published here before intake opens at mainnet launch.</div></div>`
              : html`<div class="card"><div class="tbl-empty"><b>Pending verification</b>The verified contract list is published here before intake opens.</div></div>`}</div>
          <div class="block"><h2 class="display h3">Environment</h2><div class="grid-2">
            <div class="item"><span>Pinned fork block</span><b class="${p.fork_block ? 'num' : ''}">${p.fork_block ? H.num(p.fork_block) : closed() ? 'Published before launch' : 'pending'}</b></div>
            <div class="item"><span>Proof format</span><b>Foundry test</b></div>
            ${p.repo ? html`<div class="item"><span>Source</span><a class="link-arrow" href="${p.repo}" target="_blank" rel="noopener noreferrer">Repository ${H.icon('i-ext', 14)}</a></div>` : ''}
            ${p.commit ? html`<div class="item"><span>Commit</span><button class="addr" type="button" data-copy="${p.commit}">${H.short(p.commit, 10, 0)}${H.icon('i-copy', 13)}</button></div>` : ''}</div></div>
          <div class="block"><h2 class="display h3">Out of scope</h2>${p.out_of_scope && p.out_of_scope.length ? html`<ul class="list">${p.out_of_scope.map((o) => html`<li>${o}</li>`)}</ul>` : html`<p class="muted">Published with the scope.</p>`}</div>`;
        if (tab === 'rewards') return html`
          <div class="block"><h2 class="display h3">Rewards by threat level</h2><p class="lede" style="font-size:15.5px;max-width:46em">Researchers are paid in α straight through the subnet’s weights: from validation by measured severity, with a bonus once the program accepts the finding. Bounty amounts stay private. Severity is the lower of your claim and the measured impact.</p></div>
          <div class="card">${H.SEV.map((s) => { const on = inScope.indexOf(s) >= 0; return html`<div class="tier"><i style="background:var(--${s === 'critical' ? 'crit' : s === 'medium' ? 'med' : s})"></i><span class="name">${s}</span><span class="note">${on ? 'Filed with the bounty platform' : 'Not filed for this program yet'}</span><span class="val" style="${on ? '' : 'color:#71717a'}">${on ? 'α · by severity' : 'Out of scope'}</span></div>`; })}</div>`;
        if (tab === 'rules') {
          const terms = p.runner_terms, lim = (terms && terms.limits) || {};
          const days = (sec) => (sec % 86400 === 0 ? H.num(sec / 86400) + ' day' + (sec === 86400 ? '' : 's') : H.num(sec) + ' s');
          return html`
          <div class="block"><h2 class="display h3">Proof-of-concept rules</h2><p class="muted" style="margin:-6px 0 16px;max-width:46em">The runner checks these call by call in Foundry\u2019s own trace. Your asserts and logs are ignored.</p>
            <ol class="rules-list" id="poc-rules">${(p.poc_rules || []).map((r) => html`<li>${r}</li>`)}</ol></div>
          <div class="grid-2" style="grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px;margin-bottom:38px">
            <div class="card" style="padding:24px" id="cheat-list"><h3 class="h4">Allowed cheatcodes</h3><p class="muted" style="margin-top:8px;font-size:14px">Nothing else is allowed. Even an attempt counts, also in helper contracts and reverted calls.</p>
              <ul class="cheats">${(p.allowed_cheatcodes || []).map((c) => html`<li><code>${c[0]}</code>${c[1] ? html`<span>${c[1]}</span>` : ''}</li>`)}</ul></div>
            <div class="card" style="padding:24px" id="helper-list"><h3 class="h4">Capital and helpers</h3>${terms ? html`<ul class="cheats" style="margin-top:12px">
              <li><code>_fund(token, to, amount)</code><span>${terms.capital.length ? terms.capital.map((c) => c.symbol + (c.cap ? ' up to ' + c.cap : '')).join(', ') : 'No capital token for this program'}. Capital is subtracted from your gain.</span></li>
              <li><code>_asRole(role, target, data)</code><span>${terms.as_role.length ? terms.as_role.map((a) => a.function + ' on ' + H.short(a.target, 8, 4) + (a.max_calls ? ', at most ' + a.max_calls + '×' : '')).join('; ') : 'Not available for this program'}</span></li>
              <li><code>_setPrice(feed, answer)</code><span>${terms.set_price.length ? terms.set_price.map((f) => (f.token || H.short(f.feed, 8, 4)) + ' within ' + (f.max_move_bps / 100) + '%').join('; ') : 'Not available for this program'}</span></li>
              <li><code>step1() … stepN()</code><span>One transaction each${lim.max_steps ? ', up to ' + lim.max_steps : ''}</span></li>
              ${lim.max_warp_s != null ? html`<li><code>warp, roll</code><span>Forward only: up to ${days(lim.max_warp_s)}${lim.max_roll != null ? ' and ' + H.num(lim.max_roll) + ' blocks' : ''}</span></li>` : ''}</ul>`
              : html`<p class="muted" style="margin-top:12px;font-size:14px">Capital tokens and caps, and whether _asRole and _setPrice are available, are published with the verified impact spec.</p>`}</div>
            <div class="card" style="padding:24px"><h3 class="h4">Trusted roles</h3>${p.trusted_roles && p.trusted_roles.length ? html`<ul class="list" style="margin-top:12px;font-size:14.5px">${p.trusted_roles.map((r) => html`<li>${H.cap(r)}</li>`)}</ul>` : html`<p class="muted" style="margin-top:12px">Published with the scope.</p>`}</div>
            <div class="card" style="padding:24px"><h3 class="h4">Conduct</h3><ul class="list" style="margin-top:12px;font-size:14.5px">${CONDUCT.map((r) => html`<li>${r}</li>`)}</ul></div></div>
          <div class="block" id="check-howto"><h2 class="display h3">Check before you submit</h2>
            <p class="lede" style="font-size:15.5px;max-width:46em">hyblis check runs your proof on your own machine the way the runner does: the same harness, the same verdict engine and this program\u2019s impact spec. It prints VALIDATED with the measured impact, or REJECTED with the reason.</p>
            ${checkDownload(p)}
            ${p.check_tool ? codeBlock('Terminal', checkCommands(p), 'Commands copied') : ''}
            <ul class="list" style="margin-top:16px;font-size:14.5px">
              <li>Foundry ${(p.check_tool && p.check_tool.foundry) || '1.9.0'} exactly, with forge and cast on your PATH.</li>
              <li>Python 3.11 or newer with eth-abi and eth-utils.</li>
              <li>The program\u2019s Foundry project${p.commit ? ' at commit ' + H.short(p.commit, 10, 0) : ''}, with its dependencies installed and built once.</li>
              <li>Your own archive RPC, or anvil forked from it at block ${p.fork_block ? H.num(p.fork_block) : 'the pinned block'}. Not a third-party provider: it would see every slot your proof reads.</li></ul></div>`;
        }
        return html`<div class="block"><h2 class="display h3">Proof-of-concept template</h2>
          <p class="muted" style="margin:-6px 0 16px;max-width:46em">Put both files in test/hyblis/ of the program\u2019s project. HyblisBase.sol gives you _fund, _asRole and _setPrice. In plain forge test they fall back to ordinary cheatcodes, so the file you submit is a normal Foundry test.</p>
          ${p.poc_template ? codeBlock('HyblisPoC.t.sol', p.poc_template, 'PoC template copied') : html`<p class="muted">${closed() ? 'HyblisPoC.t.sol, with the pinned block and the in-scope contracts filled in, is published here with the verified scope, before intake opens at mainnet launch.' : 'The template is published with the scope.'}</p>`}</div>
          <div class="block">${p.poc_base ? codeBlock('HyblisBase.sol', p.poc_base, 'HyblisBase.sol copied') : html`<p class="muted">HyblisBase.sol is published with the scope.</p>`}</div>
          <div class="block"><h2 class="display h3">hyblis check</h2><p class="muted" style="margin:-6px 0 16px;max-width:46em">See the runner\u2019s verdict on your machine before you submit. <button class="addr" type="button" data-tab="rules" style="text-decoration:underline">How to run it</button></p>${checkDownload(p)}</div>`;
      }
      function body(focusTab) {
        $('#pm', root).innerHTML = html`<div class="tabs" role="tablist" aria-label="Program sections">${TABS.map((t) => html`<button class="tab ${t[0] === tab ? 'on' : ''}" type="button" role="tab" id="pt-${t[0]}" aria-controls="pt-panel" aria-selected="${t[0] === tab ? 'true' : 'false'}" tabindex="${t[0] === tab ? '0' : '-1'}" data-tab="${t[0]}">${t[1]}</button>`)}</div><div class="tabpanel" role="tabpanel" id="pt-panel" aria-labelledby="pt-${tab}" tabindex="0">${panel()}</div>`;
        // the tab list was rebuilt, so keyboard focus goes back to the selected tab
        if (focusTab) { const b = $('#pt-' + tab, root); if (b) b.focus(); }
      }
      function side() {
        const w = windowState(p);
        const shut = closed();
        const featured = p.featured_until ? (w === 'live' ? 'Until ' + H.date(p.featured_until) : 'Ended ' + H.date(p.featured_until))
          : p.status === 'featured' ? (shut ? 'From mainnet launch' : 'Dates to be announced') : 'No';
        $('#ps', root).innerHTML = html`<div class="card facts">
          <div><span class="label">Max reward</span><b>Private</b></div><div><span class="label">Paid in</span><b>α · by severity</b></div>
          <div><span class="label">In scope</span><b>${(p.severity_scope || []).map(H.cap).join(' · ') || '—'}</b></div>
          <div><span class="label">Featured</span><b>${featured}</b></div>
          <div><span class="label">Intake</span><b>${p.open_for_intake ? 'Open, never closes' : shut ? H.LAUNCH : 'Opens after verification'}</b></div>
          ${shut ? '' : html`<div><span class="label">Opened</span><b>${p.opened_at ? H.date(p.opened_at) : 'To be announced'}</b></div>`}</div>
          <div class="card" style="padding:22px"><div class="label">Automatic validation</div><p class="muted" style="margin-top:10px;font-size:14px;line-height:1.6">No human in the loop. The verdict target is under one hour from submission, and a validated finding is filed within twelve.</p>
          <a class="link-arrow" href="#home" data-jump="validation" style="margin-top:14px">Watch a validation run ${H.icon('i-arrow', 14)}</a></div>`;
      }
      const offs = [H.on(root, 'click', '[data-tab]', (e, b) => { tab = b.dataset.tab; body(true); })];
      offs.push(H.on(root, 'click', '[data-demo-download]', (e, b) => H.toast('This preview has no files. On the live site this downloads ' + b.dataset.demoDownload + '.')));
      // arrow keys, Home and End move between tabs
      offs.push(H.on(root, 'keydown', '[role="tab"]', (e, b) => {
        const i = TABS.findIndex((t) => t[0] === b.dataset.tab), n = TABS.length;
        let to = -1;
        if (e.key === 'ArrowRight') to = (i + 1) % n; else if (e.key === 'ArrowLeft') to = (i - 1 + n) % n;
        else if (e.key === 'Home') to = 0; else if (e.key === 'End') to = n - 1;
        if (to < 0) return;
        e.preventDefault(); tab = TABS[to][0]; body(true);
      }));
      function load() {
        H.data.program(id).then((res) => {
          if (!alive) return;
          if (!res) {
            $('#crumb', root).textContent = 'Not found';
            $('#ph', root).innerHTML = html`<h1 class="display">Program not found</h1><p class="lede">This program is not open. Programs are revealed when their window opens.</p><div class="cta"><a class="btn btn-grad" href="#programs">Explore programs</a></div>`;
            return;
          }
          p = res; head(); body(); side();
          offs.push(H.fx.scan(root));
        }, () => {
          if (!alive) return;
          $('#crumb', root).textContent = 'Not loaded';
          $('#ph', root).innerHTML = html`<h1 class="display">Could not load this program</h1><p class="lede">The program details did not arrive. Check your connection and try again.</p><div class="cta"><button class="btn btn-grad" type="button" data-retry>Try again</button><a class="btn btn-ghost" href="#programs">Explore programs</a></div>`;
        });
      }
      offs.push(H.on(root, 'click', '[data-retry]', () => { $('#view').focus({ preventScroll: true }); $('#crumb', root).textContent = '…'; $('#ph', root).innerHTML = SKEL; load(); }));
      load();
      return () => { alive = false; offs.forEach((fn) => fn()); };
    },
  };

  /* ================= competitions (featured windows) ================= */
  H.pages.competitions = {
    title: 'Competitions — Hyblis',
    mount(root) {
      let filter = 'all', timer = null;
      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div class="eyebrow" data-scramble>Explore</div>
  <h1 class="display">Explore: <span class="grad-text">Competitions</span></h1>
  <p class="lede">Every new program opens with a featured window, when fresh code gets the most eyes. The window ends; intake never does.</p>
  <div class="chips" style="margin-top:30px" role="group" aria-label="Window status">${[['all', 'All'], ['live', 'Live'], ['upcoming', 'Upcoming'], ['ended', 'Ended']].map((x) => html`<button class="chip ${x[0] === 'all' ? 'on' : ''}" type="button" data-f="${x[0]}" aria-pressed="${x[0] === 'all' ? 'true' : 'false'}">${x[1]}</button>`)}</div>
</div></section>
<section class="body"><div class="wrap" id="cp" style="display:flex;flex-direction:column;gap:48px"></div></section>`;

      function draw() {
        const c = H.data.cache, s = c.summary;
        const live = c.tasks.filter((t) => windowState(t) === 'live'), ended = c.tasks.filter((t) => windowState(t) === 'ended');
        const next = s && s.releases && s.releases.next_release_on, every = (s && s.releases && s.releases.release_every_days) || 7;
        const show = (k) => filter === 'all' || filter === k;
        const parts = [], ready = H.data.loaded();
        if (!ready) parts.push(html`<div class="card">${H.ui.loadFail('the programs')}</div>`);
        const shut = closed();
        // featured programs whose window has no dates yet (in launch mode: they open at launch)
        const soon = c.tasks.filter((t) => t.status === 'featured' && !t.featured_until);
        if (ready && show('live')) parts.push(html`<div><h2 class="label" style="margin-bottom:16px">Live now</h2>${live.length ? live.map((t) => html`
          <article class="card live" style="margin-bottom:16px">
            <div class="live-viz" aria-hidden="true"><div class="radar"><i style="left:28%;top:34%"></i><i style="left:66%;top:58%;animation-delay:1.3s"></i><i style="left:44%;top:72%;animation-delay:2.4s"></i></div></div>
            <div class="live-body">
              <div class="tags"><span class="tag tag-hot"><span class="pulse-dot"></span>Live</span><span class="tag">Featured window</span></div>
              <h3 class="display" style="font-size:clamp(30px,3.6vw,44px)">${t.label}</h3>
              <div class="mono muted" style="font-size:13.5px">${t.opened_at ? H.date(t.opened_at) + ' – ' : 'Until '}${H.date(t.featured_until)} · 00:00 UTC</div>
              <div class="count" data-until="${t.featured_until}" aria-label="Time left in the featured window"></div>
              <div class="grid-2" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))"><div class="item"><span class="label">In scope</span><b>${t.severity_scope.map(H.cap).join(' · ')}</b></div><div class="item"><span class="label">Paid in</span><b>α · by severity</b></div></div>
              <div class="cta" style="margin:0">${t.open_for_intake ? html`<a class="btn btn-grad btn-lg" href="#submit-${t.task_id}">Submit a report</a>` : html`<span class="btn btn-grad btn-lg is-disabled" aria-disabled="true">${shut ? H.LAUNCH : 'Intake opens soon'}</span>`}<a class="btn btn-ghost btn-lg" href="#program-${t.task_id}">View program</a></div>
            </div></article>`) : html`<div class="card"><div class="tbl-empty"><b>${shut ? 'No window is live yet' : 'No window is live'}</b>${shut ? 'The first featured window opens at mainnet launch.' : next ? 'The next program opens on ' + H.date(next) + '.' : 'The next window will be announced here.'}</div></div>`}</div>`);
        if (ready && show('upcoming')) {
          const dates = next ? [next, H.toDate(next).getTime() + every * 86400000].map((d) => (typeof d === 'number' ? new Date(d).toISOString().slice(0, 10) : d)) : [];
          const cards = soon.map((t) => html`
            <article class="card live launch-win" style="margin-bottom:16px">
              <div class="live-viz" aria-hidden="true"><div class="radar idle"><i style="left:28%;top:34%"></i><i style="left:66%;top:58%;animation-delay:1.3s"></i></div></div>
              <div class="live-body">
                <div class="tags"><span class="tag tag-hot">Featured window</span><span class="tag tag-launch">${shut ? H.LAUNCH : 'Dates to be announced'}</span></div>
                <h3 class="display" style="font-size:clamp(30px,3.6vw,44px)">${t.label}</h3>
                <p class="muted" style="font-size:15px;line-height:1.6;max-width:36em">${t.scope_summary}</p>
                <div class="launch-when"><span class="label">${shut ? 'Featured window' : 'Window'}</span><b>${shut ? 'Starts at mainnet launch' : 'Dates to be announced'}</b></div>
                <div class="grid-2" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))"><div class="item"><span class="label">In scope</span><b>${t.severity_scope.map(H.cap).join(' · ')}</b></div><div class="item"><span class="label">Paid in</span><b>α · by severity</b></div></div>
                <div class="cta" style="margin:0"><a class="btn btn-grad btn-lg" href="#program-${t.task_id}">Read the program</a>${t.open_for_intake ? html`<a class="btn btn-ghost btn-lg" href="#submit-${t.task_id}">Submit a report</a>` : ''}</div>
              </div></article>`);
          parts.push(html`<div><h2 class="label" style="margin-bottom:16px">Upcoming</h2>${cards}${dates.length ? html`<div class="grid-2" style="grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px">${dates.map((d, i) => html`
            <article class="card spot" style="padding:26px;display:flex;flex-direction:column;gap:14px">
              <div style="display:flex;justify-content:space-between;align-items:center"><span class="logo-tile ghost">?</span><span class="tag">Upcoming</span></div>
              <h3 class="display h3">${i === 0 ? 'Next release' : 'Following release'}</h3>
              <div class="mono muted" style="font-size:13px">Starts ${H.date(d)}</div>
              <p class="muted" style="font-size:14px;line-height:1.6">The program is revealed when its window opens. Scope and the pinned fork block are verified first.</p></article>`)}</div>`
            : soon.length ? '' : html`<div class="card"><div class="tbl-empty"><b>Nothing scheduled yet</b>${shut ? 'Release dates are announced after mainnet launch.' : 'The next window will be announced here.'}</div></div>`}</div>`);
        }
        if (ready && show('ended')) parts.push(html`<div><h2 class="label" style="margin-bottom:16px">Ended</h2><div class="tbl-wrap"><table class="tbl" style="min-width:600px"><thead><tr><th>Program</th><th>Window</th><th>Intake</th><th><span class="sr-only">Open</span></th></tr></thead><tbody>
          ${ended.length ? ended.map((t) => html`<tr class="is-link" data-href="program-${t.task_id}"><td><div class="pname"><span class="logo-tile">${t.label.charAt(0)}</span><b>${t.label}</b></div></td><td class="num muted">${H.date(t.opened_at)} – ${H.date(t.featured_until)}</td><td>${t.open_for_intake ? html`<span class="tag tag-ok">Still open</span>` : html`<span class="tag">Closed</span>`}</td><td class="r"><a class="btn btn-ghost btn-sm" href="#program-${t.task_id}">View program</a></td></tr>`)
            : html`<tr><td colspan="4"><div class="tbl-empty"><b>No window has ended yet</b>Ended windows are listed here. Findings stay private until disclosure is cleared.</div></td></tr>`}</tbody></table></div></div>`);
        parts.push(html`<div class="card triple">
          <div><div class="eyebrow" data-scramble>01</div><h3 class="h4" style="margin-top:12px">Featured 3 to 7 days</h3><p>Up to 1,000 lines: 3 days. Up to 3,000: 5 days. Up to 6,000: 7 days. Larger scopes are split.</p></div>
          <div><div class="eyebrow" data-scramble>02</div><h3 class="h4" style="margin-top:12px">Intake never closes</h3><p>After its window a program stays open. Valid proofs are filed within hours, not at the end of a round.</p></div>
          <div><div class="eyebrow" data-scramble>03</div><h3 class="h4" style="margin-top:12px">A new program every ${every === 7 ? 'week' : every + ' days'}</h3><p>Programs are released one at a time, the most achievable first.</p></div></div>`);
        $('#cp', root).innerHTML = parts.join('');
        tick();
      }
      function tick() {
        const counts = $$('.count[data-until]', root);
        // a window that just ended moves to "Ended" without waiting for new data
        if (counts.some((el) => H.toDate(el.dataset.until) <= Date.now())) { draw(); return; }
        counts.forEach((el) => {
          const c = H.countdown(el.dataset.until), p = (n) => String(n).padStart(2, '0');
          el.innerHTML = html`<div><b>${p(c.d)}</b><span>DAYS</span></div><div><b>${p(c.h)}</b><span>HOURS</span></div><div><b>${p(c.m)}</b><span>MIN</span></div><div><b>${p(c.s)}</b><span>SEC</span></div>`;
        });
      }
      const offs = [H.data.subscribe(draw)];
      offs.push(H.on(root, 'click', '[data-f]', (e, b) => { filter = b.dataset.f; $$('[data-f]', root).forEach((x) => { const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-pressed', on); }); draw(); }));
      offs.push(H.on(root, 'click', 'tr[data-href]', (e, tr) => { if (!e.target.closest('a,button')) H.go(tr.dataset.href); }));
      draw();
      timer = setInterval(tick, 1000);
      return () => { clearInterval(timer); offs.forEach((fn) => fn()); };
    },
  };
})();
