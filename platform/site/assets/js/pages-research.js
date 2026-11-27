/* Hyblis site — leaderboard, researcher profile, public ledger. */
(function () {
  'use strict';
  const H = window.Hyblis, html = H.html, $ = H.$, $$ = H.$$;
  H.pages = H.pages || {};
  const SEVK = [['critical', 'C', 'crit'], ['high', 'H', 'high'], ['medium', 'M', 'med'], ['low', 'L', 'low']];
  const MEDAL = ['#f5d06f', '#d4d4d8', '#e0a370'];

  function sevPills(counts) {
    return html`<span class="sevs">${SEVK.map((s) => html`<span class="sev ${counts[s[0]] ? 'sev-' + s[0] : 'sev-off'}" title="${H.cap(s[0])}">${s[1]}${counts[s[0]]}</span>`)}</span>`;
  }

  /* ================= leaderboard ================= */
  H.pages.leaderboard = {
    title: 'Leaderboard — Hyblis',
    mount(root) {
      let q = '';
      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div class="eyebrow" data-scramble>Researchers</div>
  <h1 class="display">Leader<span class="grad-text">board</span></h1>
  <p class="lede">Scores come from the published scoring policy, applied to every credited finding on the public ledger.</p>
  <div class="chips" style="margin-top:28px"><button class="btn btn-ghost btn-sm" type="button" data-action="policy">Read the scoring policy</button><a class="btn btn-ghost btn-sm" href="#ledger">Open the public ledger</a></div>
</div></section>
<section class="body"><div class="wrap">
  <div class="podium" id="lb-pod"></div>
  <div class="toolbar"><label class="search"><span class="sr-only">Find a researcher</span>${H.icon('i-search', 16)}<input class="input mono" id="lb-q" type="search" placeholder="Find a researcher by hotkey" autocomplete="off" spellcheck="false"></label></div>
  <div class="tbl-wrap"><table class="tbl" style="min-width:860px">
    <thead><tr><th>Rank</th><th>Researcher</th><th>Findings by severity</th><th class="r">Accepted</th><th class="r">Validated</th><th class="r">Under review</th><th class="r">Score</th></tr></thead>
    <tbody id="lb-body"></tbody></table></div>
  <div class="tbl-foot"><span id="lb-count"></span><span>Score = share of the miner pool × 10,000 under the published policy. C / H / M / L = credited findings by severity.</span></div>
</div></section>`;
      function draw() {
        const c = H.data.cache, all = c.leaderboard, ready = H.data.loaded();
        const pod = $('#lb-pod', root);
        pod.innerHTML = all.length >= 3 && !q ? all.slice(0, 3).map((r, i) => html`<a class="card spot pod pod-${i + 1}" href="#researcher-${r.hotkey}" style="color:${MEDAL[i]}">
            <span class="place">${['1st', '2nd', '3rd'][i]}</span>${H.identicon(r.hotkey, i === 0 ? 84 : 68)}
            <span class="mono" style="font-size:14px;color:var(--fg)">${H.short(r.hotkey, 8, 6)}</span>
            <span class="score" style="color:var(--fg)">${H.num(r.score, 2)}</span><span class="label">Score</span>
            <span class="tags" style="justify-content:center"><span class="tag tag-ok">${r.accepted} accepted</span><span class="tag">${r.validated} validated</span></span></a>`).join('') : '';
        pod.hidden = !pod.innerHTML;
        const rows = all.filter((r) => !q || r.hotkey.toLowerCase().indexOf(q) >= 0);
        $('#lb-body', root).innerHTML = rows.length ? rows.map((r) => html`<tr class="is-link" data-href="researcher-${r.hotkey}">
            <td><span class="rank rank-${r.rank}">#${r.rank}</span></td>
            <td><a class="who" href="#researcher-${r.hotkey}">${H.identicon(r.hotkey, 30)}<span class="mono">${H.short(r.hotkey, 8, 6)}</span></a></td>
            <td>${sevPills(H.data.sevCounts(r.hotkey))}</td>
            <td class="r num">${r.accepted}</td><td class="r num muted">${r.validated}</td><td class="r num muted">${r.under_review}</td><td class="r num"><b>${H.num(r.score, 2)}</b></td></tr>`).join('')
          : String(html`<tr><td colspan="7">${!ready ? H.ui.loadFail('the leaderboard') : html`<div class="tbl-empty"><b>${all.length ? 'No researcher matches' : 'No ranked researchers yet'}</b>${all.length ? 'Check the hotkey and try again.' : H.data.intakeOpen() ? 'Scores appear with the first validated finding.' : 'Intake opens at mainnet launch. Scores appear here with the first validated finding.'}</div>`}</td></tr>`);
        $('#lb-count', root).textContent = ready ? rows.length + ' researcher' + (rows.length === 1 ? '' : 's') : '';
      }
      const offs = [H.data.subscribe(draw)];
      $('#lb-q', root).addEventListener('input', H.debounce((e) => { q = e.target.value.trim().toLowerCase(); draw(); }, 120));
      offs.push(H.on(root, 'click', 'tr[data-href]', (e, tr) => { if (!e.target.closest('a,button')) H.go(tr.dataset.href); }));
      draw();
      return () => offs.forEach((fn) => fn());
    },
  };

  /* ================= researcher profile ================= */
  H.pages.researcher = {
    title: 'Researcher — Hyblis',
    mount(root, ctx) {
      const hk = ctx.params[0];
      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <nav class="crumbs" aria-label="Breadcrumb"><a href="#leaderboard">Leaderboard</a><span aria-hidden="true">/</span><span>Researcher</span></nav>
  <div class="profile-head">${H.identicon(hk, 112)}
    <div style="flex:1 1 360px;min-width:0"><div class="tags" id="rs-tags"></div>
      <h1 class="display" style="font-size:clamp(28px,4vw,46px);text-transform:none;margin-top:14px">${H.short(hk, 8, 6)}</h1>
      <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:14px"><code class="mono muted" style="font-size:12.5px;padding:8px 12px;border:1px solid var(--line-2);border-radius:6px;background:rgba(13,13,16,.8);overflow-wrap:anywhere">${hk}</code>
        <button class="iconbtn" type="button" data-copy="${hk}" data-copied="Hotkey copied">${H.icon('i-copy', 14)}Copy hotkey</button></div></div></div>
</div></section>
<section class="body"><div class="wrap" style="display:flex;flex-direction:column;gap:36px">
  <div class="card statrow" id="rs-stats"></div>
  <div class="cols" id="rs-cols" style="gap:16px"><div class="card" style="flex:1 1 400px;min-width:0;padding:26px"><h2 class="h4">Findings by severity</h2><div id="rs-sev"></div></div>
    <div class="card" style="flex:1 1 400px;min-width:0;padding:26px"><h2 class="h4">Milestones</h2><div class="miles" id="rs-miles" style="margin-top:18px"></div></div></div>
  <div><div class="sec-head" style="margin-bottom:16px"><h2 class="display h3">Credited findings</h2></div>
    <div class="tbl-wrap"><table class="tbl" style="min-width:720px"><thead><tr><th>Submission</th><th>Severity</th><th>Received</th><th>Status</th></tr></thead><tbody id="rs-body"></tbody></table></div></div>
</div></section>`;
      function draw() {
        // Until the data has loaded once, show that instead of an empty profile.
        const ready = H.data.loaded();
        $('#rs-stats', root).hidden = !ready; $('#rs-cols', root).hidden = !ready;
        if (!ready) { $('#rs-tags', root).innerHTML = ''; $('#rs-body', root).innerHTML = String(html`<tr><td colspan="4">${H.ui.loadFail('this profile')}</td></tr>`); return; }
        const r = H.data.researcher(hk), rows = H.data.findings(hk), sc = H.data.sevCounts(hk);
        const total = SEVK.reduce((t, s) => t + sc[s[0]], 0);
        $('#rs-tags', root).innerHTML = r ? html`<span class="tag tag-hot">Rank #${r.rank}</span>${r.accepted ? html`<span class="tag tag-ok">${r.accepted} accepted</span>` : ''}` : html`<span class="tag">Not ranked yet</span>`;
        $('#rs-stats', root).innerHTML = [['Score', r ? H.num(r.score, 2) : '0.00'], ['Accepted', r ? r.accepted : 0], ['Validated', r ? r.validated : 0], ['Under review', r ? r.under_review : 0], ['Paid out', 'Private']]
          .map((x) => html`<div><span class="label">${x[0]}</span><b>${x[1]}</b></div>`).join('');
        $('#rs-sev', root).innerHTML = html`<div class="sevbar" role="img" aria-label="${total} credited findings: ${SEVK.map((s) => sc[s[0]] + ' ' + s[0]).join(', ')}">${total ? SEVK.map((s) => html`<i style="width:${(100 * sc[s[0]]) / total}%;background:var(--${s[2]})"></i>`) : ''}</div>
          <div class="legend">${SEVK.map((s) => html`<div><span><i style="background:var(--${s[2]})"></i>${H.cap(s[0])}</span><b>${sc[s[0]]}</b></div>`)}</div>`;
        const miles = [
          [!!(r && r.accepted >= 1), 'First accepted finding', 'A finding accepted by the bounty platform.'],
          [total >= 5, 'Five credited findings', 'Five findings validated or accepted.'],
          [!!(r && r.rank <= 3), 'Top three', 'Ranked in the top three by score.'],
        ];
        $('#rs-miles', root).innerHTML = miles.map((m) => html`<div class="mile ${m[0] ? '' : 'off'}"><span class="dot">${H.icon(m[0] ? 'i-check' : 'i-x', 16)}</span><div><b>${m[1]}</b><span>${m[2]}</span></div></div>`).join('');
        $('#rs-body', root).innerHTML = rows.length ? rows.map((f) => html`<tr><td><button class="addr" type="button" data-lookup="${f.hash}">${f.id}</button></td><td>${H.sev(f.severity)}</td><td class="num muted">${H.date(f.t)}</td><td>${H.status(f.status)}</td></tr>`).join('')
          : String(html`<tr><td colspan="4"><div class="tbl-empty"><b>No credited findings yet</b>Findings appear here once they validate.</div></td></tr>`);
      }
      const off = H.data.subscribe(draw); draw();
      return off;
    },
  };

  /* ================= public ledger ================= */
  H.pages.ledger = {
    title: 'Public ledger — Hyblis',
    mount(root) {
      const st = { q: '', status: 'all', sev: 'all', n: 50 };
      const STAT = ['all', 'validated', 'under_review', 'accepted', 'screening', 'reproducing', 'duplicate', 'rejected'];
      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div class="eyebrow" data-scramble>Transparency</div>
  <h1 class="display">Public <span class="grad-text">ledger</span></h1>
  <p class="lede">Every submission, with its hash, time, status and severity. The contents of a report stay private; its hash was committed the moment it arrived.</p>
</div></section>
<section class="body"><div class="wrap">
  <div class="toolbar">
    <label class="search"><span class="sr-only">Search by hash</span>${H.icon('i-search', 16)}<input class="input mono" id="ld-q" type="search" placeholder="Search by submission hash" autocomplete="off" spellcheck="false"></label>
    <label class="sr-only" for="ld-status">Status</label>
    <select class="select" id="ld-status" style="flex:0 1 200px">${STAT.map((s) => html`<option value="${s}">${s === 'all' ? 'Any status' : H.statusLabel(s)}</option>`)}</select>
    <label class="sr-only" for="ld-sev">Severity</label>
    <select class="select" id="ld-sev" style="flex:0 1 180px"><option value="all">Any severity</option>${H.SEV.map((s) => html`<option value="${s}">${H.cap(s)}</option>`)}</select>
  </div>
  <div class="tbl-wrap"><table class="tbl" style="min-width:820px">
    <thead><tr><th>Submission</th><th>Received</th><th>Severity</th><th>Researcher</th><th>Status</th></tr></thead>
    <tbody id="ld-body"></tbody></table></div>
  <div class="tbl-foot"><span id="ld-count"></span><button class="btn btn-ghost btn-sm" type="button" id="ld-more" hidden>Show more</button></div>
</div></section>`;
      function draw() {
        const all = H.data.cache.ledger.slice().sort((a, b) => b.t - a.t), ready = H.data.loaded();
        const rows = all.filter((r) => (!st.q || r.hash.indexOf(st.q) >= 0) && (st.status === 'all' || r.status === st.status) && (st.sev === 'all' || r.severity === st.sev));
        $('#ld-body', root).innerHTML = rows.length ? rows.slice(0, st.n).map((r) => html`<tr>
            <td><button class="addr" type="button" data-copy="${r.hash}" data-copied="Hash copied" title="${r.hash}">${r.id}${H.icon('i-copy', 13)}</button></td>
            <td class="num muted" title="${H.dateTime(r.t)}">${H.timeAgo(r.t)}</td><td>${H.sev(r.severity)}</td>
            <td>${r.hotkey ? html`<a class="who" href="#researcher-${r.hotkey}">${H.identicon(r.hotkey, 24)}<span class="mono" style="font-size:13px">${H.short(r.hotkey, 6, 4)}</span></a>` : html`<span class="faint">—</span>`}</td>
            <td>${H.status(r.status)}</td></tr>`).join('')
          : String(html`<tr><td colspan="5">${!ready ? H.ui.loadFail('the ledger') : html`<div class="tbl-empty"><b>${all.length ? 'Nothing matches' : H.data.intakeOpen() ? 'The ledger is empty' : 'The ledger opens at launch'}</b>${all.length ? 'Change the filters or search for a different hash.' : H.data.intakeOpen() ? 'The first submission will appear here.' : 'From the first report at mainnet launch, every submission gets its public line here: hash, time, status and severity.'}</div>`}</td></tr>`);
        $('#ld-count', root).textContent = ready ? 'Showing ' + Math.min(st.n, rows.length) + ' of ' + rows.length + ' submission' + (rows.length === 1 ? '' : 's') : '';
        $('#ld-more', root).hidden = rows.length <= st.n;
      }
      const offs = [H.data.subscribe(draw)];
      $('#ld-q', root).addEventListener('input', H.debounce((e) => { st.q = e.target.value.trim().toLowerCase(); st.n = 50; draw(); }, 120));
      $('#ld-status', root).addEventListener('change', (e) => { st.status = e.target.value; st.n = 50; draw(); });
      $('#ld-sev', root).addEventListener('change', (e) => { st.sev = e.target.value; st.n = 50; draw(); });
      $('#ld-more', root).addEventListener('click', () => { st.n += 50; draw(); });
      draw();
      return () => offs.forEach((fn) => fn());
    },
  };
})();
