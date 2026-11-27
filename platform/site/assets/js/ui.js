/* Hyblis site — shared interface: navigation, modals, wallet dialog, report lookup. */
(function () {
  'use strict';
  const H = window.Hyblis, html = H.html, $ = H.$, $$ = H.$$;
  const ui = (H.ui = {});

  /* ---------- modal ---------- */
  let openModal = null;
  ui.modal = function (opts) {
    if (openModal) openModal.close();
    const root = document.getElementById('modal-root');
    const back = document.createElement('div');
    back.className = 'modal-back';
    const lastFocus = document.activeElement;
    back.innerHTML = html`<div class="modal ${opts.wide ? 'wide' : ''} ${opts.cls || ''}" role="dialog" aria-modal="true" aria-label="${opts.title || 'Dialog'}">
      ${opts.bare ? '' : html`<div class="modal-head"><h2 class="h4">${opts.title}</h2><button class="iconbtn" type="button" data-close aria-label="Close">${H.icon('i-x', 14)}</button></div>`}
      <div class="${opts.bare ? '' : 'modal-body'}" data-body></div></div>`;
    root.appendChild(back);
    const body = $('[data-body]', back);
    const api = {
      el: back, body,
      set(content) { body.innerHTML = content; },
      // routed === true: the page is changing, and swap() moves focus to the new page itself
      close(routed) {
        if (openModal !== api) return;
        openModal = null;
        document.removeEventListener('keydown', onKey, true);
        back.classList.remove('in');
        // While it fades out, the old dialog must not catch input or clash with the next one.
        back.inert = true;
        back.style.pointerEvents = 'none';
        $$('[id]', back).forEach((el) => el.removeAttribute('id'));
        document.documentElement.style.overflow = '';
        setTimeout(() => { if (back.parentNode) back.parentNode.removeChild(back); }, 240);
        if (opts.onClose) opts.onClose();
        if (routed === true) return;
        // Focus goes back to the control that opened the dialog; if that is gone or hidden, to the page.
        const to = lastFocus && lastFocus !== document.body && lastFocus.isConnected ? lastFocus : null;
        if (to && to.focus) to.focus();
        if (!to || document.activeElement !== to) { const v = $('#view'); if (v) v.focus({ preventScroll: true }); }
      },
    };
    function onKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); api.close(); return; }
      if (opts.onKey && opts.onKey(e) === true) return;
      if (e.key !== 'Tab') return;
      const f = $$('a[href],button:not([disabled]),input,select,textarea,[tabindex]:not([tabindex="-1"])', back).filter((x) => x.offsetParent !== null);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      // focus is still outside (on the opener behind the backdrop): bring it into the dialog
      if (!back.contains(document.activeElement)) { e.preventDefault(); (e.shiftKey ? last : first).focus(); return; }
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
    back.addEventListener('mousedown', (e) => { if (e.target === back) api.close(); });
    H.on(back, 'click', '[data-close]', () => api.close());
    document.addEventListener('keydown', onKey, true);
    document.documentElement.style.overflow = 'hidden';
    openModal = api;
    if (opts.body != null) api.set(opts.body);
    if (opts.onOpen) opts.onOpen(api);
    requestAnimationFrame(() => {
      if (openModal !== api) return;
      back.classList.add('in');
      // the first control, or the close button when the dialog has nothing else to press
      const f = $('[autofocus],input,button:not([data-close])', back) || $('[data-close]', back);
      if (f) f.focus();
    });
    return api;
  };
  // Route changes close any open dialog.
  ui.closeModals = () => { if (openModal) openModal.close(true); };
  // Shown where a page would otherwise state an empty-data fact before any data has loaded.
  ui.loadFail = (what) => html`<div class="tbl-empty"><b>Could not load ${what}</b>The page retries on its own. If this does not clear, check your connection.</div>`;

  /* ---------- wallet dialog ---------- */
  ui.walletDialog = function (after) {
    const w = H.wallet;
    const m = ui.modal({ title: w.state.address ? 'Your wallet' : 'Connect a wallet', onOpen: draw });
    function draw(api) {
      api = api || m;
      if (w.state.address) {
        api.set(html`<p>Reports are signed by the selected account. Use the hotkey registered on the Hyblis subnet: emission for accepted findings is paid to it.</p>
          <div class="wlist">${w.state.accounts.map((a) => html`<button class="wopt ${a.address === w.state.address ? 'on' : ''}" type="button" data-pick="${a.address}">
            ${H.identicon(a.address, 36)}<span class="txt"><b>${a.name}</b><span>${H.short(a.address, 10, 8)}</span></span>${a.address === w.state.address ? H.icon('i-check', 16) : ''}</button>`)}</div>
          <div class="form-nav"><button class="btn btn-ghost" type="button" data-disc>Disconnect</button><button class="btn btn-grad" type="button" data-close>Done</button></div>`);
        return;
      }
      const exts = w.extensions();
      api.set(exts.length ? html`<p>${H.cfg.demo ? 'This is the design preview. The preview wallet signs nothing and sends nothing.' : 'Choose the wallet extension that holds your miner hotkey. Hyblis never sees your keys; the wallet only signs a short message for each report.'}</p>
          <div class="wlist">${exts.map((x) => html`<button class="wopt" type="button" data-ext="${x.id}"><span class="mile"><span class="dot">${H.icon('i-wallet', 18)}</span></span><span class="txt"><b>${x.title}</b><span>${x.demo ? 'sample account' : 'browser extension'}</span></span>${H.icon('i-arrow', 16)}</button>`)}</div>
          <p class="err" data-err style="margin-top:14px;color:var(--crit)" hidden></p>`
        : html`<p>No Polkadot-compatible wallet extension was found in this browser.</p>
          <div class="notice info" style="margin-top:16px">${H.icon('i-wallet', 18)}<span>Install <b>Talisman</b>, <b>SubWallet</b> or <b>polkadot&#123;.js&#125;</b>, import your miner hotkey (sr25519), then reload this page. Prefer the terminal? The command-line miner signs and submits the same report.</span></div>
          <div class="form-nav"><span></span><button class="btn btn-ghost" type="button" data-close>Close</button></div>`);
    }
    H.on(m.el, 'click', '[data-ext]', async (e, t) => {
      t.classList.add('on'); const err = $('[data-err]', m.el);
      try {
        await w.connect(t.dataset.ext); H.toast('Wallet connected', 'ok');
        // one usable account: nothing to choose, so get out of the way; several: let the visitor pick the hotkey
        if (w.state.accounts.length === 1 || after) { m.close(); if (after) after(); } else draw();
      }
      catch (ex) { t.classList.remove('on'); if (err) { err.hidden = false; err.textContent = ex && ex.message ? ex.message : 'The wallet refused the connection.'; } }
    });
    H.on(m.el, 'click', '[data-pick]', (e, t) => { w.select(t.dataset.pick); draw(); });
    H.on(m.el, 'click', '[data-disc]', () => { w.disconnect(); H.toast('Wallet disconnected'); m.close(); });
    return m;
  };

  /* ---------- scoring policy dialog ---------- */
  ui.policyDialog = async function () {
    const m = ui.modal({ title: 'Scoring policy', wide: true, body: html`<p>Loading the published policy…</p>` });
    const p = await H.data.policy();
    if (!p) { m.set(html`<p>The policy file could not be loaded right now.</p>`); return; }
    const pct = (x) => Math.round((x || 0) * 100) + '%';
    const pts = Object.keys(p.severity_points || {}).map((k) => H.cap(k) + ' ' + p.severity_points[k]).join(' · ');
    const rows = p.pools ? [
      ['Policy version', p.version], ['How miners are paid', 'Straight through the subnet\u2019s weights every epoch; nothing is held in a team key'],
      ['Validated findings', pct(p.pools.validated) + ' of the miner pool, by measured severity, fading over ' + p.validated_expiry_days + ' days'],
      ['Acceptance bonus', pct(p.pools.accepted) + ' of the miner pool, by final severity, for ' + p.accepted_expiry_days + ' days after the program accepts'],
      ['Warm-up track', pct(p.pools.warmup) + ' of the miner pool, one reward per reproduced past exploit, for ' + p.warmup_expiry_days + ' days'],
      ['Points by severity', pts], ['Empty pool', 'Its share passes to the other pools, so the whole pool goes to miners who earned'],
      ...(p.miner_burn > 0 ? [['Miner burn', pct(p.miner_burn) + ' of the miner pool is burned (sent to the owner UID) whenever miners earned']] : []),
      ['Strikes before suspension', p.strikes_to_suspend],
    ] : [
      ['Policy version', p.version], ['Points by severity', pts],
      ['Provisional share before platform acceptance', pct(p.provisional_fraction)],
      ['Pool share per point', ((p.share_per_point || 0) * 100).toFixed(1) + '%'], ['Half-life', p.half_life_days + ' days'], ['Expiry', p.expiry_days + ' days'],
      ['Cap per program', pct(p.program_cap) + ' of the pool'], ['Strikes before suspension', p.strikes_to_suspend],
    ];
    m.set(html`<p>Weights and leaderboard scores come from this policy, applied to the public scoring ledger. The same inputs always give the same result.</p>
      <dl class="review card" style="margin-top:18px">${rows.map((r) => html`<div><dt class="label" style="width:230px">${r[0]}</dt><dd>${r[1]}</dd></div>`)}</dl>`);
  };

  /* ---------- submission lookup ---------- */
  ui.lookup = async function (id) {
    const m = ui.modal({ title: 'Submission ' + H.short(id, 10, 0), body: html`<p>Looking it up on the public ledger…</p>` });
    let s = null;
    try { s = await H.data.submissionStatus(id); } catch (e) { m.set(html`<p>The ledger could not be reached. Try again in a moment.</p>`); return; }
    if (!s) { m.set(html`<p>No submission starts with <span class="mono">${id}</span>. Paste at least the first 12 characters of the hash.</p>`); return; }
    m.set(html`<dl class="review card">
      <div><dt class="label">Hash</dt><dd class="mono" style="font-size:12.5px">${s.hash}</dd></div>
      <div><dt class="label">Status</dt><dd>${H.status(s.status)}</dd></div>
      <div><dt class="label">Severity</dt><dd>${H.sev(s.severity)}</dd></div>
      <div><dt class="label">Received</dt><dd>${H.dateTime(s.t)}</dd></div></dl>
      <div class="form-nav"><button class="iconbtn" type="button" data-copy="${s.hash}">${H.icon('i-copy', 14)}Copy hash</button><a class="btn btn-ghost" href="#ledger" data-close>Open the ledger</a></div>`);
  };

  /* ---------- look up a report by its hash ---------- */
  ui.lookupPrompt = function () {
    const m = ui.modal({
      title: 'Look up a report',
      body: html`<form class="field" id="lk-form" novalidate>
        <label for="lk-q">Submission hash</label>
        <input class="input mono" id="lk-q" type="text" autocomplete="off" spellcheck="false" placeholder="Paste the hash from your receipt" autofocus>
        <span class="err" id="lk-err" role="alert"></span>
        <button class="btn btn-grad" type="submit" style="margin-top:6px;align-self:flex-start">Look up</button></form>`,
    });
    const q = $('#lk-q', m.el), err = $('#lk-err', m.el);
    if (q) q.focus();
    $('#lk-form', m.el).addEventListener('submit', (e) => {
      e.preventDefault();
      const v = q.value.trim().toLowerCase().replace(/^0x/, '');
      if (!/^[0-9a-f]{12,64}$/.test(v)) { err.textContent = 'A submission hash is 12 to 64 hexadecimal characters.'; q.focus(); return; }
      ui.lookup(v);
    });
  };

  /* ---------- navigation chrome ---------- */
  ui.setActive = function (page) {
    const group = { programs: 'programs', program: 'programs', competitions: 'competitions', leaderboard: 'researchers', researcher: 'researchers', ledger: 'researchers', dashboard: 'researchers', submit: 'researchers', guide: 'researchers' }[page] || '';
    $$('[data-nav]').forEach((el) => el.classList.toggle('on', el.dataset.nav === group));
  };
  function closeMenus() {
    $$('.dd.open').forEach((d) => { d.classList.remove('open'); $('.dd-btn', d).setAttribute('aria-expanded', 'false'); });
  }
  function closeMobile() { const mm = $('#mobile-menu'), b = $('#burger'); if (mm && !mm.hidden) { mm.hidden = true; b.setAttribute('aria-expanded', 'false'); b.setAttribute('aria-label', 'Open menu'); } }
  ui.closeMenus = () => { closeMenus(); closeMobile(); };

  ui.renderLogin = function () {
    const a = H.wallet.state.address;
    const b = $('#btn-login'), m = $('#btn-login-m');
    if (b) {
      b.innerHTML = a ? html`${H.identicon(a, 16)}${H.short(a, 5, 4)}` : 'Log in';
      b.setAttribute('aria-label', a ? 'Wallet ' + a : 'Log in with a wallet');
    }
    if (m) m.textContent = a ? 'Wallet ' + H.short(a, 5, 4) : 'Log in';
  };
  ui.renderStatus = function (c) {
    // the footer line is the only status display (the top status bar was removed)
    const ft = $('#foot-updated'); if (!ft) return;
    if (H.cfg.demo) { ft.textContent = 'Preview with sample data'; return; }
    if (!c.ok || !c.summary) { ft.textContent = 'Ledger unreachable · retrying'; return; }
    ft.textContent = (H.data.intakeOpen() ? 'Ledger updated ' : 'Updated ') + H.ago(c.summary.generated_at);
  };

  ui.init = function () {
    // dropdowns: click toggles; hover opens on fine pointers; Escape and outside click close
    $$('.dd').forEach((dd) => {
      const btn = $('.dd-btn', dd);
      const open = (v) => { if (v) closeMenus(); dd.classList.toggle('open', v); btn.setAttribute('aria-expanded', v ? 'true' : 'false'); };
      let hoverAt = 0;
      // A click right after the pointer opened the menu must not close it again.
      btn.addEventListener('click', (e) => { e.stopPropagation(); open(Date.now() - hoverAt < 600 ? true : !dd.classList.contains('open')); });
      if (H.finePointer) { let t; dd.addEventListener('pointerenter', () => { clearTimeout(t); if (!dd.classList.contains('open')) hoverAt = Date.now(); open(true); }); dd.addEventListener('pointerleave', () => { t = setTimeout(() => open(false), 160); }); }
      dd.addEventListener('keydown', (e) => {
        const links = $$('.dd-menu a', dd), i = links.indexOf(document.activeElement);
        if (e.key === 'Escape') { open(false); btn.focus(); }
        else if (e.key === 'ArrowDown') { e.preventDefault(); open(true); (links[i + 1] || links[0]).focus(); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); open(true); (links[i - 1] || links[links.length - 1]).focus(); }
      });
      // tabbing out of the menu closes it
      dd.addEventListener('focusout', (e) => { if (dd.classList.contains('open') && e.relatedTarget && !dd.contains(e.relatedTarget)) open(false); });
    });
    document.addEventListener('click', (e) => { if (!e.target.closest('.dd')) closeMenus(); });
    const burger = $('#burger'), mm = $('#mobile-menu');
    burger.addEventListener('click', () => { const v = mm.hidden; mm.hidden = !v; burger.setAttribute('aria-expanded', v ? 'true' : 'false'); burger.setAttribute('aria-label', v ? 'Close menu' : 'Open menu'); });
    // the current page's link changes no route, so every link closes the menu itself
    H.on(mm, 'click', 'a', closeMobile);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !e.defaultPrevented && !mm.hidden) { closeMobile(); burger.focus(); } });
    // The skip link moves focus to the page without changing the route.
    H.on(document, 'click', 'a.skip', (e) => { e.preventDefault(); $('#view').focus(); });

    $('#btn-login').addEventListener('click', () => ui.walletDialog());
    $('#btn-login-m').addEventListener('click', () => { closeMobile(); ui.walletDialog(); });

    // delegated actions used across pages
    H.on(document, 'click', '[data-copy]', (e, t) => { e.preventDefault(); H.copy(t.dataset.copy, t.dataset.copied || 'Copied'); });
    H.on(document, 'click', '[data-action="policy"]', (e) => { e.preventDefault(); ui.closeMenus(); ui.policyDialog(); });
    H.on(document, 'click', '[data-action="wallet"]', (e) => { e.preventDefault(); ui.walletDialog(); });
    H.on(document, 'click', '[data-action="lookup"]', (e) => { e.preventDefault(); ui.lookupPrompt(); });
    H.on(document, 'click', '[data-jump]', (e, t) => { e.preventDefault(); ui.closeMenus(); H.jump = t.dataset.jump; if (H.route && H.route.page === 'home') H.doJump(); else H.go('home'); });
    H.on(document, 'click', '[data-lookup]', (e, t) => { e.preventDefault(); ui.lookup(t.dataset.lookup); });

    H.wallet.onChange(ui.renderLogin);
    ui.renderLogin();
  };
})();
