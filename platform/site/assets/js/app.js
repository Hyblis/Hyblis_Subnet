/* Hyblis site — boot and hash router.
 * Routes are plain hash names (letters, digits, hyphens): #home, #programs, #program-<id>,
 * #competitions, #leaderboard, #researcher-<hotkey>, #ledger, #submit, #submit-<id>, #dashboard, #guide.
 */
(function () {
  'use strict';
  const H = window.Hyblis, $ = H.$;
  const ROUTES = [
    [/^(?:home)?$/, 'home'], [/^programs$/, 'programs'], [/^program-([a-z0-9][a-z0-9-]{0,39})$/, 'program'],
    [/^competitions$/, 'competitions'], [/^leaderboard$/, 'leaderboard'], [/^researcher-([1-9A-HJ-NP-Za-km-z]{40,60})$/, 'researcher'],
    [/^ledger$/, 'ledger'], [/^submit(?:-([a-z0-9][a-z0-9-]{0,39}))?$/, 'submit'], [/^dashboard$/, 'dashboard'], [/^guide$/, 'guide'],
  ];
  let cleanup = null, first = true;

  function parse() {
    const raw = (location.hash || '').replace(/^#\/?/, '');
    let h;
    // a malformed escape (a stray % in a typed or cut-off link) is just an unknown page
    try { h = decodeURIComponent(raw); } catch (e) { return { page: 'notfound', params: [], hash: raw }; }
    for (const [re, page] of ROUTES) { const m = h.match(re); if (m) return { page, params: m.slice(1).filter((x) => x != null), hash: h }; }
    return { page: 'notfound', params: [], hash: h };
  }

  H.doJump = function () {
    const id = H.jump; H.jump = null;
    if (!id) return;
    const el = document.getElementById(id);
    // This runs after swap() has focused <main>, so keyboard focus ends on the section itself.
    if (el) requestAnimationFrame(() => {
      el.setAttribute('tabindex', '-1');
      el.scrollIntoView({ behavior: H.reduced ? 'auto' : 'smooth', block: 'start' });
      el.focus({ preventScroll: true });
    });
  };

  function swap(route) {
    const view = $('#view');
    if (cleanup) { try { cleanup(); } catch (e) { console.error(e); } cleanup = null; }
    const page = H.pages[route.page];
    document.body.setAttribute('data-page', route.page);
    document.body.setAttribute('data-mode', route.page === 'home' ? 'hero' : 'ambient');
    if (H.sceneCtl) H.sceneCtl.setRoute(route.page === 'home' ? 'hero' : 'ambient');
    H.ui.setActive(route.page);
    H.ui.closeMenus();
    H.ui.closeModals();
    if (!page) {
      view.innerHTML = H.html`<section class="phero"><div class="wrap phero-in"><div class="eyebrow">Not found</div><h1 class="display">This page does not exist</h1><p class="lede">The link may be old, or the program may not be open yet.</p><div class="cta"><a class="btn btn-grad btn-lg" href="#home">Back to the start</a><a class="btn btn-ghost btn-lg" href="#programs">Explore programs</a></div></div></section>`;
      document.title = 'Not found — Hyblis';
    } else {
      document.title = page.title;
      const c1 = page.mount(view, route) || null;
      const c2 = H.fx.scan(view);
      cleanup = () => { if (typeof c1 === 'function') c1(); c2(); };
    }
    if (!H.jump) window.scrollTo(0, 0);
    H.doJump();
    const an = $('#announcer'); if (an) an.textContent = document.title;
    if (!first) view.focus({ preventScroll: true });
    first = false;
  }

  function navigate() {
    const route = (H.route = parse());
    const view = $('#view');
    if (first || H.reduced) { swap(route); return; }
    if (document.startViewTransition) {
      // A transition is skipped when another navigation starts or the tab is hidden; the page
      // has still been swapped, so those rejections are expected and safe to ignore.
      let done = false;
      const run = () => { if (!done) { done = true; swap(route); } };
      try {
        const t = document.startViewTransition(run);
        [t.ready, t.finished, t.updateCallbackDone].forEach((p) => { if (p && p.catch) p.catch(() => {}); });
      } catch (e) { run(); }
      return;
    }
    view.classList.add('leaving');
    setTimeout(() => {
      view.classList.remove('leaving'); swap(route);
      view.classList.add('entering'); setTimeout(() => view.classList.remove('entering'), 460);
    }, 160);
  }

  function mountScene() {
    const canvas = $('#bg3d');
    if (!canvas || !window.HyblisScene || H.store.get('scene', 'on') === 'off') return;
    const small = Math.min(window.innerWidth, window.innerHeight) < 500;
    const lowPower = (navigator.hardwareConcurrency || 8) <= 4 || (navigator.deviceMemory || 8) <= 4;
    try {
      H.sceneCtl = window.HyblisScene.mount(canvas, { quality: small || lowPower ? 'low' : 'high', reducedMotion: H.reduced, seed: 7 });
    } catch (e) { console.error('3D background failed to start', e); H.sceneCtl = null; }
    if (!H.sceneCtl) canvas.style.display = 'none';
  }

  async function boot() {
    await H.data.init();
    H.ui.init();
    mountScene();
    H.fx.global();
    H.data.subscribe(H.ui.renderStatus, { always: true });
    // a finding that validates makes the 3D scene flare, and tells the visitor
    H.data.onEvents((events) => {
      const hit = events.filter((e) => e.row.status === 'validated');
      if (hit.length && H.sceneCtl) H.sceneCtl.pulse();
      const mine = H.data.receipts.all();
      events.forEach((e) => { if (e.type === 'status' && mine.some((r) => r.id === e.row.hash)) H.toast('Your report ' + H.short(e.row.hash, 8, 0) + ' is ' + H.statusLabel(e.row.status).toLowerCase(), e.row.status === 'rejected' ? 'bad' : 'ok'); });
    });
    await H.data.refresh();
    H.wallet.restore();
    window.addEventListener('hashchange', navigate);
    // Polling starts first, so a page that fails to mount cannot stop the data refresh.
    H.data.start();
    setInterval(() => { if (!document.hidden) H.tickAgo(); }, 30000);
    navigate();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
