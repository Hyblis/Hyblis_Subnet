/* Hyblis site — effects. All of them are optional polish: with reduced motion (or without JS)
 * the page is fully readable and nothing stays hidden.
 *
 *   scan(root)   wire the per-page effects under root; returns a cleanup function
 *     [data-reveal]            fade/slide in when scrolled into view (only below-the-fold elements start hidden)
 *     [data-stagger]           its [data-reveal] children come in one after another
 *     [data-count="42"]        count up (data-decimals, data-prefix, data-suffix)
 *     [data-scramble]          "decode" the text once
 *     [data-magnetic]          the button leans toward the pointer
 *     [data-tilt]              3D tilt toward the pointer
 *     .spot                    pointer-following highlight (CSS reads --mx / --my)
 *     [data-parallax="0.15"]   drifts with scroll
 *   global()     scroll progress bar, header hide/show, pointer + scroll feeds for the 3D scene
 *   typer(el, lines, opts)     terminal typing
 */
(function () {
  'use strict';
  const H = window.Hyblis;
  const fx = (H.fx = {});
  fx.disabled = /(?:^|[?&])fx=off(?:&|$)/.test(location.search.slice(1));   // ?fx=off shows the settled page
  const off = () => H.reduced || fx.disabled;

  /* ---------- count up ---------- */
  function countTo(el, to) {
    const dec = parseInt(el.dataset.decimals || '0', 10), pre = el.dataset.prefix || '', suf = el.dataset.suffix || '';
    const from = parseFloat(el.dataset.shown || '0') || 0;
    el.dataset.shown = String(to);
    const put = (v) => { el.textContent = pre + H.num(v, dec) + suf; };
    if (off() || from === to) { put(to); return; }
    const t0 = performance.now(), dur = 1300;
    (function step(now) {
      const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(2, -10 * p);
      put(from + (to - from) * (p >= 1 ? 1 : e));
      if (p < 1) requestAnimationFrame(step);
    })(t0);
  }
  fx.countTo = countTo;

  /* ---------- scramble / decode ---------- */
  const GLYPHS = '!<>-_\\/[]{}=+*^?#01';
  function scramble(el, dur) {
    const final = el.dataset.text || el.textContent;
    el.dataset.text = final;
    if (off()) { el.textContent = final; return; }
    el.setAttribute('aria-label', final);
    const t0 = performance.now(); dur = dur || Math.min(1100, 380 + final.length * 16);
    (function step(now) {
      const p = Math.min(1, (now - t0) / dur), n = Math.floor(p * final.length);
      let out = final.slice(0, n);
      for (let i = n; i < final.length; i++) { const c = final[i]; out += c === ' ' || c === '\n' ? c : GLYPHS[(Math.random() * GLYPHS.length) | 0]; }
      el.textContent = out;
      if (p < 1) requestAnimationFrame(step); else el.textContent = final;
    })(t0);
  }
  fx.scramble = scramble;

  /* ---------- terminal typing ---------- */
  // lines: [{ text, cls, wait (ms before this line), type (bool: type char by char) }]
  fx.typer = function (el, lines, opts) {
    opts = opts || {};
    let timers = [], alive = true;
    const later = (fn, ms) => { const t = setTimeout(() => { if (alive) fn(); }, ms); timers.push(t); };
    function clear() { timers.forEach(clearTimeout); timers = []; }
    function line(l) { const s = document.createElement('span'); s.className = 'tl ' + (l.cls || ''); el.appendChild(s); return s; }
    function finish() { el.textContent = ''; lines.forEach((l, i) => { line(l).textContent = l.text; if (opts.onLine) opts.onLine(i, l, true); }); if (opts.onDone) opts.onDone(); }
    function play() {
      clear(); el.textContent = '';
      if (off()) { finish(); return; }
      let at = 250;
      lines.forEach((l, i) => {
        at += l.wait == null ? 420 : l.wait;
        if (l.type) {
          const startAt = at;
          later(() => { const s = line(l); const caret = document.createElement('i'); caret.className = 'caret';
            let k = 0; (function tick() { if (!alive) return; s.textContent = l.text.slice(0, ++k); s.appendChild(caret); if (k < l.text.length) timers.push(setTimeout(tick, 22)); else { caret.remove(); if (opts.onLine) opts.onLine(i, l, false); } })();
          }, startAt);
          at += l.text.length * 22 + 200;
        } else {
          later(() => { line(l).textContent = l.text; if (opts.onLine) opts.onLine(i, l, false); }, at);
        }
      });
      later(() => { if (opts.onDone) opts.onDone(); }, at + 300);
    }
    play();
    return { replay: play, stop() { alive = false; clear(); } };
  };

  /* ---------- per-page wiring ---------- */
  fx.scan = function (root) {
    const cleanups = [];
    const vh = window.innerHeight || 800;

    // stagger indices
    H.$$('[data-stagger]', root).forEach((p) => { H.$$('[data-reveal]', p).forEach((c, i) => c.style.setProperty('--i', i)); });

    const enter = (el) => {
      el.classList.remove('pre'); el.classList.add('is-in');
      if (el.dataset.count != null) countTo(el, parseFloat(el.dataset.count));
      H.$$('[data-count]', el).forEach((c) => countTo(c, parseFloat(c.dataset.count)));
      if (el.dataset.scramble != null) scramble(el);
      H.$$('[data-scramble]', el).forEach((c) => scramble(c));
      el.dispatchEvent(new CustomEvent('fx:in'));
    };
    const targets = H.$$('[data-reveal], [data-count], [data-scramble], [data-watch]', root)
      .filter((el) => !el.parentElement.closest('[data-reveal]') || el.hasAttribute('data-reveal'));
    if (off() || !('IntersectionObserver' in window)) targets.forEach(enter);
    else {
      const io = new IntersectionObserver((entries) => {
        entries.forEach((en) => { if (en.isIntersecting) { io.unobserve(en.target); enter(en.target); } });
      }, { threshold: 0.12, rootMargin: '0px 0px -6% 0px' });
      targets.forEach((el) => {
        const r = el.getBoundingClientRect();
        // Only elements that start below the fold are hidden first; what is on screen stays visible.
        if (r.top > vh * 0.92 && el.hasAttribute('data-reveal')) el.classList.add('pre');
        io.observe(el);
      });
      cleanups.push(() => io.disconnect());
    }

    if (H.finePointer && !off()) {
      // spotlight: one delegated listener
      const move = (e) => {
        const s = e.target.closest && e.target.closest('.spot'); if (!s) return;
        const r = s.getBoundingClientRect();
        s.style.setProperty('--mx', (e.clientX - r.left) + 'px'); s.style.setProperty('--my', (e.clientY - r.top) + 'px');
      };
      root.addEventListener('pointermove', move, { passive: true });
      cleanups.push(() => root.removeEventListener('pointermove', move));

      H.$$('[data-magnetic]', root).forEach((el) => {
        const mv = (e) => { const r = el.getBoundingClientRect(); const x = (e.clientX - r.left - r.width / 2) / r.width, y = (e.clientY - r.top - r.height / 2) / r.height; el.style.transform = 'translate(' + (x * 10).toFixed(1) + 'px,' + (y * 8).toFixed(1) + 'px)'; };
        const lv = () => { el.style.transform = ''; };
        el.addEventListener('pointermove', mv); el.addEventListener('pointerleave', lv);
      });
      H.$$('[data-tilt]', root).forEach((el) => {
        const mv = (e) => { const r = el.getBoundingClientRect(); const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5; el.style.transform = 'perspective(900px) rotateX(' + (-y * 5).toFixed(2) + 'deg) rotateY(' + (x * 6).toFixed(2) + 'deg) translateZ(0)'; };
        const lv = () => { el.style.transform = ''; };
        el.addEventListener('pointermove', mv); el.addEventListener('pointerleave', lv);
      });
    }

    const par = H.$$('[data-parallax]', root);
    if (par.length && !off()) {
      const onScroll = () => { const y = window.scrollY; par.forEach((el) => { el.style.transform = 'translate3d(0,' + (y * parseFloat(el.dataset.parallax || '0.1')).toFixed(1) + 'px,0)'; }); };
      window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
      cleanups.push(() => window.removeEventListener('scroll', onScroll));
    }
    return () => cleanups.forEach((fn) => fn());
  };

  // Reveal everything now (used by tests and full-page captures).
  fx.revealAll = function () { H.$$('.pre').forEach((el) => { el.classList.remove('pre'); el.classList.add('is-in'); }); };

  /* ---------- global: progress bar, header, feeds for the 3D scene ---------- */
  fx.global = function () {
    const nav = document.getElementById('nav'), bar = document.getElementById('progress');
    let lastY = window.scrollY, ticking = false;
    function frame() {
      ticking = false;
      const y = window.scrollY, max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
      if (bar) bar.style.setProperty('--p', (y / max).toFixed(4));
      if (nav) {
        nav.classList.toggle('is-scrolled', y > 8);
        const menuOpen = !document.getElementById('mobile-menu').hidden || !!document.querySelector('.dd.open');
        if (y > 420 && y > lastY + 6 && !menuOpen) nav.classList.add('is-hidden');
        else if (y < lastY - 6 || y <= 420) nav.classList.remove('is-hidden');
      }
      lastY = y;
      // the scene recedes while the visitor scrolls past the first screen
      const p = H.clamp(y / Math.max(320, window.innerHeight * 0.9), 0, 1);
      if (H.sceneCtl) H.sceneCtl.setScroll(p);
      document.documentElement.style.setProperty('--scene-o', (1 - 0.72 * p).toFixed(3));
    }
    window.addEventListener('scroll', () => { if (!ticking) { ticking = true; requestAnimationFrame(frame); } }, { passive: true });
    window.addEventListener('resize', H.debounce(frame, 120));
    frame();

    if (H.finePointer && !off()) {
      window.addEventListener('pointermove', (e) => {
        const nx = (e.clientX / window.innerWidth) * 2 - 1, ny = (e.clientY / window.innerHeight) * 2 - 1;
        if (H.sceneCtl) H.sceneCtl.setPointer(nx, ny);
        const hero = document.querySelector('.hero');
        if (hero) { const r = hero.getBoundingClientRect(); hero.style.setProperty('--gx', (e.clientX - r.left) + 'px'); hero.style.setProperty('--gy', (e.clientY - r.top) + 'px'); hero.style.setProperty('--go', '1'); }
      }, { passive: true });
    }
  };
})();
