/* Hyblis site — home page. */
(function () {
  'use strict';
  const H = window.Hyblis, html = H.html, $ = H.$, $$ = H.$$;
  H.pages = H.pages || {};

  const PIPE = [
    ['Policy screen', 'Signature, file layout, scope and a static check for forbidden cheatcodes.'],
    ['Isolated rerun', 'A sandbox on the pinned fork runs the proof twice, then once as plain forge test. The runs must agree.'],
    ['Measured impact', 'Every cheatcode call is checked in Foundry\u2019s own trace. Impact is measured against a clean copy of the same block. Asserts are ignored.'],
    ['Program rules', 'Impact type, known issues and benign entry points are checked automatically.'],
    ['Severity', 'The lower of the claimed severity and the measured impact.'],
    ['Duplicates', 'Same contract, function and impact type: the earliest valid proof wins.'],
  ];
  const TERM = [
    { type: true, cls: 'tl-cmd', text: 'python hyblis_miner.py submit --task aave-v4 --poc HyblisPoC.t.sol', wait: 300 },
    { cls: 'tl-dim', text: 'signed with hotkey 5Fpj…Vgo6', wait: 450 },
    { cls: 'tl-dim', text: 'receipt   sha256 9c2e…a41f   hash and time committed', wait: 450 },
    { text: '[policy]    static screen .............. pass', step: 0, wait: 600 },
    { text: '[sandbox]   run 1 of 2 ................. ok', step: 1, wait: 750 },
    { text: '[sandbox]   run 2 of 2 ................. ok, identical', step: 1, wait: 750 },
    { text: '[sandbox]   plain forge test ........... pass, same calls', step: 1, wait: 550 },
    { text: '[trace]     every cheatcode call ....... allowed', step: 2, wait: 550 },
    { text: '[impact]    exploited vs clean fork .... measured', step: 2, wait: 650 },
    { text: '[rules]     scope and known issues ..... in scope', step: 3, wait: 600 },
    { text: '[severity]  min(claimed, measured) ..... medium', step: 4, wait: 550 },
    { text: '[dedup]     earliest valid proof ....... yes', step: 5, wait: 550 },
    { cls: 'tl-hot', text: 'VALIDATED   filed with the platform within 12 hours', step: 6, wait: 750 },
  ];
  const FAQ = [
    ['Do I need to submit a fix?', 'No. A submission is a valid finding plus a reproducible proof of concept. A fix is never required.'],
    ['Who decides if a finding is valid?', 'Code does. The runner runs your proof twice in an isolated sandbox on the pinned fork, then once as plain forge test. It checks every cheatcode call in Foundry’s own trace and measures the protocol against a clean copy of the same block. Your asserts are ignored. The bounty platform’s own acceptance is a second, independent check.'],
    ['Can I check my proof before I submit?', 'Yes. Each program page has hyblis check, the runner’s own code for your machine. Run it against your own RPC and it gives the verdict the runner would give, with the reason when it rejects.'],
    ['How do I see why a report was rejected?', 'Open your dashboard. Each rejected report shows the runner’s reason and, where it applies, the lines of your proof. Only you can see it: it is fetched with the receipt token kept in your browser.'],
    ['What happens with duplicates?', 'The earliest valid submission of the same bug wins the credit. Every submission is hash-committed and timestamped at intake.'],
    ['How and when am I paid?', 'In alpha (α), straight through the subnet’s weights every epoch (about 72 minutes). 60% of the miner pool follows findings the runner has validated, by measured severity; 25% is a bonus once the program accepts the finding; 15% goes to the warm-up track. Nothing is held in a team key.'],
    ['What is public and what stays private?', 'Public: the scoring code, the leaderboard, and the ledger of submission hashes, times, statuses, severities and scores. Private: the contents of a report, bounty amounts and payout amounts.'],
    ['Which wallet do I need?', 'Any Polkadot-compatible browser wallet that holds your miner hotkey (sr25519), such as Talisman, SubWallet or polkadot{.js}. You can also sign from the terminal with the command-line miner.'],
  ];

  function template() {
    return html`
<section class="hero" data-hero>
  <div class="ticks-v" aria-hidden="true"></div><div class="ticks-h" aria-hidden="true"></div>
  <div class="wrap hero-in">
    <div class="hero-copy">
      <div class="eyebrow" data-scramble>Bittensor subnet · Blockchain security</div>
      <h1 class="display hero-h1"><span class="line"><span>Your audit ends.</span></span><span class="line"><span class="grad-text">Attackers don't.</span></span></h1>
      <p class="lede">Live code keeps changing, and so do the attacks. Hyblis keeps a network of security researchers on it after launch. Every proof is reproduced in isolation and measured on-chain before it counts.</p>
      <div class="cta">
        <a class="btn btn-grad btn-lg" href="#programs" data-magnetic>Explore programs <svg class="ic ic-go" width="16" height="16" aria-hidden="true"><use href="#i-arrow"/></svg></a>
        <a class="btn btn-ghost btn-lg" href="#submit">Submit a report</a>
      </div>
      <div class="proof"><i></i><span id="hero-proof">Every proof reproduced twice before it counts</span></div>
    </div>
    <aside class="hud" aria-label="Ledger at a glance">
      <div class="hud-row"><span>Ledger</span><b id="hud-subs">—</b></div>
      <div class="hud-row"><span>Validated</span><b id="hud-val" class="hot">—</b></div>
      <div class="hud-row"><span>Last event</span><b id="hud-last">—</b></div>
      <div class="hud-row"><span>Next release</span><b id="hud-next">—</b></div>
      <div class="hud-bar" aria-hidden="true"><i></i></div>
    </aside>
    <button class="scroll-cue" type="button" data-scrollto="ticker" aria-label="Scroll to the live ledger"><i></i>Scroll</button>
  </div>
</section>

<div class="ticker" id="ticker" role="region" tabindex="0" aria-label="Latest ledger events"><div class="ticker-track" id="ticker-track"></div></div>

<section class="sec" aria-label="Ledger in numbers">
  <div class="wrap stats" data-stagger>
    <div class="stat" data-reveal><div class="stat-n" id="st-val" data-count="0">0</div><div class="stat-l">Validated findings on the public ledger</div></div>
    <div class="stat" data-reveal><div class="stat-n" id="st-acc" data-count="0">0</div><div class="stat-l">Accepted by the bounty platform</div></div>
    <div class="stat" data-reveal><div class="stat-n" id="st-res" data-count="0">0</div><div class="stat-l">Ranked researchers</div></div>
    <div class="stat" data-reveal><div class="stat-n" id="st-prog" data-count="0">0</div><div class="stat-l">Programs open for research</div></div>
  </div>
</section>

<section class="sec sec-alt">
  <div class="wrap">
    <div class="sec-head" data-reveal><div><div class="eyebrow" data-scramble>By design</div><h2 class="display h2" style="margin-top:14px">Built so the result<br>can't be argued with</h2></div></div>
    <div class="bento" data-stagger>
      <article class="card spot bento-card w7" data-reveal data-tilt>
        <div class="label">Reproduced twice</div><div class="bento-big grad-text">2×</div>
        <p>Every proof runs twice in a disposable sandbox on a pinned mainnet fork. Both runs must match before anything counts.</p>
        <div class="bento-viz twin" aria-hidden="true">
          <div class="twin-row"><span>RUN 1</span><span class="twin-track"><i></i></span><span class="twin-ok">OK</span></div>
          <div class="twin-row"><span>RUN 2</span><span class="twin-track"><i></i></span><span class="twin-ok">MATCH</span></div>
        </div>
      </article>
      <article class="card spot bento-card w5" data-reveal data-tilt>
        <div class="label">Measured, not claimed</div><h3 class="display h3">Impact comes from protocol state</h3>
        <p>The runner measures balances, invariants and withdrawals after your proof. Your own asserts are ignored.</p>
        <p class="bento-fine">Only listed cheatcodes are allowed, checked call by call in Foundry’s own trace. Impact is measured on the exploited fork and on a clean copy of the same block.</p>
        <div class="bento-viz kv" aria-hidden="true"><div><span>clean copy</span><b>measured</b></div><div><span>exploited fork</span><b>measured</b></div><div><span>difference</span><b class="up">checked against scope</b></div></div>
      </article>
      <article class="card spot bento-card w5" data-reveal data-tilt>
        <div class="label">First valid wins</div><h3 class="display h3">Hash and time, committed at intake</h3>
        <p>The earliest valid proof of a bug takes the credit. You get a receipt the moment your report arrives.</p>
        <div class="bento-viz hashline" aria-hidden="true">hyblis-submit:v1:<b>9c2e41f7…a41f</b></div>
      </article>
      <article class="card spot bento-card w7" data-reveal data-tilt>
        <div class="label">Paid through weights</div><div class="bento-big grad-text">Direct</div>
        <p>Rewards go straight to the researcher’s hotkey through the subnet’s weights: from the moment a finding is validated, with a bonus when the program accepts it. Nothing is held in a team key.</p>
        <div class="bento-viz flow" aria-hidden="true"><span>Emission</span>${H.icon('i-arrow', 14)}<span>Weights</span>${H.icon('i-arrow', 14)}<span>Researchers</span></div>
      </article>
    </div>
  </div>
</section>

<section class="sec" id="validation">
  <div class="wrap split" style="align-items:flex-start">
    <div data-reveal="left">
      <div class="eyebrow" data-scramble>Automatic validation</div>
      <h2 class="display h2" style="margin-top:14px">Watch a proof get validated</h2>
      <p class="lede" style="margin-top:20px">No human expert in the loop and no self-reported results. Every submission goes through the same six checks.</p>
      <ol class="pipe" id="pipe">${PIPE.map((p, i) => html`<li><b>0${i + 1}</b><div><strong>${p[0]}</strong><span>${p[1]}</span></div></li>`)}</ol>
    </div>
    <div data-reveal="right" data-watch id="term-wrap">
      <div class="term">
        <div class="term-bar"><i></i><i></i><i></i><span>validation run</span><button class="iconbtn" type="button" id="term-replay">Replay</button></div>
        <div class="term-body" id="term" aria-label="Illustration of a validation run"></div>
      </div>
      <p class="faint" style="margin-top:14px;font-size:13px">An illustration of one run. Real verdicts appear on the public ledger.</p>
    </div>
  </div>
</section>

<section class="sec sec-alt" id="how">
  <div class="wrap life">
    <div class="life-aside" data-reveal="left">
      <div class="eyebrow" data-scramble>How it works</div>
      <h2 class="display h2" style="margin-top:14px">From live code to <span class="grad-text">on&#8209;chain payout</span></h2>
      <ol class="life-rail" id="life-rail">
        <li data-step="0"><b>01</b>Pick a program</li><li data-step="1"><b>02</b>Submit a proof</li><li data-step="2"><b>03</b>Automatic validation</li><li data-step="3"><b>04</b>Paid in alpha</li>
      </ol>
    </div>
    <div class="life-steps" id="life-steps">
      <article class="card life-step" data-step="0">
        <div class="eyebrow" data-scramble>Step 01</div><h3 class="display h3">Pick a program</h3>
        <p>One live program is featured at a time and earlier ones stay open. Scope, trusted roles and the pinned fork block are published before intake opens.</p>
        <ul><li>Featured for 3 to 7 days by code size</li><li>Intake never closes</li><li>A new program every week</li></ul>
        <div class="mini" id="mini-programs"></div>
        <a class="link-arrow" href="#programs">Explore programs ${H.icon('i-arrow', 14)}</a>
      </article>
      <article class="card life-step" data-step="1">
        <div class="eyebrow" data-scramble>Step 02</div><h3 class="display h3">Submit a proof</h3>
        <p>One Foundry proof of concept per finding. No fix required. You sign a short message with your hotkey, in your browser wallet or from the terminal.</p>
        <ul><li>Signed with your hotkey</li><li>Receipt with hash and time</li><li>No fix required</li></ul>
        <div class="mini"><div class="mini-row"><span>Message to sign</span><span class="mono">hyblis-submit:v1:9c2e…a41f</span></div><div class="mini-row"><span>Signed by</span><span class="mono">5Fpj…Vgo6</span></div></div>
        <a class="link-arrow" href="#submit">Submit a report ${H.icon('i-arrow', 14)}</a>
      </article>
      <article class="card life-step" data-step="2">
        <div class="eyebrow" data-scramble>Step 03</div><h3 class="display h3">Automatic validation</h3>
        <p>Your proof is reproduced twice in a disposable sandbox on a pinned mainnet fork. Impact is measured from protocol state, never taken from your own asserts.</p>
        <ul><li>Every cheatcode call checked</li><li>Deterministic double run</li><li>Verdict target under one hour</li></ul>
        <div class="mini"><div class="mini-row"><span>Run 1</span>${H.status('validated')}</div><div class="mini-row"><span>Run 2, identical</span>${H.status('validated')}</div></div>
      </article>
      <article class="card life-step" data-step="3">
        <div class="eyebrow" data-scramble>Step 04</div><h3 class="display h3">Paid in alpha</h3>
        <p>Validated findings are filed with the bounty program. Researchers are paid in α straight through the subnet’s weights: from validation, by measured severity, with a bonus once the program accepts.</p>
        <ul><li>No custody: paid through weights</li><li>Public scoring ledger</li><li>By measured severity</li></ul>
        <div class="mini"><div class="mini-row"><span>Paid</span><span class="mono" id="mini-settle">—</span></div><div class="mini-row"><span>Paid to</span><span class="mono">the signing hotkey</span></div></div>
        <a class="link-arrow" href="#leaderboard">See the leaderboard ${H.icon('i-arrow', 14)}</a>
      </article>
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap split">
    <div data-reveal="left">
      <div class="eyebrow" data-scramble>Why speed matters</div>
      <h2 class="display h2" style="margin-top:14px">Speed decides who gets paid</h2>
      <p class="lede" style="margin-top:20px">On bounty platforms the earliest report wins a duplicate. Hyblis files a validated finding within hours, not at the end of a round, so fewer findings are lost to other reporters.</p>
      <a class="link-arrow" href="#competitions" style="margin-top:24px">How featured windows work ${H.icon('i-arrow', 14)}</a>
    </div>
    <figure class="card bars" data-reveal="right" style="margin:0">
      <figcaption class="label">Share of valid findings lost to earlier reporters</figcaption>
      <div><div class="bar-top"><span>Filed within 12 hours</span><b>~5%</b></div><div class="bar-track"><div class="bar-fill" style="--w:5%"></div></div></div>
      <div><div class="bar-top"><span>Filed at the end of a 7-day round</span><b>~46%</b></div><div class="bar-track"><div class="bar-fill" style="--w:46%"></div></div></div>
      <div class="faint" style="font-size:13px">Source: Hyblis model of live bounty programs, November 2026.</div>
    </figure>
  </div>
</section>

<section class="sec sec-alt">
  <div class="wrap">
    <div class="sec-head" data-reveal>
      <div><div class="eyebrow" data-scramble>Researchers</div><h2 class="display h2" style="margin-top:14px">Top researchers</h2><p>Deterministic scores from the published scoring policy.</p></div>
      <a class="btn btn-ghost" href="#leaderboard">View leaderboard</a>
    </div>
    <div class="tbl-wrap" data-reveal><table class="tbl" style="min-width:640px">
      <thead><tr><th>Rank</th><th>Researcher</th><th class="r">Score</th><th class="r">Accepted</th><th class="r">Validated</th></tr></thead>
      <tbody id="home-top"></tbody></table></div>
  </div>
</section>

<section class="sec" id="faq">
  <div class="wrap split" style="align-items:flex-start">
    <div style="flex:1 1 300px" data-reveal="left"><div class="eyebrow" data-scramble>FAQ</div><h2 class="display h2" style="margin-top:14px">Fair questions. <span class="grad-text">Straight answers.</span></h2></div>
    <div class="acc" style="flex:2 1 560px" data-reveal="right" id="faq-acc">
      ${FAQ.map((f, i) => html`<div class="acc-item ${i === 0 ? 'open' : ''}"><button class="acc-q" type="button" aria-expanded="${i === 0 ? 'true' : 'false'}"><span class="n">0${i + 1}</span><span class="t">${f[0]}</span><span class="pm" aria-hidden="true"></span></button><div class="acc-a"><div><p>${f[1]}</p></div></div></div>`)}
    </div>
  </div>
</section>

<section class="cta-band">
  <div class="wrap" data-reveal="scale">
    <h2 class="display">Find bugs. <span class="grad-text" style="display:block">Get paid in alpha.</span></h2>
    <p>Pick a live program, submit one proof, and watch it move from received to validated on the public ledger.</p>
    <div class="cta"><a class="btn btn-grad btn-lg" href="#programs" data-magnetic data-pulse>Explore programs</a><a class="btn btn-ghost btn-lg" href="#dashboard">Open dashboard</a></div>
  </div>
</section>`;
  }

  H.pages.home = {
    title: 'Hyblis — blockchain security research, validated and paid on-chain',
    mount(root) {
      root.innerHTML = template();
      const cleanups = [];

      function update(c) {
        // Until the data has loaded once, nothing here may claim the ledger or the program list is empty.
        const s = c.summary, ready = H.data.loaded();
        const counts = s ? s.counts : { submissions: 0, validated: 0, accepted: 0, researchers: 0, open_programs: 0 };
        [['st-val', counts.validated], ['st-acc', counts.accepted], ['st-res', counts.researchers], ['st-prog', counts.open_programs]].forEach(([id, v]) => {
          const el = document.getElementById(id); if (!el) return;
          if (!ready) { el.removeAttribute('data-count'); el.textContent = '—'; return; }
          el.dataset.count = String(v);
          if (el.closest('.is-in')) H.fx.countTo(el, v);
        });
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        const last = c.ledger.reduce((m, r) => Math.max(m, r.t), 0);
        // launch mode: intake opens at mainnet launch, so an empty ledger and no release date are expected
        const closed = !!s && !H.data.intakeOpen();
        set('hero-proof', closed ? H.data.intakeMessage().replace(/\.$/, '') : 'Every proof reproduced twice before it counts');
        set('hud-subs', !s ? '—' : closed && !counts.submissions ? 'Opens at launch' : H.num(counts.submissions) + ' submissions');
        set('hud-val', s ? H.num(counts.validated) : '—');
        const hl = document.getElementById('hud-last');
        if (hl) hl.innerHTML = !ready ? '—' : last ? H.timeAgo(last) : 'None yet';
        set('hud-next', s && s.releases && s.releases.next_release_on ? H.date(s.releases.next_release_on) : closed ? 'At launch' : 'To be announced');
        set('mini-settle', closed ? 'After launch' : 'Every epoch');

        const rows = c.ledger.slice().sort((a, b) => b.t - a.t).slice(0, 14);
        const track = document.getElementById('ticker-track');
        if (track) {
          const facts = ['Every proof is reproduced twice', 'Hash and time committed at intake', 'Paid on-chain through weights'];
          if (closed) facts.unshift(H.data.intakeMessage().replace(/\.$/, ''), 'Programs and rules are public now');
          else if (ready) facts.unshift('The ledger starts with the first submission');
          // The second copy only makes the loop seamless, so assistive technology skips it.
          const copy = (dup) => (rows.length ? rows.map((r) => html`<span class="tick"${dup ? H.raw(' aria-hidden="true"') : ''}>${H.status(r.status)}<b>${r.id}</b>${H.sev(r.severity)}${H.timeAgo(r.t)}</span>`)
            : facts.map((f) => html`<span class="tick"${dup ? H.raw(' aria-hidden="true"') : ''}>${f}</span>`)).join('');
          track.style.setProperty('--dur', Math.max(36, (rows.length || facts.length) * 5) + 's');
          track.innerHTML = copy(false) + copy(true);
        }
        const mp = document.getElementById('mini-programs');
        if (mp) mp.innerHTML = c.tasks.length ? c.tasks.slice(0, 3).map((t) => html`<div class="mini-row"><b>${t.label}</b><span class="sevs">${t.severity_scope.map((x) => H.sev(x))}<span class="tag ${t.status === 'featured' ? 'tag-hot' : ''}">${t.status}</span></span></div>`).join('')
          : String(html`<div class="mini-row"><span class="muted">${ready ? 'The first program opens soon' : 'Could not load the programs. Retrying.'}</span></div>`);
        const top = document.getElementById('home-top');
        if (top) top.innerHTML = c.leaderboard.length ? c.leaderboard.slice(0, 5).map((r) => html`<tr class="is-link" data-href="researcher-${r.hotkey}">
            <td><span class="rank rank-${r.rank}">#${r.rank}</span></td>
            <td><a class="who" href="#researcher-${r.hotkey}">${H.identicon(r.hotkey, 30)}<span class="mono">${H.short(r.hotkey, 8, 6)}</span></a></td>
            <td class="r num">${H.num(r.score, 2)}</td><td class="r num">${r.accepted}</td><td class="r num muted">${r.validated}</td></tr>`).join('')
          : String(html`<tr><td colspan="5">${ready ? html`<div class="tbl-empty"><b>No ranked researchers yet</b>${closed ? 'Scores appear with the first validated finding after launch.' : 'Scores appear with the first validated finding.'}</div>` : H.ui.loadFail('the leaderboard')}</td></tr>`);
      }
      cleanups.push(H.data.subscribe(update));
      update(H.data.cache);

      // terminal + pipeline highlight
      const pipe = $$('#pipe li', root);
      let typer = null;
      const play = () => {
        pipe.forEach((li) => li.classList.remove('on', 'done'));
        if (typer) typer.stop();
        typer = H.fx.typer(document.getElementById('term'), TERM, {
          onLine(i, l) { if (l.step == null) return; pipe.forEach((li, k) => { li.classList.toggle('done', k < l.step); li.classList.toggle('on', k === l.step); }); },
        });
      };
      const tw = document.getElementById('term-wrap');
      tw.addEventListener('fx:in', play, { once: true });
      document.getElementById('term-replay').addEventListener('click', play);
      cleanups.push(() => { if (typer) typer.stop(); });

      // lifecycle: the step nearest the middle of the screen is active
      const steps = $$('.life-step', root), rail = $$('#life-rail li', root);
      const setStep = (n) => { steps.forEach((s, i) => s.classList.toggle('on', i === n)); rail.forEach((r, i) => r.classList.toggle('on', i === n)); };
      setStep(0);
      if ('IntersectionObserver' in window) {
        const io = new IntersectionObserver((es) => { es.forEach((e) => { if (e.isIntersecting) setStep(+e.target.dataset.step); }); }, { rootMargin: '-42% 0px -42% 0px', threshold: 0 });
        steps.forEach((s) => io.observe(s));
        cleanups.push(() => io.disconnect());
      }
      rail.forEach((r) => r.addEventListener('click', () => { const s = steps[+r.dataset.step]; if (s) s.scrollIntoView({ behavior: H.reduced ? 'auto' : 'smooth', block: 'center' }); }));

      // FAQ: one open at a time
      cleanups.push(H.on(root, 'click', '.acc-q', (e, b) => {
        const item = b.parentElement, was = item.classList.contains('open');
        $$('.acc-item', root).forEach((x) => { x.classList.remove('open'); $('.acc-q', x).setAttribute('aria-expanded', 'false'); });
        if (!was) { item.classList.add('open'); b.setAttribute('aria-expanded', 'true'); }
      }));
      cleanups.push(H.on(root, 'click', '[data-scrollto]', (e, b) => { const t = document.getElementById(b.dataset.scrollto); if (t) t.scrollIntoView({ behavior: H.reduced ? 'auto' : 'smooth', block: 'start' }); }));
      cleanups.push(H.on(root, 'click', 'tr[data-href]', (e, tr) => { if (!e.target.closest('a')) H.go(tr.dataset.href); }));
      // the 3D scene answers the main call to action
      let lastPulse = 0;
      cleanups.push(H.on(root, 'pointerenter', '[data-pulse]', () => { const n = Date.now(); if (H.sceneCtl && n - lastPulse > 2500) { lastPulse = n; H.sceneCtl.pulse(); } }, true));
      return () => cleanups.forEach((fn) => fn());
    },
  };
})();
