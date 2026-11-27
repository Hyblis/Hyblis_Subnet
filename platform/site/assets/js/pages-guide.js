/* Hyblis site — miner guide (#guide). Network-aware: on testnet.hyblis.com it gives the testnet subnet's
 * steps and reward rules (scoring policy v2); on the main site it says the mainnet rules come at launch. */
(function () {
  'use strict';
  const H = window.Hyblis, html = H.html;

  function code(name, text) {
    return html`<div class="code" style="margin:12px 0 4px"><div class="code-bar"><span>${name}</span><button class="iconbtn" type="button" data-copy="${text}" data-copied="Copied" aria-label="Copy ${name}">${H.icon('i-copy', 13)}Copy</button></div><pre><code>${text}</code></pre></div>`;
  }

  H.pages.guide = {
    title: 'Miner guide — Hyblis',
    mount(root) {
      const test = H.cfg.network === 'testnet';
      const netuid = H.cfg.netuid || (test ? 626 : null);
      const net = test ? 'test' : 'finney';
      const sub = netuid != null ? String(netuid) : '<NETUID>';
      root.innerHTML = html`
<section class="phero"><div class="wrap phero-in">
  <div class="eyebrow" data-scramble>Researchers</div>
  <h1 class="display">Miner <span class="grad-text">guide</span></h1>
  <p class="lede">${test
    ? html`Hyblis runs on the Bittensor test network as subnet ${sub}. Find a vulnerability in a live program, prove it with a Foundry test, sign it with your hotkey and get paid through the subnet's weights. Testnet α has no market value: this is where you learn the rules before mainnet.`
    : 'Find a vulnerability in a live program, prove it with a Foundry test, sign it with your Bittensor hotkey and get paid in the subnet’s α. Intake on mainnet opens at launch; the testnet subnet is open now at testnet.hyblis.com.'}</p>
</div></section>
<section class="body"><div class="wrap guide" style="max-width:860px">

  <h2 class="h3" style="margin-top:0">1. Set up a wallet and register</h2>
  <p class="muted">You need a Bittensor coldkey (holds funds, keep it offline) and a hotkey (signs your reports and receives rewards). Rewards go only to hotkeys that hold a UID on the subnet.</p>
  ${code('Terminal', 'pip install bittensor-cli\nbtcli wallet create -w hunter -H default\nbtcli subnets register --netuid ' + sub + ' --network ' + net + ' -w hunter -H default')}
  <p class="muted" style="font-size:14px">${test
    ? 'Registration on the testnet subnet costs about τ1 of free testnet TAO; 90% of it is held as your collateral. Ask for testnet TAO in the Bittensor community.'
    : 'The registration price floats with demand; part of it is held as your collateral.'} A new UID is protected from removal for about 9 days.</p>

  <h2 class="h3">2. Pick a program and read its rules</h2>
  <p class="muted">Each <a href="#programs">program</a> page lists the contracts in scope, the severities it pays for, the chain block your proof runs against, the proof template and the rules the runner enforces.</p>

  <h2 class="h3">3. Write the proof and check it locally</h2>
  <ol class="rules-list">
    <li>Start from the program's proof template: a Foundry test named <code>HyblisPoC</code> with <code>test_exploit()</code> (or <code>step1()</code> … <code>stepN()</code> for attacks over several transactions).</li>
    <li>Run it as an ordinary attacker. Capital comes only from the template's helpers; impersonating a protocol contract, editing storage, mocking calls or calling the shell gets the proof rejected, even inside a helper contract.</li>
    <li>Download <b>hyblis check</b> from the program page. It runs your proof on your machine exactly as the runner will and prints VALIDATED with the measured impact, or REJECTED with the reason.</li>
  </ol>

  <h2 class="h3">4. Submit</h2>
  <ol class="rules-list">
    <li>Open <a href="#submit">Submit a report</a>, choose the program, describe the finding and paste your proof.</li>
    <li>Sign with your hotkey in a Polkadot wallet extension (Talisman, SubWallet or polkadot{.js}). The wallet shows the text <code>hyblis-submit:v1:&lt;hash&gt;</code>: that hash is your report.</li>
    <li>Keep the receipt link private: it is the only way to see your report's detailed status. The <a href="#ledger">public ledger</a> shows its hash, time, status and severity, never its contents.</li>
  </ol>

  <h2 class="h3">5. How you are paid</h2>
  ${test ? html`
  <p class="muted">Rewards are paid straight through the subnet's weights every epoch (about 72 minutes), with no custody. The miner pool is split three ways; a pool with nobody in it passes its share to the others.</p>
  <div class="tbl-wrap"><table class="tbl" style="min-width:560px"><thead><tr><th>Pool</th><th>Share</th><th>What earns it</th></tr></thead><tbody>
    <tr><td>Validated findings</td><td class="num">60%</td><td>The runner reproduced your proof and measured the impact. By measured severity (Low 1, Medium 3, High 10, Critical 30), fading over about 30 days.</td></tr>
    <tr><td>Acceptance bonus</td><td class="num">25%</td><td>The program accepted the finding. By final severity, for 90 days.</td></tr>
    <tr><td>Warm-up track</td><td class="num">15%</td><td>You reproduced a real past exploit on its historical chain state (programs marked warm-up). Short-lived, one reward per exploit.</td></tr>
  </tbody></table></div>
  <p class="muted" style="font-size:14px">A finding later rejected as invalid stops earning and counts a strike; three strikes suspend the hotkey. Duplicates stop earning without a strike.</p>`
  : html`<p class="muted">The scoring policy for mainnet, with every number behind a reward, is published before intake opens. The testnet subnet already runs the planned rules: see this page on testnet.hyblis.com.</p>`}

  <h2 class="h3">6. Good to know</h2>
  <ul class="rules-list">
    <li>Only measured impact counts: a loss of funds, a freeze, insolvency or an unbacked mint above the program's threshold. Asserts and logs in your proof are ignored.</li>
    <li>The first valid report of a bug wins; a later report of the same bug is a duplicate.</li>
    <li>Proofs run with no network, against the program's pinned chain state, in an isolated sandbox. Anything else your proof tries is rejected.</li>
    <li>A real vulnerability in a live program is disclosed only through that program's own process. Never publish it.</li>
  </ul>
</div></section>`;
      return null;
    },
  };
})();
