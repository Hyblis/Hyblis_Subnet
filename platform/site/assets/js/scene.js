/* Hyblis 3D background — scene module skeleton (three.js r128, global THREE).
 *
 * CONTRACT (do not change):
 *   window.HyblisScene.mount(canvas, opts) -> controller | null (null when WebGL is unavailable)
 *   opts: { quality: 'high'|'low', reducedMotion: bool, seed: int,
 *           palette: { bg, pink, magenta, violet, ink, dim } }
 *   controller:
 *     setRoute('hero'|'ambient')  hero = home top (full show); ambient = inner pages (calm backdrop)
 *     setScroll(p)                0..1, how far the visitor scrolled past the hero (scene recedes)
 *     setPointer(nx, ny)          -1..1 pointer parallax
 *     pulse()                     one-shot "a finding was validated" flare
 *     resize()                    call when the canvas CSS size changes (also polled every frame)
 *     renderAt(t)                 render exactly ONE frame at time t seconds (deterministic)
 *     start() / stop()            animation loop
 *     destroy()                   free GPU resources and listeners
 *     info()                      { calls, triangles, points, lines }
 *
 * RULES for concept code (the part between the BEGIN/END CONCEPT markers):
 *   - All motion is a closed-form function of time `t` and the smoothed inputs in `S`
 *     (no per-frame accumulation), so renderAt(t) reproduces any frame exactly.
 *   - Use `rand()` (seeded) instead of Math.random().
 *   - No textures or other network loads. Procedural geometry and shaders only.
 *   - Keep it light: aim for < 12 draw calls and < 250k triangles. Prefer InstancedMesh,
 *     merged BufferGeometry, Points and LineSegments. Additive blending for glow.
 *   - The canvas is opaque: the scene paints its own background (P.bg).
 */
(function () {
  'use strict';

  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const clamp01 = (x) => Math.max(0, Math.min(1, x));
  const smooth = (a, b, x) => { const t = clamp01((x - a) / (b - a)); return t * t * (3 - 2 * t); };

  function mount(canvas, opts) {
    opts = opts || {};
    if (typeof THREE === 'undefined') return null;
    const P = Object.assign({ bg: '#0a0a0c', pink: '#f43f73', magenta: '#d91e8f', violet: '#a91ee6', ink: '#fafafa', dim: '#3a3a42' }, opts.palette || {});
    const quality = opts.quality === 'low' ? 'low' : 'high';
    const rand = mulberry32(opts.seed || 7);
    const reduced = !!opts.reducedMotion;

    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: quality !== 'low', alpha: false, powerPreference: 'high-performance', stencil: false });
    } catch (e) { return null; }
    let pixelRatio = Math.min(window.devicePixelRatio || 1, quality === 'low' ? 1 : 1.75);
    renderer.setPixelRatio(pixelRatio);
    renderer.setClearColor(new THREE.Color(P.bg), 1);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 400);

    // S = smoothed inputs the concept code reads every frame.
    const S = {
      t: 0,
      routeK: 0,      // 0 = hero, 1 = ambient (smoothed)
      scrollK: 0,     // 0..1 (smoothed)
      px: 0, py: 0,   // pointer -1..1 (smoothed)
      pulseAt: -1e3,  // time of the last pulse()
      w: 0, h: 0, aspect: 1, wide: true,
    };
    const target = { route: 'hero', scroll: 0, px: 0, py: 0 };

    /* ===================== BEGIN CONCEPT ===================== */
    // "The ledger under scan"
    // A tower of dark-glass blocks (the ledger: contract code, block by block) turns slowly while a thin
    // scan plane sweeps through it: the audit that never ends. Every sweep flags a couple of blocks (picked
    // per sweep, so findings do not recur in the same spots). A flagged block flares, slides out on rails
    // and is acquired by a reticle; the reticle locks shut (verified), the block slides back in sealed and
    // keeps a white-violet scar for a while, so the tower visibly hardens. New blocks keep arriving as a
    // short chain joined by paired link beams; it docks onto the top and presses the ledger down a row.
    // pulse() is one validated finding: the flagged block that is out right now (or the next one) is
    // locked with bolts, flashes white, and two rings run up and down the tower from it.
    const LOW = quality === 'low';
    const lerp = (a, b, x) => a + (b - a) * x;
    const easeInOut = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
    const easeOut3 = (x) => 1 - Math.pow(1 - clamp01(x), 3);
    const easeOutBack = (x) => { const c1 = 1.35, c3 = c1 + 1, y = x - 1; return 1 + c3 * y * y * y + c1 * y * y; };
    const ihash = (n) => {
      let x = Math.imul((n | 0) ^ 0x5bd1e995, 0x9e3779b1);
      x ^= x >>> 15; x = Math.imul(x, 0x85ebca77); x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae3d); x ^= x >>> 16;
      return (x >>> 0) / 4294967296;
    };

    const cBg = new THREE.Color(P.bg), cPink = new THREE.Color(P.pink), cMag = new THREE.Color(P.magenta);
    const cVio = new THREE.Color(P.violet), cInk = new THREE.Color(P.ink), cDim = new THREE.Color(P.dim);
    const cEdge = cVio.clone().lerp(cDim, 0.28).lerp(cInk, 0.10);   // muted violet for resting edges
    const cSeal = cVio.clone().lerp(cInk, 0.52);                      // verified / sealed: white-violet
    const cHalo = cPink.clone().lerp(cInk, 0.35);

    /* ---------- timeline constants (everything below is a closed-form function of t) ---------- */
    const SCAN_T = 7.0;            // hero: one sweep every 7 s, alternating up / down
    const SCAN_PHI = -0.65;        // phase offset (seconds)
    const SCAN_Y0 = -8.6, SCAN_Y1 = 1.3;
    const AMB_T = 26.0;            // inner pages: one slow sweep every 26 s
    const SLIDE = 1.5;             // how far a flagged block slides out (cells)
    const REACT = 3.5, LOCK_AT = 1.75, BACK_AT = 2.35, SCAR_T = 6.5;
    const CH_T = 14.0, CH_OFF = -0.3, CH_X0 = 5.2; // the arriving chain: cycle, phase, distance travelled (cells)
    const FOV = 28, TANF = Math.tan((FOV * Math.PI) / 360);
    const spinAt = (t) => -0.64 + 0.36 * Math.sin(0.075 * t - 1.1) + 0.06 * Math.sin(0.031 * t + 0.6);

    /* ---------- lattice: NX wide, NZ deep, NY tall ---------- */
    const NX = 7, NZ = 4, NY = 14, HALF = 0.43;
    const hx = (NX - 1) / 2, hz = (NZ - 1) / 2, HULLX = hx + HALF, HULLZ = hz + HALF;
    const cid = (i, j, k) => (j * NZ + k) * NX + i;
    const inside = (i, j, k) => i >= 0 && j >= 0 && k >= 0 && i < NX && j < NY && k < NZ;
    // skyline: layers missing from the top of each column (rows: back k = 0 .. front k = 3), stepping down
    // towards the far (left) end. Row k = 1, i = 3..5 is the dock the arriving chain lands on.
    const SKY = [
      [5, 4, 3, 2, 1, 1, 0],
      [4, 4, 2, 0, 0, 0, 1],
      [5, 3, 3, 1, 0, 0, 0],
      [5, 4, 3, 2, 1, 0, 0],
    ];
    const topCut = (i, k) => SKY[k][i];
    const has = (i, j, k) => (inside(i, j, k) && j >= topCut(i, k) ? 1 : 0);
    const DOCK_K = 1, DOCK_I0 = 3, NCH = 3;
    const isDock = (i, k) => k === DOCK_K && i >= DOCK_I0 && i < DOCK_I0 + NCH;

    const blocks = [];
    for (let j = 0; j < NY; j++) for (let k = 0; k < NZ; k++) for (let i = 0; i < NX; i++) {
      if (!has(i, j, k)) continue;
      blocks.push({ x: i - hx, y: -j, z: k - hz, i: i, j: j, k: k, dock: isDock(i, k) });
    }
    // the camera always looks from the (+x, +y, +z) side of the lattice, so this order is front to back
    blocks.sort((a, b) => (b.x + b.y + b.z) - (a.x + a.y + a.z));
    const NB = blocks.length;

    // what each face of a block looks at: 1 = a neighbouring block (a seam), 0 = open air
    const faceType = (i, j, k) => (has(i, j, k) ? 1 : 0);
    const aOffset = new Float32Array(NB * 3), aSeed = new Float32Array(NB * 4), aDir = new Float32Array(NB * 3), aState = new Float32Array(NB * 4);
    const aNbP = new Float32Array(NB * 3), aNbN = new Float32Array(NB * 3);
    const lookup = new Map();
    const dockSeed = (i) => [0.3 + 0.17 * (i - DOCK_I0), 0.62 - 0.21 * (i - DOCK_I0), 0.78];
    blocks.forEach((b, n) => {
      // a few blocks on the visible faces stand slightly proud of the wall (it reads as stacked blocks, not a facade)
      const face = b.k === NZ - 1 ? 2 : b.i === NX - 1 ? 0 : -1;
      const proud = face >= 0 && !b.dock && rand() < 0.14 ? 0.05 + 0.07 * rand() : 0;
      aOffset[n * 3] = b.x + (face === 0 ? proud : 0); aOffset[n * 3 + 1] = b.y; aOffset[n * 3 + 2] = b.z + (face === 2 ? proud : 0);
      b.x = aOffset[n * 3]; b.z = aOffset[n * 3 + 2];
      const s0 = rand(), s1 = rand(), s2 = rand();
      if (b.dock) { const ds = dockSeed(b.i); aSeed[n * 4] = ds[0]; aSeed[n * 4 + 1] = ds[1]; aSeed[n * 4 + 2] = ds[2]; }
      else { aSeed[n * 4] = s0; aSeed[n * 4 + 1] = s1; aSeed[n * 4 + 2] = s2; }
      aSeed[n * 4 + 3] = 1;                                     // scale
      lookup.set(cid(b.i, b.j, b.k), n);
      aNbP[n * 3] = faceType(b.i + 1, b.j, b.k); aNbP[n * 3 + 1] = faceType(b.i, b.j - 1, b.k); aNbP[n * 3 + 2] = faceType(b.i, b.j, b.k + 1);
      aNbN[n * 3] = faceType(b.i - 1, b.j, b.k); aNbN[n * 3 + 1] = faceType(b.i, b.j + 1, b.k); aNbN[n * 3 + 2] = faceType(b.i, b.j, b.k - 1);
    });
    const dockN = [];                                             // instance indices of the dock columns
    blocks.forEach((b, n) => { if (b.dock) dockN.push(n); });

    // blocks that can be flagged: the wide front face (+z) and the near end (+x), away from the misty base
    const cand = [];
    blocks.forEach((b, n) => {
      let nrm = null, u = null;
      if (b.k === NZ - 1 && b.i >= 2 && b.i <= 5 && b.j >= topCut(b.i, b.k) + 1 && b.j <= 9) { nrm = [0, 0, 1]; u = [1, 0, 0]; }
      else if (b.i === NX - 1 && (b.k === 1 || b.k === 2) && b.j >= topCut(b.i, b.k) + 1 && b.j <= 9) { nrm = [1, 0, 0]; u = [0, 0, 1]; }
      if (!nrm) return;
      aDir[n * 3] = nrm[0]; aDir[n * 3 + 1] = nrm[1]; aDir[n * 3 + 2] = nrm[2];
      cand.push({ n: n, j: b.j, front: nrm[2] > 0, c: [b.x, b.y, b.z], nrm: nrm, u: u });
    });
    // hashed sweeps flag rows 2..6 only: the flags then fall mid-sweep, so the turnarounds stay quiet and the
    // events of consecutive sweeps never overlap
    const candMid = cand.map((c, i) => i).filter((i) => cand[i].j >= 2 && cand[i].j <= 6);
    const candFront = candMid.filter((i) => cand[i].front);
    // per sweep: two flagged blocks, picked by a hash of the sweep index, at least three rows apart.
    // The first sweeps after load are choreographed (front face F(i, j), near end X(k, j)).
    const findCand = (front, a, j) => cand.findIndex((c) => c.front === front && c.j === j && (front ? blocks[c.n].i === a : blocks[c.n].k === a));
    const HAND = new Map([
      [-1, [findCand(true, 4, 7), findCand(false, 1, 3)]],
      [0, [findCand(true, 3, 6), findCand(true, 4, 3)]],
      [1, [findCand(false, 2, 1), findCand(true, 2, 5)]],
    ]);
    const flagMemo = new Map();
    // the plain hash picks of a sweep (no look-back, so nothing recurses)
    function rawFlags(s) {
      const h = HAND.get(s);
      if (h) return h;
      const a = candFront[Math.floor(ihash(s * 2 + 11) * candFront.length)];
      const pool = candMid.filter((i) => Math.abs(cand[i].j - cand[a].j) >= 3);
      return pool.length ? [a, pool[Math.floor(ihash(s * 2 + 12) * pool.length)]] : [a];   // a mid-row pick flags alone
    }
    function flagsOf(s) {
      let f = flagMemo.get(s) || HAND.get(s);
      if (f) return f;
      // a block the last three sweeps picked is drawn again, so findings do not recur in the same spots
      const recent = [].concat(rawFlags(s - 1), rawFlags(s - 2), rawFlags(s - 3));
      const draw = (list, salt) => {
        for (let k = 0; k < 6; k++) {
          const c = list[Math.floor(ihash(s * 2 + salt + k * 7919) * list.length)];
          if (recent.indexOf(c) < 0) return c;
        }
        return list[Math.floor(ihash(s * 2 + salt) * list.length)];
      };
      const a = draw(candFront, 11);
      const pool = candMid.filter((i) => Math.abs(cand[i].j - cand[a].j) >= 3);
      f = pool.length ? [a, draw(pool, 12)] : [a];
      if (flagMemo.size > 64) flagMemo.clear();
      flagMemo.set(s, f);
      return f;
    }

    /* ---------- shared uniforms + GLSL ---------- */
    const U = {
      uTime: { value: 0 }, uRes: { value: new THREE.Vector2(1, 1) }, uMask: { value: new THREE.Vector4(1, 0, 0.4, 0.6) },
      uMask2: { value: new THREE.Vector4(1, 0, 0.4, 0.6) }, uMaskMix: { value: 0 },
      uMaskMin: { value: 0.15 }, uDim: { value: 1 }, uScanY: { value: 0 }, uScanK: { value: 0 }, uScanDir: { value: 1 },
      uBg: { value: cBg }, uPink: { value: cPink }, uMagenta: { value: cMag }, uViolet: { value: cVio }, uInk: { value: cInk },
      uEdge: { value: cEdge }, uSeal: { value: cSeal }, uHalf: { value: HALF }, uHull: { value: new THREE.Vector2(HULLX, HULLZ) },
      uFadeY: { value: new THREE.Vector2(-12.2, -5.4) },
    };
    const GL_COMMON = [
      'uniform vec2 uRes; uniform vec4 uMask, uMask2; uniform float uMaskMin, uMaskMix; uniform float uDim;',
      'uniform vec3 uBg, uPink, uMagenta, uViolet, uInk, uEdge, uSeal;',
      'uniform float uTime, uScanY, uScanK, uScanDir, uHalf; uniform vec2 uHull, uFadeY;',
      // legibility mask: a ramp across the screen (two of them blended while the layout changes route)
      'float screenMask(){ vec2 uv = gl_FragCoord.xy / uRes; return mix(uMaskMin, 1.0, mix(smoothstep(uMask.z, uMask.w, dot(uv, uMask.xy)), smoothstep(uMask2.z, uMask2.w, dot(uv, uMask2.xy)), uMaskMix)); }',
      'float dither(){ return fract(52.9829189 * fract(dot(gl_FragCoord.xy, vec2(0.06711056, 0.00583715)))); }',
    ].join('\n');

    const group = new THREE.Group();
    scene.add(group);

    /* ---------- 1. the blocks (the lattice, and the arriving chain as a second small batch) ---------- */
    const boxSrc = new THREE.BoxGeometry(HALF * 2, HALF * 2, HALF * 2);
    function blockGeometry(n, off, seed, dir, nbp, nbn, state, dynamic) {
      const g = new THREE.InstancedBufferGeometry();
      g.index = boxSrc.index;
      g.setAttribute('position', boxSrc.attributes.position);
      g.setAttribute('normal', boxSrc.attributes.normal);
      const mk = (arr, size, dyn) => { const a = new THREE.InstancedBufferAttribute(arr, size); if (dyn) a.setUsage(THREE.DynamicDrawUsage); return a; };
      g.setAttribute('aOffset', mk(off, 3, dynamic)); g.setAttribute('aSeed', mk(seed, 4, dynamic));
      g.setAttribute('aDir', mk(dir, 3, false)); g.setAttribute('aNbP', mk(nbp, 3, false)); g.setAttribute('aNbN', mk(nbn, 3, false));
      g.setAttribute('aState', mk(state, 4, true));
      g.instanceCount = n;
      return g;
    }
    const blockGeo = blockGeometry(NB, aOffset, aSeed, aDir, aNbP, aNbN, aState, false);

    const NL = 2;
    const lights = []; for (let i = 0; i < NL; i++) lights.push(new THREE.Vector4(0, 0, 0, 0));
    const blockMat = new THREE.ShaderMaterial({
      uniforms: Object.assign({}, U, {
        uCamL: { value: new THREE.Vector3() }, uKey: { value: new THREE.Vector3() }, uRim: { value: new THREE.Vector3() },
        uFog: { value: new THREE.Vector2(18, 40) }, uLights: { value: lights }, uNumL: { value: 0 },
        uPulseC: { value: new THREE.Vector4(0, -100, 0, 0) }, uPulseB: { value: new THREE.Vector4(-100, -100, 0, 0) }, uDetail: { value: 1 },
      }),
      extensions: { derivatives: true },
      vertexShader: [
        'attribute vec3 aOffset; attribute vec4 aSeed; attribute vec3 aDir; attribute vec4 aState; attribute vec3 aNbP; attribute vec3 aNbN;',
        'uniform float uTime, uDim, uMaskMin, uMaskMix; uniform vec3 uCamL, uKey; uniform vec2 uFog, uHull, uFadeY; uniform vec4 uMask, uMask2;',
        'varying vec3 vP, vN, vL, vRay; varying vec4 vSeed; varying vec4 vState; varying vec4 vK;',
        'void main(){',
        '  vec3 c = aOffset + aDir * aState.x;',
        '  c.y += aState.z;',
        '  vec3 pl = c + position * aSeed.w;',
        '  vP = position; vN = normal; vL = pl; vRay = pl - uCamL; vSeed = aSeed;',
        // a block that has left its slot (slid out, or still above its dock) shows plain glass on every side
        '  float away = aState.x + max(aState.z, 0.0);',
        '  float ft = (dot(max(normal, 0.0), aNbP) + dot(max(-normal, 0.0), aNbN)) * (1.0 - smoothstep(0.0, 0.35, away));',
        // x: flare, y: sealed, z: what this face looks at, w: slow twinkle
        '  vState = vec4(aState.y, aState.w, ft, 0.85 + 0.15 * sin(uTime * (0.5 + aSeed.y) + aSeed.y * 40.0));',
        '  vec4 cp = projectionMatrix * modelViewMatrix * vec4(pl, 1.0);',
        '  gl_Position = cp;',
        // Terms that change slowly across a block are worked out per vertex, so the pixels only interpolate them.
        // Key light from the screen right, a dim fill: the near end (x faces) and the wide front (z faces) each get
        // their own level, seams included, so the volume reads; the tower also darkens towards its misty base.
        '  float kd = max(dot(normal, uKey), 0.0);',
        '  float onZ = smoothstep(-0.3, 0.3, (uHull.x - abs(pl.x)) - (uHull.y - abs(pl.z)));',
        '  float facL = mix(max(uKey.x * sign(pl.x), 0.0), max(uKey.z * sign(pl.z), 0.0), onZ);',
        '  facL = mix(facL, kd, step(0.5, normal.y) * (1.0 - step(0.5, ft)));',
        '  float vg = 0.62 + 0.38 * smoothstep(-9.0, 0.6, pl.y);',
        '  float nearK = smoothstep(uFog.y, uFog.x, length(vRay));',
        // depth fade, fade into the dark below, legibility mask
        '  vec2 uv = cp.xy / cp.w * 0.5 + 0.5;',
        '  float mask = mix(uMaskMin, 1.0, mix(smoothstep(uMask.z, uMask.w, dot(uv, uMask.xy)), smoothstep(uMask2.z, uMask2.w, dot(uv, uMask2.xy)), uMaskMix));',
        '  vK = vec4(mix(0.3, 1.0, nearK) * smoothstep(uFadeY.x, uFadeY.y, pl.y) * uDim * mask, (0.46 + 0.84 * facL) * vg, nearK, kd);',
        '}',
      ].join('\n'),
      // Written for cheap fill: bells are rational, powers are repeated squaring, few exp, no sin, and the
      // seam, pulse and detail work only runs where it is needed.
      fragmentShader: [
        'precision highp float;',
        GL_COMMON,
        'uniform vec3 uKey, uRim; uniform vec4 uLights[' + NL + ']; uniform float uNumL; uniform vec4 uPulseC; uniform vec4 uPulseB; uniform float uDetail;',
        'varying vec3 vP, vN, vL, vRay; varying vec4 vSeed; varying vec4 vState; varying vec4 vK;',
        'float edgeDist(vec3 p){ vec3 d = uHalf - abs(p); return d.x + d.y + d.z - min(d.x, min(d.y, d.z)) - max(d.x, max(d.y, d.z)); }',
        'void main(){',
        '  float vis = vK.x;',
        '  if (vis < 0.003) { gl_FragColor = vec4(uBg, 1.0); return; }',
        '  vec3 N = vN;',
        '  vec3 rd = normalize(vRay);',
        '  float fl = vState.x, sealK = vState.y, lightK = vK.y, nearK = vK.z, kd = vK.w;',
        // scan plane terms (dy > 0: ahead of the plane, dy < 0: already scanned)
        '  float dy = (vL.y - uScanY) * uScanDir;',
        '  float lq = 1.0 + dy * dy * 900.0; float line = 1.0 / (lq * lq);',
        '  float hq = 1.0 + dy * dy * 11.0; float halo = 1.0 / (hq * hq);',
        '  float trail = exp(dy * (dy < 0.0 ? 0.6667 : -5.5556));',
        '  float sK = uScanK;',
        '  float pinkK = clamp(trail * 1.35, 0.0, 1.0) * sK;',
        // soft reflections: each pane is very slightly pillowed and tilted, so highlights become gradients
        '  vec3 tang = vP - N * dot(vP, N);',
        '  vec3 Nj = normalize(N + tang * 0.55 + (vSeed.xyz - 0.5) * 0.16);',
        '  vec3 R = reflect(rd, Nj);',
        // pink light from flagged blocks on their neighbours, and its glint in the glass (skipped when none is lit)
        '  float litS = 0.0, glint = 0.0;',
        '  for (int i = 0; i < ' + NL + '; i++) {',
        '    if (float(i) >= uNumL) break;',
        '    vec3 d = uLights[i].xyz - vL; float d2 = dot(d, d); float inv = inversesqrt(d2 + 1e-4);',
        '    float nd = dot(N, d) * inv;',
        '    float rl = max(dot(R, d) * inv, 0.0); rl *= rl; rl *= rl; rl *= rl;',
        '    litS += uLights[i].w * (max(nd, 0.0) * 0.85 + 0.15) / (1.0 + d2 * d2 * 0.55);',
        '    glint += uLights[i].w * rl * step(0.0, nd) / (1.0 + d2 * 0.2);',
        '  }',
        // pulse: a flash around the validated block, then two bands running up and down the tower from it
        '  float sh = 0.0;',
        '  if (uPulseB.z + uPulseB.w > 0.0005) {',
        '    float pr = (length(vL - uPulseC.xyz) - uPulseC.w) * 1.6; float pq = 1.0 + pr * pr;',
        '    float b1 = (vL.y - uPulseB.x) * 3.2, b2 = (vL.y - uPulseB.y) * 3.2;',
        '    sh = uPulseB.w / (pq * pq) + uPulseB.z * (1.0 / (1.0 + b1 * b1) + 1.0 / (1.0 + b2 * b2));',
        '  }',
        // Colours are accumulated as scalar weights of the palette and mixed once at the end.
        '  vec3 col;',
        '  if (vState.z > 0.5) {',
        // --- seam: lit from inside the lattice (a little warmer at the near end); floor seams are kept lower
        '    float dH = max(min(uHull.x - abs(vL.x), uHull.y - abs(vL.z)), 0.0);',
        '    float dk = mix(0.16, 1.0, smoothstep(0.0, 0.26, dH));',
        '    float sG = ((0.32 + 0.38 * vSeed.z) * vState.w * (1.0 + 3.2 * trail * sK) * lightK * mix(1.0, 0.6, abs(N.y)) + line * sK * 1.4 + halo * sK * 0.4) * 1.5 * dk;',
        '    float m1 = 0.06 + 0.26 * nearK;',
        '    col = uBg + uViolet * ((1.0 - m1) * (1.0 - pinkK) * sG) + uMagenta * (m1 * (1.0 - pinkK) * sG) + uPink * (pinkK * sG + litS * 2.2 * dk) + uSeal * (sh * 2.6 * dk);',
        '  } else {',
        // --- a pane of dark glass
        '    float e = edgeDist(vP);',
        '    float aa = fwidth(e) + 1e-5;',
        '    float wl = max(0.014, aa);',
        '    float core = (1.0 - smoothstep(wl - aa, wl + aa, e)) * clamp(0.014 / wl, 0.4, 1.0);',
        '    float g1 = max(1.0 - e * 4.5, 0.0); g1 *= g1; float glow = g1 * g1;',
        '    float side = 1.0 - abs(N.y);',
        '    float vol = 0.45, back = 0.0, code = 0.0;',
        '    if (uDetail > 0.004) {',
        // path of the (slightly refracted) view ray through the block: volume tint + back edges
        '      vec3 rr = refract(rd, N, 0.78);',
        '      vec3 sg = step(0.0, rr) * 2.0 - 1.0; rr = sg * max(abs(rr), vec3(1e-4));',
        '      vec3 tt = (sg * uHalf - vP) / rr;',
        '      float tExit = min(tt.x, min(tt.y, tt.z));',
        '      vol = mix(0.45, tExit / (2.0 * uHalf), uDetail);',
        '      float eb = edgeDist(vP + rr * tExit);',
        '      back = (1.0 - smoothstep(wl, wl + aa * 2.0 + 0.012, eb)) * uDetail;',
        // rows of abstract dashes etched in some panes: the code under review (no glyphs)
        '      if (vSeed.z > 0.56 || fl > 0.01) {',
        '        float uu = mix(vP.z, vP.x, abs(N.z)) / uHalf * 0.5 + 0.5;',
        '        float rv = (vP.y / uHalf * 0.5 + 0.5) * 7.0;',
        '        float ri = floor(rv), rf = fract(rv), fwv = fwidth(rv);',
        '        float h1 = fract((ri * 0.618034 + vSeed.x * 7.13 + vSeed.y * 3.71) * 5.3713);',
        '        float h2 = fract(h1 * 57.31 + 0.17);',
        '        float ind = 0.15 + 0.09 * floor(h2 * 3.0);',
        '        float len = 0.14 + 0.36 * h1;',
        '        float seg = step(ind, uu) * step(uu, ind + len) + step(0.45, h2) * step(ind + len + 0.07, uu) * step(uu, min(ind + len + 0.07 + 0.22 * h2, 0.86));',
        '        float rowK = smoothstep(0.30 - fwv, 0.30, rf) * (1.0 - smoothstep(0.62, 0.62 + fwv, rf)) * step(1.0, ri) * step(ri, 5.0);',
        '        code = seg * rowK * side * (1.0 - smoothstep(0.3, 0.6, fwv)) * uDetail;',
        '      }',
        '    }',
        '    float s1 = max(dot(R, uKey), 0.0); s1 *= s1; s1 *= s1; s1 *= s1; float spec = s1 * s1;',
        '    float f1 = 1.0 - max(dot(-rd, N), 0.0); float fres = f1 * f1 * f1;',
        // bevel: the vertical edge of the pane nearest to this fragment catches the key light, or does not
        '    vec3 dd = uHalf - abs(vP) + abs(N) * 10.0;',
        '    vec3 mA = step(dd.xyz, dd.yzx) * step(dd.xyz, dd.zxy);',
        '    float bev = max(dot(N + mA * sign(vP), uKey) * 0.7071, 0.0) * (1.0 - 0.65 * mA.y * side);',
        '    float B = core * bev * bev * 0.85 * (0.5 + vSeed.y) * lightK;',
        '    float base = (0.016 + 0.11 * kd + 0.018 * vol + 0.02 * smoothstep(-uHalf, uHalf, vP.y) * side) * (0.5 + vSeed.x) * lightK;',
        '    float k1 = vSeed.y * vSeed.y * 0.6;',
        '    float bq = 1.0 + max(uScanY - vL.y, 0.0) * 0.9;',
        '    float topL = step(0.5, N.y) * step(vL.y, uScanY) * sK * 0.30 / (bq * bq);',
        // edges (front, back) and etched code take the edge colour: muted violet, pink near the plane, white-violet once sealed
        '    float eI = 0.19 * (1.0 + 4.0 * trail * sK) * lightK + sealK * 0.85;',
        '    float X = (core + glow * 0.12) * eI + back * (0.035 + 0.45 * trail * sK + 0.35 * sealK) + code * (0.085 + 0.8 * trail * sK + 0.5 * halo * sK);',
        '    float eS = X * sealK, eR = X - eS;',
        '    float wV = 0.7 * (1.0 - k1) * base + 0.204 * spec + 0.04 * fres + 0.55 * B;',
        '    float wI = 0.12 * base + 0.136 * spec + 0.105 * glint + 0.45 * B + 0.45 * code * fl + 0.34 * line * sK + fl * fl * (core + glow * 0.2 + 0.05 * vol) + 0.03 * sh;',
        // flagged: the block glows like hot glass (more light where the ray travels further through it)
        '    float wP = 0.3 * glint + 0.9 * code * fl + 0.85 * line * sK + 0.11 * halo * sK + topL + fl * (0.10 + 0.26 * vol + glow * 0.6 + core * 1.3 + back * 0.5)',
        '             + litS * (0.5 + core * 1.2 + glow * 0.3) + eR * pinkK;',
        '    float wS = eS + sealK * (0.045 + 0.06 * vol) + sh * ((core + glow * 0.12) * 1.5 + back + code + 0.07);',
        '    col = uBg + uViolet * wV + uMagenta * (0.7 * k1 * base) + uInk * wI + uPink * wP + uEdge * (eR * (1.0 - pinkK)) + uSeal * wS;',
        '  }',
        '  gl_FragColor = vec4(mix(uBg, col, vis), 1.0);',
        '}',
      ].join('\n'),
    });
    const blockMesh = new THREE.Mesh(blockGeo, blockMat);
    blockMesh.frustumCulled = false;
    group.add(blockMesh);

    // the arriving chain: NCH blocks that dock onto the dock columns (same material, its own small batch)
    const chOff = new Float32Array(NCH * 3), chSeed = new Float32Array(NCH * 4), chDir = new Float32Array(NCH * 3), chState = new Float32Array(NCH * 4);
    const chNbP = new Float32Array(NCH * 3), chNbN = new Float32Array(NCH * 3);
    for (let c = 0; c < NCH; c++) {
      const i = DOCK_I0 + c, n0 = lookup.get(cid(i, 0, DOCK_K));
      chOff[c * 3] = i - hx; chOff[c * 3 + 1] = 0; chOff[c * 3 + 2] = DOCK_K - hz;
      const ds = dockSeed(i); chSeed[c * 4] = ds[0]; chSeed[c * 4 + 1] = ds[1]; chSeed[c * 4 + 2] = ds[2]; chSeed[c * 4 + 3] = 0;
      chDir[c * 3] = 1;
      for (let q = 0; q < 3; q++) { chNbP[c * 3 + q] = aNbP[n0 * 3 + q]; chNbN[c * 3 + q] = aNbN[n0 * 3 + q]; }
    }
    const chainGeo = blockGeometry(NCH, chOff, chSeed, chDir, chNbP, chNbN, chState, true);
    const chainMesh = new THREE.Mesh(chainGeo, blockMat);
    chainMesh.frustumCulled = false;
    group.add(chainMesh);

    /* ---------- 2. scan sheet + pulse rings (horizontal quads hugging the tower, lattice space) ---------- */
    const NQ = 3;
    const quadGeo = new THREE.InstancedBufferGeometry();
    const quadSrc = new THREE.BufferGeometry();
    quadSrc.setAttribute('position', new THREE.BufferAttribute(new Float32Array([-1, 0, -1, 1, 0, -1, 1, 0, 1, -1, 0, 1]), 3));
    quadSrc.setIndex([0, 2, 1, 0, 3, 2]);
    quadGeo.index = quadSrc.index; quadGeo.setAttribute('position', quadSrc.attributes.position);
    const qA = new Float32Array(NQ * 4), qAAttr = new THREE.InstancedBufferAttribute(qA, 4); qAAttr.setUsage(THREE.DynamicDrawUsage);
    quadGeo.setAttribute('aQ', qAAttr); // x: height, y: kind (0 scan sheet, 1 ring), z: intensity, w: reach beyond the hull
    quadGeo.instanceCount = NQ;
    const sheetMat = new THREE.ShaderMaterial({
      uniforms: Object.assign({}, U),
      extensions: { derivatives: true },
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide,
      vertexShader: [
        'attribute vec4 aQ; uniform vec2 uHull; varying vec2 vXZ; varying vec2 vQ;',
        'void main(){ vec3 p = position; p.xz *= uHull + aQ.w; p.y = aQ.x; vXZ = p.xz; vQ = aQ.yz;',
        '  gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0); }',
      ].join('\n'),
      fragmentShader: [
        'precision highp float;', GL_COMMON, 'varying vec2 vXZ; varying vec2 vQ;',
        'void main(){',
        '  vec2 q = abs(vXZ) - uHull;',
        '  float d = length(max(q, 0.0)) + min(max(q.x, q.y), 0.0);',
        '  float fw = fwidth(d);',
        '  vec3 c;',
        '  if (vQ.x < 0.5) {',
        '    float outK = smoothstep(-0.05, 0.12, d);',
        '    float fall = exp(-max(d, 0.0) / 1.5);',
        '    float w1 = max(0.03, fw * 1.1);',
        '    float rim = exp(-pow((d - 0.42) / w1, 2.0)) * (0.03 / w1);',
        '    float w2 = max(0.018, fw * 1.1);',
        '    float rim2 = exp(-pow((d - 1.3) / w2, 2.0)) * (0.018 / w2) * 0.4;',
        '    c = uMagenta * fall * 0.15 * outK + uPink * (rim + rim2) * 0.9 + uMagenta * (1.0 - outK) * 0.10;',
        '    c *= 1.0 - smoothstep(2.6, 3.9, d);',
        '  } else {',
        '    float w1 = max(0.035, fw * 1.1);',
        '    float rim = exp(-pow((d - 0.30) / w1, 2.0)) * (0.035 / w1);',
        '    float soft = exp(-abs(d - 0.30) * 3.0) * 0.16;',
        '    vec3 rc = mix(uSeal, uPink, 0.22);',
        '    c = (rc + uInk * 0.35) * rim + rc * soft;',
        '    c *= 1.0 - smoothstep(1.2, 1.9, d);',
        '  }',
        '  gl_FragColor = vec4(c * vQ.y * uDim * screenMask(), 1.0);',
        '}',
      ].join('\n'),
    });
    const sheet = new THREE.Mesh(quadGeo, sheetMat);
    sheet.frustumCulled = false;
    group.add(sheet);

    /* ---------- 3. rails, sockets, reticles, lock bolts, link beams (screen-space thick lines, lattice space) ---------- */
    const NSLOT = 4, SEG_PER = 20, NLINK = (NCH - 1) * 2, NSEG = NSLOT * SEG_PER + NLINK;
    const lA = new Float32Array(NSEG * 4 * 3), lB = new Float32Array(NSEG * 4 * 3), lSide = new Float32Array(NSEG * 4 * 2), lI = new Float32Array(NSEG * 4 * 4);
    const lIdx = new Uint16Array(NSEG * 6);
    for (let s = 0; s < NSEG; s++) {
      const sides = [0, -1, 0, 1, 1, -1, 1, 1];
      for (let v = 0; v < 8; v++) lSide[s * 8 + v] = sides[v];
      lIdx.set([s * 4, s * 4 + 2, s * 4 + 1, s * 4 + 1, s * 4 + 2, s * 4 + 3], s * 6);
    }
    const lineGeo = new THREE.BufferGeometry();
    const lAAttr = new THREE.BufferAttribute(lA, 3), lBAttr = new THREE.BufferAttribute(lB, 3), lIAttr = new THREE.BufferAttribute(lI, 4);
    lAAttr.setUsage(THREE.DynamicDrawUsage); lBAttr.setUsage(THREE.DynamicDrawUsage); lIAttr.setUsage(THREE.DynamicDrawUsage);
    lineGeo.setAttribute('position', lAAttr); lineGeo.setAttribute('aB', lBAttr);
    lineGeo.setAttribute('aSide', new THREE.BufferAttribute(lSide, 2)); lineGeo.setAttribute('aI', lIAttr);
    lineGeo.setIndex(new THREE.BufferAttribute(lIdx, 1));
    const lineMat = new THREE.ShaderMaterial({
      uniforms: Object.assign({}, U, { uLineW: { value: 1.6 } }),
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide,
      vertexShader: [
        'attribute vec3 aB; attribute vec2 aSide; attribute vec4 aI;',
        'uniform vec2 uRes; uniform float uLineW;',
        'varying float vAcross; varying vec2 vI; varying vec2 vFlow;',
        'void main(){',
        '  vec4 a = projectionMatrix * modelViewMatrix * vec4(position, 1.0);',
        '  vec4 b = projectionMatrix * modelViewMatrix * vec4(aB, 1.0);',
        '  vec2 d = (b.xy / b.w - a.xy / a.w) * uRes * 0.5;',
        '  float len = length(d);',
        '  vec2 dir = len > 1e-4 ? d / len : vec2(1.0, 0.0);',
        '  vec4 p = mix(a, b, aSide.x);',
        '  p.xy += vec2(-dir.y, dir.x) * aSide.y * uLineW * aI.z / (uRes * 0.5) * p.w;',
        '  gl_Position = p; vAcross = aSide.y; vI = aI.xy; vFlow = vec2(aSide.x, aI.w);',
        '}',
      ].join('\n'),
      fragmentShader: [
        'precision highp float;', GL_COMMON, 'varying float vAcross; varying vec2 vI; varying vec2 vFlow;',
        'void main(){',
        '  float a = 1.0 - smoothstep(0.3, 1.0, abs(vAcross));',
        // link beams carry a packet of light towards the tower
        '  if (vFlow.y > 0.0) { float q = (fract(vFlow.x * 0.5 - uTime * 0.7 + vFlow.y) - 0.5) * 5.0; a *= 0.45 + 1.4 / (1.0 + q * q * q * q); }',
        '  vec3 c = mix(uPink, uSeal, vI.y);',
        '  c = mix(c, uInk, clamp(vI.x - 0.9, 0.0, 0.7));',
        '  gl_FragColor = vec4(c * a * min(vI.x, 1.4) * uDim * screenMask(), 1.0);',
        '}',
      ].join('\n'),
    });
    const lineMesh = new THREE.Mesh(lineGeo, lineMat);
    lineMesh.frustumCulled = false;
    group.add(lineMesh);
    // inten: brightness (> 0.9 turns white), hue: 0 pink .. 1 white-violet, wid: width factor
    function setSeg(s, ax, ay, az, bx, by, bz, inten, hue, wid, flow) {
      const o = s * 12, o3 = s * 16;
      for (let v = 0; v < 4; v++) {
        lA[o + v * 3] = ax; lA[o + v * 3 + 1] = ay; lA[o + v * 3 + 2] = az;
        lB[o + v * 3] = bx; lB[o + v * 3 + 1] = by; lB[o + v * 3 + 2] = bz;
        lI[o3 + v * 4] = inten; lI[o3 + v * 4 + 1] = hue; lI[o3 + v * 4 + 2] = wid; lI[o3 + v * 4 + 3] = flow || 0;
      }
    }
    function clearSegs(s0, n) { for (let s = s0; s < s0 + n; s++) for (let v = 0; v < 4; v++) lI[s * 16 + v * 4] = 0; }

    /* ---------- 4. backdrop: the static haze in one quad ---------- */
    const backGeo = new THREE.PlaneGeometry(34, 44);
    const backMat = new THREE.ShaderMaterial({
      uniforms: Object.assign({}, U),
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: 'varying vec2 vXY; void main(){ vec4 wp = modelMatrix * vec4(position, 1.0); vXY = wp.xy; gl_Position = projectionMatrix * viewMatrix * wp; }',
      fragmentShader: [
        'precision highp float;', GL_COMMON, 'varying vec2 vXY;',
        'float lobe(vec2 c, vec2 r){ float a = max(1.0 - length((vXY - c) / r), 0.0); return a * a; }',
        'void main(){',
        '  vec3 c = uViolet * 0.15 * lobe(vec2(1.0, -3.0), vec2(16.0, 17.0))',
        '         + uMagenta * 0.075 * lobe(vec2(2.0, -8.0), vec2(10.0, 12.0))',
        '         + uViolet * 0.09 * lobe(vec2(1.2, -4.0), vec2(3.4, 20.0));',
        '  c *= uDim * screenMask();',
        '  gl_FragColor = vec4(c + (dither() - 0.5) * 0.004 * step(0.0005, c.b), 1.0);',
        '}',
      ].join('\n'),
    });
    const backMesh = new THREE.Mesh(backGeo, backMat);
    backMesh.position.set(1, -4, -9); backMesh.frustumCulled = false;
    scene.add(backMesh);

    /* ---------- 5. glow sprites: mist, scan bloom, flagged halos and streaks, pulse flash (world space billboards) ---------- */
    const NSPR = NSLOT * 2 + 5;
    const sC = new Float32Array(NSPR * 3), sS = new Float32Array(NSPR * 3), sCol = new Float32Array(NSPR * 4);
    const sprGeo = new THREE.InstancedBufferGeometry();
    const planeSrc = new THREE.PlaneGeometry(1, 1);
    sprGeo.index = planeSrc.index; sprGeo.setAttribute('position', planeSrc.attributes.position);
    const sCAttr = new THREE.InstancedBufferAttribute(sC, 3), sSAttr = new THREE.InstancedBufferAttribute(sS, 3), sColAttr = new THREE.InstancedBufferAttribute(sCol, 4);
    sCAttr.setUsage(THREE.DynamicDrawUsage); sSAttr.setUsage(THREE.DynamicDrawUsage); sColAttr.setUsage(THREE.DynamicDrawUsage);
    sprGeo.setAttribute('aC', sCAttr); sprGeo.setAttribute('aS', sSAttr); sprGeo.setAttribute('aCol', sColAttr);
    sprGeo.instanceCount = NSPR;
    const sprMat = new THREE.ShaderMaterial({
      uniforms: Object.assign({}, U),
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: [
        'attribute vec3 aC; attribute vec3 aS; attribute vec4 aCol; varying vec2 vUv; varying vec4 vCol;',
        'void main(){',
        '  vec4 mv = viewMatrix * vec4(aC, 1.0);',
        '  mv.xy += position.xy * aS.xy; mv.z += aS.z;',
        '  gl_Position = projectionMatrix * mv; vUv = position.xy * 2.0; vCol = aCol;',
        '}',
      ].join('\n'),
      fragmentShader: [
        'precision highp float;', GL_COMMON, 'varying vec2 vUv; varying vec4 vCol;',
        'void main(){',
        '  float r = length(vUv);',
        '  float a = max(1.0 - r, 0.0); a = a * a * mix(1.0, a, vCol.a);',
        '  vec3 c = vCol.rgb * a * uDim * screenMask();',
        '  gl_FragColor = vec4(c + (dither() - 0.5) * 0.004 * step(0.001, a), 1.0);',
        '}',
      ].join('\n'),
    });
    const sprMesh = new THREE.Mesh(sprGeo, sprMat);
    sprMesh.frustumCulled = false;
    scene.add(sprMesh);
    function setSprite(n, x, y, z, sx, sy, bias, color, inten, falloff) {
      sC[n * 3] = x; sC[n * 3 + 1] = y; sC[n * 3 + 2] = z;
      sS[n * 3] = sx; sS[n * 3 + 1] = sy; sS[n * 3 + 2] = bias;
      sCol[n * 4] = color.r * inten; sCol[n * 4 + 1] = color.g * inten; sCol[n * 4 + 2] = color.b * inten; sCol[n * 4 + 3] = falloff;
    }

    /* ---------- 6. drifting dust (world space points) ---------- */
    const ND = LOW ? 160 : 340;
    const DBOX = [40, 26, 28], DCEN = [-1, -5, 1];
    const dPos = new Float32Array(ND * 3), dSeed = new Float32Array(ND * 4);
    for (let i = 0; i < ND; i++) {
      dPos[i * 3] = DCEN[0] + (rand() - 0.5) * DBOX[0]; dPos[i * 3 + 1] = rand() * DBOX[1]; dPos[i * 3 + 2] = DCEN[2] + (rand() - 0.5) * DBOX[2];
      const big = rand() < 0.035;
      dSeed[i * 4] = rand(); dSeed[i * 4 + 1] = rand(); dSeed[i * 4 + 2] = big ? 0.5 + rand() * 0.5 : 0.035 + rand() * rand() * 0.10; dSeed[i * 4 + 3] = rand();
    }
    const dustGeo = new THREE.BufferGeometry();
    dustGeo.setAttribute('position', new THREE.BufferAttribute(dPos, 3));
    dustGeo.setAttribute('aSeed', new THREE.BufferAttribute(dSeed, 4));
    const dustMat = new THREE.ShaderMaterial({
      uniforms: Object.assign({}, U, { uPx: { value: 1000 }, uBox: { value: new THREE.Vector3(DBOX[1], DCEN[1], 0) } }),
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
      vertexShader: [
        'attribute vec4 aSeed; uniform float uTime, uPx, uScanY, uScanK; uniform vec3 uBox;',
        'varying float vA; varying float vTint; varying float vSoft;',
        'void main(){',
        '  vec3 p = position;',
        '  float yy = mod(p.y + uTime * (0.05 + 0.13 * aSeed.x), uBox.x);',
        '  float yn = yy / uBox.x;',
        '  p.y = yy - uBox.x * 0.5 + uBox.y;',
        '  p.x += sin(uTime * (0.06 + 0.09 * aSeed.y) + aSeed.y * 30.0) * 0.7;',
        '  p.z += cos(uTime * (0.05 + 0.07 * aSeed.x) + aSeed.x * 17.0) * 0.7;',
        '  vec4 mv = modelViewMatrix * vec4(p, 1.0);',
        '  float d = -mv.z;',
        '  float size = aSeed.z * uPx / max(d, 0.1);',
        '  float big = step(0.4, aSeed.z);',
        '  float a = smoothstep(4.0, 12.0, d) * smoothstep(90.0, 50.0, d) * smoothstep(0.0, 0.1, yn) * smoothstep(1.0, 0.9, yn);',
        '  a *= 0.55 + 0.45 * sin(uTime * (0.4 + aSeed.w) + aSeed.w * 50.0);',
        '  a *= mix(0.95, 0.055, big);',
        '  float sy = p.y - uScanY;',
        '  float lit = exp(-sy * sy / 0.5) * exp(-dot(p.xz, p.xz) / 90.0) * uScanK;',
        '  a *= 1.0 + 3.0 * lit;',
        '  float ps = max(size, 1.3);',
        '  a *= min(1.0, (size * size) / (1.3 * 1.3));',
        '  gl_PointSize = min(ps, 90.0);',
        '  vA = a; vTint = clamp(aSeed.w * 0.8 + lit, 0.0, 1.0); vSoft = big;',
        '  gl_Position = projectionMatrix * mv;',
        '}',
      ].join('\n'),
      fragmentShader: [
        'precision highp float;', GL_COMMON, 'varying float vA; varying float vTint; varying float vSoft;',
        'void main(){',
        '  float r = length(gl_PointCoord - 0.5) * 2.0;',
        '  float a = mix(pow(max(1.0 - r, 0.0), 1.6), smoothstep(1.0, 0.75, r), vSoft);',
        '  vec3 c = mix(uViolet * 0.9 + uInk * 0.15, uPink, vTint * vTint);',
        '  gl_FragColor = vec4(c * a * vA * uDim * screenMask(), 1.0);',
        '}',
      ].join('\n'),
    });
    const dust = new THREE.Points(dustGeo, dustMat);
    dust.frustumCulled = false;
    scene.add(dust);

    /* ---------- layout: where the tower sits and how big it is, in CSS pixels ---------- */
    // The site's hero copy: on desktop (> 820 px) a left column whose headline never wraps (font-size
    // clamp(34px, 4.5vw, 66px), inside a 1360 px container with 40 px padding) and a 31em lede of 19 px;
    // at 820 px and below the copy sits at the bottom (44 px padding) under a 110 px header.
    const NAV_B = 110;
    const EXT_L = 4.7, EXT_R = 4.0;          // tower half-widths on screen in cells (left side includes slid-out blocks)
    const lay = { pk: 0, cell: 40, ax: 0, top: 0, textR: 0, x0: 0, textT: 0 };
    function layout() {
      const w = Math.max(1, S.w), h = Math.max(1, S.h), rk = S.routeK, sk = S.scrollK;
      const pk = 1 - smooth(808, 832, w);                    // 1 = phone layout (copy below), 0 = desktop (copy left)
      // desktop hero: in the free area right of the copy column
      const left = Math.max(40, (w - 1360) / 2 + 40);
      const fs = Math.min(66, Math.max(34, 0.045 * w));
      const textR = left + Math.max(12.07 * fs, 580);
      const x0 = textR + Math.max(24, 0.025 * w), x1 = w - Math.max(10, 0.03 * w);
      const topD = Math.max(NAV_B + 66, 0.22 * h);
      const cellD = Math.max(3, Math.min((x1 - x0) / (EXT_L + EXT_R), (0.96 * h - topD) / 13.4, h / 11));
      const axD = x0 + EXT_L * cellD + Math.max(0, (x1 - x0) - (EXT_L + EXT_R) * cellD) * 0.5;
      // phone hero: in the band between the header and the copy
      const copyH = w < 440 ? 432 : w > 640 ? 300 : 432 - (w - 440) * 0.66;
      const textT = h - 44 - copyH;
      const bandT = NAV_B + 14, bandB = Math.max(bandT + 0.1 * h, textT - 0.02 * h);
      const cellP = Math.max(3, Math.min((w - 2 * Math.max(14, 0.04 * w)) / (EXT_L + EXT_R), Math.max((bandB - bandT) / 8.6, 0.026 * h), h / 15));
      const topP = bandT + 1.3 * cellP, axP = w * 0.5 + 0.35 * cellP;
      // inner pages: smaller, against the right edge, clear of a content panel where there is room
      const cellAD = Math.max(3, Math.min(cellD * 0.82, h / 15)), axAD = w - Math.max(14, 0.02 * w) - 4.1 * cellAD, topAD = Math.max(NAV_B + 40, 0.17 * h);
      const cellAP = cellP * 0.8, axAP = w * 0.76, topAP = 0.5 * h;   // phone inner pages: low on the right, under the content
      const cH = lerp(cellD, cellP, pk), cA = lerp(cellAD, cellAP, pk);
      lay.pk = pk;
      lay.cell = lerp(cH, cA, rk) / (1 + 0.6 * sk);
      lay.ax = lerp(lerp(axD, axP, pk), lerp(axAD, axAP, pk), rk);
      lay.top = lerp(lerp(topD, topP, pk), lerp(topAD, topAP, pk), rk) - (0.11 - 0.09 * pk) * h * sk;   // lifts a little, stays below the header
      lay.textR = textR; lay.x0 = x0; lay.textT = textT;
      return lay;
    }
    // Where the focal mass sits on screen, in NDC-ish units (-1..1): the tower's axis.
    function focus() { const L = layout(); return { x: (L.ax / Math.max(1, S.w)) * 2 - 1, y: 0 }; }

    /* ---------- the timeline ---------- */
    const sweepOf = (t) => Math.floor((t + SCAN_PHI) / SCAN_T);
    // the time at which sweep s (even: upwards, odd: downwards) reaches the middle of row y
    function crossTime(s, y) {
      const up = (s & 1) === 0;
      const ph = up ? (y - 0.25 - SCAN_Y0) / (SCAN_Y1 - SCAN_Y0) : (SCAN_Y1 - (y + 0.25)) / (SCAN_Y1 - SCAN_Y0);
      return (s + ph) * SCAN_T - SCAN_PHI;
    }
    // a flagged block, tau seconds after the scan crossed it: found, acquired, locked (verified), sealed
    function evSlide(tau) {
      if (tau <= 0 || tau >= REACT) return 0;
      if (tau < 0.6) return easeOutBack(tau / 0.6);
      if (tau < BACK_AT) return 1;
      return 1 - easeInOut((tau - BACK_AT) / (REACT - BACK_AT));
    }
    function evFlare(tau) {
      if (tau <= -0.15 || tau >= REACT) return 0;
      if (tau < 0.08) return smooth(-0.15, 0.08, tau);
      return (0.5 + 0.5 * Math.exp(-(tau - 0.08) * 3.0)) * (1 - 0.75 * smooth(LOCK_AT, BACK_AT + 0.3, tau)) * (1 - smooth(REACT - 1.0, REACT, tau));
    }
    function evSeal(tau) {
      if (tau < LOCK_AT) return 0;
      if (tau < REACT) return smooth(LOCK_AT, LOCK_AT + 0.25, tau);
      return Math.exp(-(tau - REACT) / SCAR_T);
    }
    // pulse(): the finding being validated is the flagged block that is out right now, or else the next one
    let pT = { at: NaN, ci: -1, q: 0, tc: 0, s0: 0 };
    function pulseTarget(pA) {
      if (pT.at === pA) return pT;
      const s = sweepOf(pA);
      let best = null, bestScore = -1, next = null;
      for (let q = s - 1; q <= s + 2; q++) {
        const f = flagsOf(q);
        for (let m = 0; m < f.length; m++) {
          const ci = f[m], tc = crossTime(q, cand[ci].c[1]), tau = pA - tc;
          if (tau > -0.2 && tau < BACK_AT + 0.5) {
            const sc = evSlide(Math.max(tau, 1e-3)) + (tau < LOCK_AT ? 0.5 : 0);
            if (sc > bestScore) { bestScore = sc; best = { ci: ci, q: q, tc: tc }; }
          } else if (tau <= -0.2 && (!next || tc < next.tc)) next = { ci: ci, q: q, tc: tc };
        }
      }
      const b = best || next;
      pT = { at: pA, ci: b.ci, q: b.q, tc: b.tc, s0: evSlide(Math.max(1e-3, pA - b.tc)) };
      return pT;
    }

    const bSlide = new Float32Array(cand.length), bFlare = new Float32Array(cand.length), bSeal = new Float32Array(cand.length);
    const bLock = new Float32Array(cand.length), bTick = new Float32Array(cand.length), bBolt = new Float32Array(cand.length), bAcq = new Float32Array(cand.length);
    const drawSize = new THREE.Vector2();
    const order = [];
    const toWorld = (x, y, z, cs, sn, out) => { out[0] = x * cs + z * sn; out[1] = y; out[2] = -x * sn + z * cs; return out; };
    const W3 = [0, 0, 0];

    function update(t) {
      const L = layout();
      const rk = S.routeK, sk = S.scrollK, pk = L.pk, hero = 1 - rk;
      const dim = (1 - 0.5 * rk) * (1 - (0.6 + 0.22 * pk) * sk) * (1 + 0.15 * pk);

      /* --- scan: hero sweeps every 7 s; inner pages one slow sweep every 26 s --- */
      const qh = (t + SCAN_PHI) / SCAN_T, sw = Math.floor(qh), ph = qh - sw;
      const scanH = (sw & 1) === 0 ? lerp(SCAN_Y0, SCAN_Y1, ph) : lerp(SCAN_Y1, SCAN_Y0, ph);
      const envH = smooth(0, 0.06, ph) * (1 - smooth(0.94, 1, ph));
      const qa = t / AMB_T, sa = Math.floor(qa), pa = qa - sa;
      const scanA = (sa & 1) === 0 ? lerp(SCAN_Y0, SCAN_Y1, pa) : lerp(SCAN_Y1, SCAN_Y0, pa);
      const envA = smooth(0, 0.08, pa) * (1 - smooth(0.92, 1, pa));
      const scanY = lerp(scanH, scanA, rk);
      const scanK = lerp(envH, envA * 0.42, rk) * (1 - (0.3 + 0.62 * pk) * sk);
      const scanUp = rk < 0.5 ? (sw & 1) === 0 : (sa & 1) === 0;

      /* --- pulse --- */
      const pd = t - S.pulseAt, pOn = pd >= 0 && pd < 40;
      const tgt = pOn ? pulseTarget(S.pulseAt) : null;
      const pLive = pOn && pd < 2.4;

      /* --- flagged blocks --- */
      bSlide.fill(0); bFlare.fill(0); bSeal.fill(0); bLock.fill(0); bTick.fill(0); bBolt.fill(0); bAcq.fill(0);
      for (let q = sw - 4; q <= sw + 1; q++) {
        const f = flagsOf(q);
        for (let m = 0; m < f.length; m++) {
          const ci = f[m], tc = crossTime(q, cand[ci].c[1]);
          let tau = t - tc, sl, fl, se, lk, tk, bo, ac;
          if (tgt && tgt.q === q && tgt.ci === ci) {
            // the validated finding: snap out (if it was not), lock with bolts, flash white, slide back sealed
            sl = pd < 0.22 ? tgt.s0 + (1 - tgt.s0) * easeOut3(pd / 0.22) : pd < 1.05 ? 1 : pd < 1.95 ? 1 - easeInOut((pd - 1.05) / 0.9) : 0;
            const flash = smooth(0.04, 0.12, pd) * Math.exp(-Math.max(0, pd - 0.12) * 3.2);
            fl = Math.max(0.35 * (1 - smooth(0.6, 1.6, pd)), 1.45 * flash);
            lk = smooth(0.0, 0.14, pd); tk = flash; ac = 1;
            bo = smooth(0.04, 0.2, pd) * (1 - smooth(0.95, 1.5, pd));
            se = pd < 1.95 ? smooth(0.06, 0.2, pd) : Math.exp(-(pd - 1.95) / 15);
          } else {
            sl = evSlide(tau); fl = evFlare(tau); se = evSeal(tau);
            lk = smooth(LOCK_AT - 0.1, LOCK_AT + 0.06, tau);
            const dl = tau - LOCK_AT - 0.04; tk = dl > 0 ? smooth(0, 0.05, dl) * Math.exp(-dl * 5.0) : 0;
            bo = 0; ac = smooth(0.2, 0.75, tau);
          }
          if (sl > bSlide[ci]) { bSlide[ci] = sl; bLock[ci] = lk; bAcq[ci] = ac; }
          bFlare[ci] = Math.max(bFlare[ci], fl); bSeal[ci] = Math.max(bSeal[ci], se);
          bTick[ci] = Math.max(bTick[ci], tk); bBolt[ci] = Math.max(bBolt[ci], bo);
        }
      }
      aState.fill(0);
      const calm = hero;                                      // slides are a hero thing
      for (let ci = 0; ci < cand.length; ci++) {
        const n = cand[ci].n;
        aState[n * 4] = bSlide[ci] * SLIDE * calm;
        aState[n * 4 + 1] = bFlare[ci] * (1 - 0.85 * rk) * (pLive && tgt && tgt.ci === ci ? 1 : hero);
        aState[n * 4 + 3] = bSeal[ci] * (1 - 0.6 * rk);
      }

      /* --- the arriving chain: glides in over the stepped far end one cell above the top, closes up, docks and presses the ledger down a row --- */
      const cq = (t + CH_OFF) / CH_T, phi = (cq - Math.floor(cq)) * CH_T;
      const chainOn = rk < 0.5;
      const sink = chainOn ? easeInOut(clamp01((phi - 7.6) / 1.2)) : 0;
      const gp = clamp01(phi / 7.0), glide = 1 - (1 - gp) * (1 - gp);
      const xLead = CH_X0 * (1 - glide);
      const sp = lerp(1.95, 1.0, smooth(6.0, 7.0, phi));
      const grow = smooth(0.0, 0.9, phi) * (1 - smooth(0.15, 0.45, rk));
      const fresh = phi < 8.8 ? 0.75 : 0.75 * Math.exp(-(phi - 8.8) / 1.4);
      for (let c = 0; c < NCH; c++) {
        chState[c * 4] = -(xLead + (NCH - 1 - c) * (sp - 1));     // the lead (c = NCH - 1) docks in the far slot
        chState[c * 4 + 1] = 0;
        chState[c * 4 + 2] = 1 - sink;
        chState[c * 4 + 3] = fresh;
        chSeed[c * 4 + 3] = chainOn ? grow : 0;
      }
      for (let m = 0; m < dockN.length; m++) aState[dockN[m] * 4 + 2] = -sink;
      chainGeo.attributes.aState.needsUpdate = true; chainGeo.attributes.aSeed.needsUpdate = true;
      chainMesh.visible = chainOn && grow > 0.001;
      blockGeo.attributes.aState.needsUpdate = true;

      /* --- lattice turn + camera --- */
      const th = spinAt(t) + S.px * 0.10;
      const cs = Math.cos(th), sn = Math.sin(th);
      group.rotation.y = th;
      const cell = Math.max(1, L.cell);
      const vh = Math.max(2, S.h / cell);                   // visible height (cells) at the look-at plane
      const D = Math.min(320, Math.max(6, vh / (2 * TANF)));
      const az = S.px * 0.07 + 0.03 * Math.sin(t * 0.09);
      const el = 0.205 + 0.03 * Math.sin(t * 0.047 + 0.4) - S.py * 0.04;
      const ty = 0.43 - (S.h * 0.5 - L.top) / cell;          // the slab's top edge at L.top
      camera.fov = FOV;
      camera.position.set(Math.sin(az) * Math.cos(el) * D, ty + Math.sin(el) * D, Math.cos(az) * Math.cos(el) * D);
      camera.lookAt(0, ty, 0);

      /* --- lights: the two hottest flagged blocks light their neighbours --- */
      order.length = 0;
      for (let ci = 0; ci < cand.length; ci++) if (bFlare[ci] > 0.004) order.push(ci);
      order.sort((a, b) => bFlare[b] - bFlare[a]);
      let nl = 0;
      for (let i = 0; i < NL; i++) {
        const ci = order[i], Lg = lights[i];
        if (ci !== undefined && hero > 0.02) {
          const c = cand[ci], s = bSlide[ci] * SLIDE * calm;
          Lg.set(c.c[0] + c.nrm[0] * s, c.c[1], c.c[2] + c.nrm[2] * s, bFlare[ci] * 0.9 * hero); nl++;
        } else Lg.set(0, 0, 0, 0);
      }

      /* --- rails, sockets, reticles, lock bolts --- */
      const slots = [];
      for (let ci = 0; ci < cand.length; ci++) if (bSlide[ci] > 0.004 && calm > 0.01) slots.push(ci);
      slots.sort((a, b) => bSlide[b] + bFlare[b] - bSlide[a] - bFlare[a]);
      for (let si = 0; si < NSLOT; si++) {
        const s0 = si * SEG_PER, ci = slots[si];
        if (ci === undefined) { clearSegs(s0, SEG_PER); continue; }
        const f = cand[ci], sl = bSlide[ci] * SLIDE, fl = bFlare[ci], lk = bLock[ci], se = bSeal[ci], tk = bTick[ci], bo = bBolt[ci];
        const on = Math.min(1, sl / (SLIDE * 0.5)) * calm;
        const cx = f.c[0], cy = f.c[1], cz = f.c[2], nx = f.nrm[0], nz = f.nrm[2], ux = f.u[0], uz = f.u[2];
        const inner = Math.max(HALF, sl - HALF);
        const outer = sl + HALF + 0.17;                       // reticle plane
        const acq = bAcq[ci];
        // the reticle closes in while acquiring; at the verdict it snaps tight and its strokes join into a frame
        const rs = lerp((HALF + 0.17) * (1 + 0.55 * (1 - acq)), HALF + 0.11, lk);
        const rl = lerp(0.27, rs, lk);
        const hot = 0.55 + 0.75 * fl;
        const hue = Math.min(1, lk * 0.9 + se * 0.3);
        let s = s0;
        for (let a = 0; a < 4; a++) {
          const su = a & 1 ? 1 : -1, sv = a & 2 ? 1 : -1;
          // rail: slot mouth corner -> block inner corner
          const px = cx + ux * su * HALF, py = cy + sv * HALF, pz = cz + uz * su * HALF;
          setSeg(s++, px + nx * HALF, py, pz + nz * HALF, px + nx * inner, py, pz + nz * inner, on * hot * 0.55, hue * 0.6, 1);
          // socket frame around the empty slot
          const e1x = cx + ux * su * 0.5 + nx * HALF, e1z = cz + uz * su * 0.5 + nz * HALF;
          if (a < 2) setSeg(s++, e1x, cy - 0.5, e1z, e1x, cy + 0.5, e1z, on * hot * 0.5, hue * 0.6, 1);
          else { const yy = cy + (a === 2 ? -0.5 : 0.5); setSeg(s++, cx - ux * 0.5 + nx * HALF, yy, cz - uz * 0.5 + nz * HALF, cx + ux * 0.5 + nx * HALF, yy, cz + uz * 0.5 + nz * HALF, on * hot * 0.5, hue * 0.6, 1); }
          // reticle corner: two strokes (they meet the neighbouring corner's strokes once locked)
          const qx = cx + nx * outer + ux * su * rs, qy = cy + sv * rs, qz = cz + nz * outer + uz * su * rs;
          const ri = on * smooth(0.0, 0.5, acq) * (0.75 + 0.6 * fl) + tk * 1.2;
          setSeg(s++, qx, qy, qz, qx - ux * su * rl, qy, qz - uz * su * rl, ri, hue, 1 + 0.5 * lk);
          setSeg(s++, qx, qy, qz, qx, qy - sv * rl, qz, ri, hue, 1 + 0.5 * lk);
        }
        // lock bolts: four short bars slide in from outside and seat against the frame
        for (let a = 0; a < 4; a++) {
          const bu = a === 0 ? -1 : a === 1 ? 1 : 0, bv = a === 2 ? -1 : a === 3 ? 1 : 0;
          const gap = rs + 0.06 + 0.42 * (1 - easeOut3(bo)), blen = 0.2;
          const ax = cx + nx * outer + ux * bu * gap, ay = cy + bv * gap, az2 = cz + nz * outer + uz * bu * gap;
          const bx = cx + nx * outer + ux * bu * (gap + blen), by = cy + bv * (gap + blen), bz = cz + nz * outer + uz * bu * (gap + blen);
          setSeg(s++, ax, ay, az2, bx, by, bz, bo * on * (1.0 + tk), 1, 2.2);
        }
      }
      // link beams: two parallel beams between neighbouring chain blocks
      const linkK = chainOn ? grow * smooth(0.25, 1.1, phi) * (1 - smooth(6.3, 7.1, phi)) : 0;
      for (let c = 0; c < NCH - 1; c++) {
        const xa = (DOCK_I0 + c - hx) + chState[c * 4] + HALF * grow, xb = (DOCK_I0 + c + 1 - hx) + chState[(c + 1) * 4] - HALF * grow;
        const yy = 1 - sink, zz = DOCK_K - hz;
        for (let p = 0; p < 2; p++) {
          const oy = (p ? 0.17 : -0.17) * grow;
          setSeg(NSLOT * SEG_PER + c * 2 + p, xa, yy + oy, zz, xb, yy + oy, zz, linkK * 1.05, 0.5, 2.4, 0.13 + 0.5 * c + 0.25 * p);
        }
      }
      lAAttr.needsUpdate = true; lBAttr.needsUpdate = true; lIAttr.needsUpdate = true;

      /* --- scan sheet and pulse rings --- */
      const fadeK = (y) => smooth(U.uFadeY.value.x, U.uFadeY.value.y, y);
      let pcx = 0, pcy = -100, pcz = 0, pFlash = 0, bandI = 0, bandA = -100, bandB = -100, flashR = 0;
      if (tgt && pLive) {
        const c = cand[tgt.ci], s = (bSlide[tgt.ci] || 0) * SLIDE * calm;
        pcx = c.c[0] + c.nrm[0] * s; pcy = c.c[1]; pcz = c.c[2] + c.nrm[2] * s;
        pFlash = smooth(0.03, 0.1, pd) * Math.exp(-Math.max(0, pd - 0.1) * 3.4);
        const bt = Math.max(0, pd - 0.1);
        bandA = pcy + 6.5 * bt; bandB = pcy - 6.5 * bt;
        bandI = smooth(0.08, 0.16, pd) * Math.exp(-bt * 1.5) * (1 - smooth(1.6, 2.3, pd));
        flashR = 0.4 + 2.6 * easeOut3(Math.min(1, pd / 0.7));
      }
      const pk2 = 1 - 0.55 * rk;
      qA[0] = scanY; qA[1] = 0; qA[2] = scanK * fadeK(scanY); qA[3] = 4.0;
      qA[4] = bandA; qA[5] = 1; qA[6] = bandI * 1.1 * pk2 * fadeK(bandA) * (bandA < 0.9 ? 1 : 1 - smooth(0.9, 2.0, bandA)); qA[7] = 2.0;
      qA[8] = bandB; qA[9] = 1; qA[10] = bandI * 1.1 * pk2 * fadeK(bandB); qA[11] = 2.0;
      qAAttr.needsUpdate = true;

      /* --- sprites --- */
      let n = 0;
      setSprite(n++, 0.5, -12.5, 5, 26, 8, 0, cVio, 0.05, 0);                // mist the tower rises from
      setSprite(n++, 0, scanY, 0, 12.5, 2.2, 7, cPink, 0.15 * scanK * fadeK(scanY), 0); // bloom on the scan line
      for (let si = 0; si < NSLOT; si++) {
        const ci = order[si];
        if (ci === undefined) { setSprite(n++, 0, 0, 0, 0, 0, 0, cPink, 0, 0); setSprite(n++, 0, 0, 0, 0, 0, 0, cPink, 0, 0); continue; }
        const f = cand[ci], s = bSlide[ci] * SLIDE * calm, g = bFlare[ci] * (1 - 0.85 * rk);
        toWorld(f.c[0] + f.nrm[0] * s, f.c[1], f.c[2] + f.nrm[2] * s, cs, sn, W3);
        setSprite(n++, W3[0], W3[1], W3[2], 2.5 + 1.2 * g, 2.5 + 1.2 * g, 1.1, cPink, 0.28 * g, 0.6);
        const hotK = Math.max(0, g - 0.55);                                   // a thin horizontal streak while the block is hottest
        setSprite(n++, W3[0], W3[1], W3[2], 3.0 + 8.0 * hotK, 0.15, 1.3, cPink, hotK * 1.5, 0);
      }
      if (chainOn && grow > 0.01) {                                         // a soft glow travels with the arriving chain
        const cx = (DOCK_I0 + 1 - hx) + chState[4]; toWorld(cx, 1 - sink, DOCK_K - hz, cs, sn, W3);
        setSprite(n++, W3[0], W3[1], W3[2], 6.5, 2.6, 1.0, cVio, 0.085 * grow * (1 - 0.8 * sink) * (0.6 + 0.4 * linkK), 0.2);
      }
      if (pFlash > 0.001) {
        toWorld(pcx, pcy, pcz, cs, sn, W3);
        setSprite(n++, W3[0], W3[1], W3[2], 5.5, 5.5, 1.6, cHalo, pFlash * 0.42 * pk2, 0.4);
        setSprite(n++, W3[0], W3[1], W3[2], 5.5 * (0.5 + 0.5 * pFlash), 0.16, 1.8, cInk, pFlash * 0.8 * pk2, 0);
      }
      while (n < NSPR) setSprite(n++, 0, 0, 0, 0, 0, 0, cPink, 0, 0);
      sCAttr.needsUpdate = true; sSAttr.needsUpdate = true; sColAttr.needsUpdate = true;

      /* --- uniforms --- */
      renderer.getDrawingBufferSize(drawSize);
      U.uRes.value.copy(drawSize);
      U.uTime.value = t; U.uDim.value = dim; U.uScanY.value = scanY; U.uScanK.value = scanK; U.uScanDir.value = scanUp ? 1 : -1;
      // legibility mask: desktop = horizontal ramp from the copy's right edge; phone = vertical ramp above the copy
      const w = Math.max(1, S.w), h = Math.max(1, S.h);
      const dA = clamp01((L.textR + 4) / w), dB = clamp01((L.x0 + 0.04 * w) / w);
      const mA = lerp(dA, 0.54, rk), mB = lerp(dB, 0.72, rk);
      const pA2 = clamp01(1 - (L.textT + 0.01 * h) / h), pB2 = clamp01(1 - (L.textT - 0.07 * h) / h);
      if (pk < 0.5) { U.uMask.value.set(1, 0, mA, Math.max(mA + 0.01, mB)); U.uMaskMix.value = 0; }
      else {                                                      // phone: dark below the hero headline; on inner pages dark at the top (page title)
        U.uMask.value.set(0, 1, pA2, Math.max(pA2 + 0.01, pB2)); U.uMask2.value.set(0, -1, -0.66, -0.5); U.uMaskMix.value = smooth(0.15, 0.85, rk);
      }
      U.uMaskMin.value = lerp(0.12, 0.05, pk);
      const bu = blockMat.uniforms;
      const cp = camera.position;
      bu.uCamL.value.set(cp.x * cs - cp.z * sn, cp.y, cp.x * sn + cp.z * cs);
      // world-fixed lights expressed in lattice space: key from the upper right, a rim from behind left
      const kx = 0.72, ky = 0.5, kz = 0.48, rx = -0.82, ry = 0.25, rz = -0.51;
      const kl = 1 / Math.hypot(kx, ky, kz);
      bu.uKey.value.set((kx * cs - kz * sn) * kl, ky * kl, (kx * sn + kz * cs) * kl);
      bu.uRim.value.set(rx * cs - rz * sn, ry, rx * sn + rz * cs);
      bu.uFog.value.set(D - 5, D + 7);
      bu.uNumL.value = nl;
      bu.uDetail.value = clamp01(1 - rk * 1.05);
      bu.uPulseC.value.set(pcx, pcy, pcz, flashR);
      bu.uPulseB.value.set(bandA, bandB, bandI * 0.55 * pk2, pFlash * 0.9 * pk2);
      lineMat.uniforms.uLineW.value = 1.5 * (drawSize.y / Math.max(1, S.h));
      dustMat.uniforms.uPx.value = drawSize.y / (2 * TANF);
      lineMesh.visible = calm > 0.01;
    }
    function disposeConcept() {
      [blockGeo, chainGeo, boxSrc, quadGeo, quadSrc, lineGeo, backGeo, sprGeo, planeSrc, dustGeo].forEach((g) => g.dispose());
      [blockMat, sheetMat, lineMat, backMat, sprMat, dustMat].forEach((m) => m.dispose());
    }
    /* ====================== END CONCEPT ====================== */

    function applyViewOffset() {
      const f = focus();
      camera.setViewOffset(S.w, S.h, -f.x * S.w * 0.5, f.y * S.h * 0.5, S.w, S.h);
    }
    let destroyed = false, lost = false;
    function resize() {
      if (destroyed) return false;
      const w = Math.max(1, canvas.clientWidth || window.innerWidth || 1);
      const h = Math.max(1, canvas.clientHeight || window.innerHeight || 1);
      if (w === S.w && h === S.h) return false;
      S.w = w; S.h = h; S.aspect = w / h; S.wide = S.aspect > 1.05;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      return true;
    }
    function frame(t, dt) {
      const k = 1 - Math.exp(-dt * 3.2);
      S.routeK += ((target.route === 'ambient' ? 1 : 0) - S.routeK) * k;
      S.scrollK += (target.scroll - S.scrollK) * (1 - Math.exp(-dt * 8));
      S.px += (target.px - S.px) * k; S.py += (target.py - S.py) * k;
      S.t = t;
      update(t);
      applyViewOffset();
      renderer.render(scene, camera);
    }
    // One exact frame with the smoothed inputs snapped to their targets (renderAt and the reduced-motion
    // still). With reduced motion, scroll and pointer count as 0 (the site dims the canvas itself).
    function snapFrame(t) {
      if (renderer.getPixelRatio() !== pixelRatio) { renderer.setPixelRatio(pixelRatio); S.w = 0; }
      resize();
      S.routeK = target.route === 'ambient' ? 1 : 0;
      S.scrollK = reduced ? 0 : target.scroll;
      S.px = reduced ? 0 : target.px; S.py = reduced ? 0 : target.py;
      frame(t, 1 / 60);
    }

    // ---- animation loop: at most 60 fps, 30 fps on inner pages or when scrolled past the hero ----
    let raf = 0, running = false, wantRunning = false, t0 = 0, lastT = 0, lastNow = -1, slow = 0, frames = 0;
    function loop(now) {
      if (!running) return;
      raf = requestAnimationFrame(loop);
      const iv = (S.routeK > 0.5 || S.scrollK > 0.9) ? 1000 / 30 : 1000 / 60;
      if (lastNow >= 0) {
        const since = now - lastNow;
        if (since < iv - 2) return;                         // too early for the cap: skip this callback
        lastNow = since < iv * 2 ? lastNow + iv : now;      // stay on the cap's grid
      } else lastNow = now;
      const t = (now - t0) / 1000;                          // time always comes from the clock
      const gap = t - lastT;                                // real time since the last rendered frame
      const dt = Math.min(0.25, Math.max(0.001, gap));
      // adaptive resolution: a frame is slow when it took clearly longer than the current cap's interval
      if (gap > Math.max(0.034, (1.5 * iv) / 1000)) slow++;
      if (++frames >= 90) {
        if (slow > 45 && pixelRatio > 0.75) { pixelRatio = Math.max(0.75, pixelRatio - 0.25); S.w = 0; }
        frames = 0; slow = 0;
      }
      lastT = t;
      // inner pages are a dim backdrop: render them at 75% resolution
      const pr = S.routeK > 0.98 ? Math.max(0.5, pixelRatio * 0.75) : pixelRatio;
      if (pr !== renderer.getPixelRatio()) { renderer.setPixelRatio(pr); S.w = 0; }
      resize();
      frame(t, dt);
    }
    function halt() { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
    function begin() {
      if (running || !wantRunning || reduced || lost || destroyed || document.hidden) return;
      running = true; t0 = performance.now() - S.t * 1000; lastT = S.t; lastNow = -1;
      raf = requestAnimationFrame(loop);
    }

    // ---- reduced motion: no loop, one still (t = 6), re-rendered when the route or the size changes ----
    let stillT = typeof opts.poseTime === 'number' ? opts.poseTime : 6, stillRaf = 0;
    function renderStill() { if (!destroyed && !lost) snapFrame(stillT); }
    function scheduleStill() {
      if (!reduced || destroyed || lost || stillRaf) return;
      stillRaf = requestAnimationFrame(() => { stillRaf = 0; renderStill(); });
    }
    function onWinResize() { if (reduced) scheduleStill(); }
    let ro = null;
    if (reduced && typeof ResizeObserver === 'function') {
      try { ro = new ResizeObserver(() => scheduleStill()); ro.observe(canvas); } catch (e) { ro = null; }
    }

    function onVisibility() { if (document.hidden) halt(); else begin(); }
    let visBeforeLoss = '';
    function onLost(e) {
      e.preventDefault();
      if (!lost) visBeforeLoss = canvas.style.visibility;
      lost = true; halt();
      if (stillRaf) { cancelAnimationFrame(stillRaf); stillRaf = 0; }
      canvas.style.visibility = 'hidden';
    }
    function onRestored() {
      // three.js re-creates its GL state and re-uploads geometry and programs on the next render
      lost = false;
      canvas.style.visibility = visBeforeLoss;
      S.w = 0;
      if (reduced) { scheduleStill(); return; }
      begin();
      if (!running && !destroyed) { resize(); frame(S.t, 0); }  // loop not wanted right now: show the last frame again
    }

    const ctl = {
      start() { if (destroyed) return; wantRunning = true; begin(); },
      stop() { wantRunning = false; halt(); },
      renderAt(t) {
        if (destroyed || lost) return;
        if (reduced) { stillT = t; renderStill(); return; }
        snapFrame(t);
      },
      setRoute(m) {
        const r = m === 'ambient' ? 'ambient' : 'hero';
        if (r === target.route) return;
        target.route = r;
        scheduleStill();
      },
      setScroll(p) { target.scroll = clamp01(+p || 0); },
      setPointer(x, y) { target.px = Math.max(-1, Math.min(1, +x || 0)); target.py = Math.max(-1, Math.min(1, +y || 0)); },
      pulse(at) { if (reduced || destroyed) return; S.pulseAt = typeof at === 'number' && isFinite(at) ? at : S.t; },
      resize() { if (resize()) scheduleStill(); },
      info() { const r = renderer.info.render; return { calls: r.calls, triangles: r.triangles, points: r.points, lines: r.lines }; },
      destroy() {
        if (destroyed) return;
        wantRunning = false; halt();
        if (stillRaf) { cancelAnimationFrame(stillRaf); stillRaf = 0; }
        destroyed = true;
        document.removeEventListener('visibilitychange', onVisibility);
        canvas.removeEventListener('webglcontextlost', onLost, false);
        canvas.removeEventListener('webglcontextrestored', onRestored, false);
        window.removeEventListener('resize', onWinResize);
        if (ro) { ro.disconnect(); ro = null; }
        if (lost) canvas.style.visibility = visBeforeLoss;
        disposeConcept();
        renderer.dispose();
      },
    };
    document.addEventListener('visibilitychange', onVisibility);
    canvas.addEventListener('webglcontextlost', onLost, false);
    canvas.addEventListener('webglcontextrestored', onRestored, false);
    window.addEventListener('resize', onWinResize);

    resize();
    if (reduced) renderStill();
    else ctl.start();
    return ctl;
  }

  window.HyblisScene = { mount: mount, _util: { mulberry32: mulberry32, clamp01: clamp01, smooth: smooth } };
})();
