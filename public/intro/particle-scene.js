(function () {
  'use strict';

  const TAU = Math.PI * 2;
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const ease = n => { n = clamp(n, 0, 1); return n * n * (3 - 2 * n); };
  const easeOut = n => { n = clamp(n, 0, 1); n = 1 - n; return 1 - n * n * n * n; };
  const easeOut3 = n => { n = 1 - clamp(n, 0, 1); return 1 - n * n * n; };
  const easeInOut = n => { n = clamp(n, 0, 1); return n < .5 ? 2 * n * n : 1 - 2 * (1 - n) * (1 - n); };
  const span = (t, start, length) => clamp((t - start) / length, 0, 1);
  const wrap = a => a - TAU * Math.floor((a + Math.PI) / TAU);
  function random(index, salt) {
    let n = Math.imul(index + 1, 374761393) ^ Math.imul(salt + 1, 668265263);
    n = Math.imul(n ^ (n >>> 13), 1274126177);
    return ((n ^ (n >>> 16)) >>> 0) / 4294967296;
  }

  // Intro timeline, in seconds on the scene clock. This is the only copy: intro.js reads it as
  // ScopehavenScene.TIMING for the copy, header and control crossfades, so the page reveal cannot
  // drift from the particles. Every dot reaches its resting place before `end`, so the last intro
  // frame and the first resting frame draw the same field. `end` must stay after every crossfade
  // below and after the last dot lands (unfold + unfoldSpread + unfoldLength).
  const TIMING = Object.freeze({
    end: 3.65,             // hand over to the resting field
    dust: .3,              // waiting dust fades in
    writeStart: .02,       // letters land left to right between writeStart and writeStart + writeSpread
    writeSpread: .58,
    write: .62,            // travel of one dot into the lockup
    sheen: Object.freeze([1.15, 1.85]), // a soft band of light crosses the finished lockup
    unfold: 1.9,           // the word opens like an aperture, middle first; about 1 s after it is complete
    unfoldSpread: .3,      // the outermost dots leave this much later
    unfoldLength: 1,       // travel of one dot from the lockup to the membrane
    clear: .45,            // before the copy, dust still crossing the headline zone fades over this long
    caption: 1.55,         // the intro caption fades out while the lockup holds, so it is gone before
    captionLength: .35,    // the aperture opens and the Replay and Pause controls arrive where it sat
    ui: 2.1,               // Skip intro fades out; once it is below 5% opacity (about 2.45 s) it is
    uiLength: .4,          // hidden and inert, and the page becomes usable
    controls: 2.05,        // Replay and Pause fade in while Skip fades out, so focus can move there
    controlsLength: .5,
    copy: 2.5,             // hero copy, once the headline zone is clear
    copyStagger: .06,
    copyLength: .85,
    header: 2.65,
    headerLength: .8,
    below: 2.8,            // anything below the hero (only visible on tall screens)
    belowLength: .8,
    replayFade: .3,        // a replay fades the visible page out first
    replayUi: .21,         // and brings Skip in only once the header is below 5% opacity
    replayUiLength: .15,
    skipFade: .2,          // a skipped intro crossfades the copy in over this long
    settle: .3,            // and the dots settle into the membrane over this long
    settleFade: .12,       // while their opacity reaches the resting value faster
    safety: 2              // intro.js ends the intro this long after `end`, counting only visible time
  });
  const T = TIMING, INTRO_END = T.end;
  const DRIFT = .35;      // orbit speed of waiting dust, radians per second
  const SWIRL = 1.05;     // inward spiral, radians
  const LAG = .85;        // outward spiral: a dot's letter angle trails its resting angle by about this much
  const AMBIENT = .12;    // share of dots that stay on the membrane as a faint frame
  const OUTLINE = 1.18;   // outline dots sit this much closer together than fill dots, for crisp letters
  const WORD = 'Scopehaven';
  // The Boundary mark (viewBox 0 0 100 100), drawn beside the wordmark like the header brand.
  const MARK_PATH = 'M66 8H18Q8 8 8 18V60Q8 70 18 70H64V56H22V22H66Z M36 30H82Q92 30 92 40V82Q92 92 82 92H34V78H78V44H36Z';

  class ScopehavenScene {
    constructor(canvas, options = {}) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d', { alpha: true });
      if (!this.ctx) throw new Error('Canvas rendering is unavailable');
      this.onIntroEnd = options.onIntroEnd;
      this.onIntroFrame = options.onIntroFrame;
      this.paused = false;
      this.visible = true;
      this.destroyed = false;
      this.intro = false;
      this.introReady = false;
      this.fromRest = false;
      this.completed = false;
      this.elapsed = 0;
      this.clock = 0;
      this.count = 0;
      this.progress = this.progressTarget = 0;
      this.mode = this.modeTarget = 0;
      this.pointerX = this.pointerY = this.pointerTargetX = this.pointerTargetY = 0;
      this.last = 0;
      this.raf = 0;
      this.rX = this.rY = this.rA = this.rB = 0;
      this.parent = canvas.closest('.hero') || canvas.parentElement || canvas;
      this.tick = this.tick.bind(this);
      this.resize = this.resize.bind(this);
      this.handleVisibility = () => { this.last = 0; this.schedule(); };
      this.handlePointer = event => {
        if (this.paused) return;
        const rect = this.canvas.getBoundingClientRect();
        this.pointerTargetX = clamp((event.clientX - rect.left) / rect.width - .5, -.5, .5);
        this.pointerTargetY = clamp((event.clientY - rect.top) / rect.height - .5, -.5, .5);
      };
      this.handleLeave = () => { this.pointerTargetX = this.pointerTargetY = 0; };
      this.parent.addEventListener('pointermove', this.handlePointer, { passive: true });
      this.parent.addEventListener('pointerleave', this.handleLeave);
      document.addEventListener('visibilitychange', this.handleVisibility);
      // A short window can change height without resizing the canvas (the hero has a min-height),
      // which moves the visible band the intro lockup is laid out in. A resized canvas is rebuilt by
      // resize() instead, when the resize observer reports it.
      this.handleWindowResize = () => {
        if (!this.intro || !this.introReady || !this.count) return;
        const rect = this.canvas.getBoundingClientRect();
        if (rect.width !== this.width || rect.height !== this.height) return;
        const band = this.band(rect), last = this.introBand;
        if (Math.abs(band.top - last.top) > 1 || Math.abs(band.height - last.height) > 1) { this.prepareIntro(band); this.render(); }
      };
      window.addEventListener('resize', this.handleWindowResize);
      // The canvas is sized by the observer's first report (after the browser's own first layout)
      // or by the first frame, never while the page scripts run, so loading forces no layout.
      this.resizeObserver = new ResizeObserver(this.resize);
      this.resizeObserver.observe(canvas);
      this.intersectionObserver = new IntersectionObserver(entries => {
        this.visible = entries[0].isIntersecting;
        this.last = 0;
        this.schedule();
      }, { rootMargin: '100px' });
      this.intersectionObserver.observe(canvas);
      this.schedule();
    }

    resize() {
      if (this.destroyed) return;
      const rect = this.canvas.getBoundingClientRect();
      const width = Math.max(1, rect.width), height = Math.max(1, rect.height);
      const mobile = window.matchMedia('(max-width: 720px)').matches;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      // The observer also reports the initial size; an unchanged box keeps the current buffers.
      if (this.count && width === this.width && height === this.height && mobile === this.mobile && dpr === this.dpr) return;
      this.width = width;
      this.height = height;
      this.mobile = mobile;
      this.dpr = dpr;
      this.canvas.width = Math.round(this.width * this.dpr);
      this.canvas.height = Math.round(this.height * this.dpr);
      this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      this.count = this.mobile ? 3000 : 6500;
      const n = this.count;
      this.baseX = new Float32Array(n);
      this.baseY = new Float32Array(n);
      this.light = new Float32Array(n);
      this.drawX = new Float32Array(n);
      this.drawY = new Float32Array(n);
      this.opacity = new Float32Array(n);
      this.size = new Float32Array(n);
      this.bucket = new Uint8Array(n);
      // Intro paths: role 1 dots draw the wordmark, role 0 dots stay on the membrane.
      this.role = new Uint8Array(n);
      this.textX = new Float32Array(n);
      this.textY = new Float32Array(n);
      this.lockA = new Float32Array(n);
      this.lR = new Float32Array(n);
      this.lT = new Float32Array(n);
      this.oR = new Float32Array(n);
      this.oT = new Float32Array(n);
      this.dT = new Float32Array(n);
      this.bend = new Float32Array(n);
      this.oA = new Float32Array(n);
      this.wD = new Float32Array(n);
      this.uD = new Float32Array(n);
      // Where each dot was when an intro was skipped, so the field settles instead of cutting.
      this.fromX = new Float32Array(n);
      this.fromY = new Float32Array(n);
      this.fromA = new Float32Array(n);
      this.fromS = new Float32Array(n);
      this.settling = false;
      this.settleT = 0;
      this.makeGeometry();
      // The wordmark target is only used by the intro. Building it reads back a small canvas,
      // so it is rebuilt lazily when an intro runs instead of on every resize. An intro that has
      // not built it yet does so on its first frame.
      this.wordmarkReady = false;
      if (this.intro && this.introReady) this.prepareIntro(); else this.introReady = false;
      this.render();
      this.schedule();
    }

    // The part of the canvas that is on screen. The hero has a min-height, so on a short or
    // landscape screen it is taller than the window; the intro lockup is centred in this band
    // instead of in the whole canvas. The resting membrane stays hero-relative.
    band(rect = this.canvas.getBoundingClientRect()) {
      const h = this.height, top = rect.top;
      const from = clamp(-top, 0, h), to = clamp(window.innerHeight - top, 0, h);
      return to - from < Math.min(h, 160) ? { top: 0, height: h } : { top: from, height: to - from };
    }

    makeGeometry() {
      for (let i = 0; i < this.count; i++) {
        // Closely spaced contour lanes form an original, fluid dot membrane.
        // There is no assessment data or security status in this geometry.
        this.baseX[i] = random(i, 0) * TAU;
        this.baseY[i] = Math.floor(random(i, 1) * 24) / 23 - .5;
        this.light[i] = random(i, 2);
      }
    }

    // A calm center protects the headline: 0 behind the copy, 1 out at the contour folds.
    quietAt(x, y) {
      const w = this.width, h = this.height;
      const quietX = (x - w * .5) / (w * (this.mobile ? .53 : .45));
      const quietY = (y - h * .48) / (h * (this.mobile ? .29 : .27));
      return ease((Math.sqrt(quietX * quietX + quietY * quietY) - .64) / .62);
    }

    // Resting membrane position and opacity of one dot (writes rX, rY, rA, and rB, the opacity
    // before the calm center is applied, so rA = rB * quietAt(rX, rY)).
    rest(i, slow, centerX, centerY) {
      const w = this.width, h = this.height;
      const light = this.light[i], lane = this.baseY[i];
      const angle = this.baseX[i] + slow;
      const fold = Math.sin(angle * 2 + .45 + slow * .3);
      const spread = lane * (this.mobile ? .13 : .095);
      const radiusX = .54 + spread + Math.sin(angle * 3 + .4) * .045;
      const radiusY = .32 + lane * .055;
      const restX = centerX + w * (Math.cos(angle + fold * .14) * radiusX + Math.sin(angle * 3) * .026);
      const restY = centerY + h * (Math.sin(angle) * radiusY + fold * .09 + Math.cos(angle * 3 + .6) * .028);
      const front = .5 + Math.sin(angle + .5) * .5;
      this.rX = restX;
      this.rY = restY;
      this.rB = (.16 + front * .42) * (.65 + light * .4);
      this.rA = this.rB * this.quietAt(restX, restY);
    }

    // Samples the mark + "Scopehaven" lockup as dust sized to the dot budget: an even outline and
    // a jittered fill, so every letter is crisp at the same density without a visible grid.
    makeWordmark(band) {
      const w = this.width, h = band.height, mobile = this.mobile;
      const family = getComputedStyle(document.documentElement).fontFamily || 'system-ui, sans-serif';
      const probe = document.createElement('canvas').getContext('2d');
      const setFont = (c, px) => {
        c.font = `560 ${px}px ${family}`;
        if (c.font.indexOf('560') !== 0) c.font = `500 ${px}px ${family}`;
        if ('letterSpacing' in c) c.letterSpacing = `${(-.032 * px).toFixed(2)}px`;
      };
      let px = Math.min(mobile ? 66 : 150, h * .17, w / 5.4);
      let markSize = 0, gap = 0, metrics = null, cap = 0, inkW = 0, lockW = 0;
      const measure = () => {
        setFont(probe, px);
        metrics = probe.measureText(WORD);
        const capMetrics = probe.measureText('H');
        cap = capMetrics.actualBoundingBoxAscent || px * .72;
        // Visible mark height is about 1.3 cap heights; the path occupies 84 of its 100 units.
        markSize = cap * 1.3 / .84;
        gap = px * .3;
        inkW = (metrics.actualBoundingBoxLeft || 0) + (metrics.actualBoundingBoxRight || metrics.width);
        lockW = markSize * .84 + gap + inkW;
      };
      measure();
      const maxW = w * (mobile ? .84 : .72);
      if (lockW > maxW) { px *= maxW / lockW; measure(); }
      const ascent = metrics.actualBoundingBoxAscent || cap;
      const descent = metrics.actualBoundingBoxDescent || px * .22;
      const cx = w * .5, cy = band.top + h * .47;
      const left = cx - lockW / 2;
      const baseline = cy + cap / 2;
      const markLeft = left - markSize * .08;
      const markTop = cy - markSize / 2;
      const textX = left + markSize * .84 + gap + (metrics.actualBoundingBoxLeft || 0);
      const pad = 4;
      const boxL = left - pad, boxT = Math.min(markTop + markSize * .08, baseline - ascent) - pad;
      const boxR = left + lockW + pad, boxB = Math.max(markTop + markSize * .92, baseline + descent) + pad;
      const scale = mobile ? 3 : 2;
      const sheet = document.createElement('canvas');
      sheet.width = Math.ceil((boxR - boxL) * scale);
      sheet.height = Math.ceil((boxB - boxT) * scale);
      const ctx = sheet.getContext('2d', { willReadFrequently: true });
      ctx.setTransform(scale, 0, 0, scale, -boxL * scale, -boxT * scale);
      ctx.fillStyle = '#fff';
      try {
        const mark = new Path2D(MARK_PATH);
        ctx.save();
        ctx.translate(markLeft, markTop);
        ctx.scale(markSize / 100, markSize / 100);
        ctx.fill(mark);
        ctx.restore();
      } catch { /* The wordmark alone still reads without the mark. */ }
      setFont(ctx, px);
      ctx.textAlign = 'left';
      ctx.textBaseline = 'alphabetic';
      ctx.fillText(WORD, textX, baseline);
      const SW = sheet.width, SH = sheet.height;
      const data = ctx.getImageData(0, 0, SW, SH).data;
      // Organic dust rather than a lattice: an evenly spaced outline keeps every letter crisp and a
      // jittered grid fills the strokes, so the lockup reads as gathered dust, not LED pixels.
      // Sampling works in sheet pixels; points convert to page pixels at the end.
      const ink = new Uint8Array(SW * SH);
      let area = 0;
      for (let p = 0, k = 3; p < ink.length; p++, k += 4) if (data[k] >= 128) { ink[p] = 1; area++; }
      const inkAt = (x, y) => {
        x = Math.floor(x); y = Math.floor(y);
        return x >= 0 && y >= 0 && x < SW && y < SH && ink[y * SW + x] === 1;
      };
      // Edge pixels: inked with an empty 4-neighbour. The sheet's padding keeps ink off its border.
      const edges = [];
      for (let y = 1; y < SH - 1; y++) {
        for (let x = 1, p = y * SW + 1; x < SW - 1; x++, p++) {
          if (ink[p] && !(ink[p - 1] & ink[p + 1] & ink[p - SW] & ink[p + SW])) edges.push(p);
        }
      }
      const target = Math.max(1, Math.floor(this.count * (1 - AMBIENT)));
      // Fill spacing s and outline spacing s / OUTLINE share the dot budget:
      // area / s^2 + OUTLINE * perimeter / s = target.
      const perim = Math.max(1, edges.length), inkArea = Math.max(1, area);
      const z = (Math.sqrt(OUTLINE * OUTLINE * perim * perim + 4 * inkArea * target) - OUTLINE * perim) / (2 * inkArea);
      const s = 1 / z;
      const edgeN = Math.min(edges.length, Math.round(OUTLINE * perim * z));
      const xs = [], ys = [], edge = [];
      // Outline: shuffled dart throwing with a minimum gap (a small Poisson-disc pass along the edge).
      const minGap = s / OUTLINE * .72, cell = minGap / Math.SQRT2;
      const gw = Math.ceil(SW / cell) + 1, gh = Math.ceil(SH / cell) + 1;
      const grid = new Int32Array(gw * gh).fill(-1);
      const order = Uint32Array.from(edges);
      for (let k = order.length - 1; k > 0; k--) {
        const j = Math.floor(random(k, 33) * (k + 1)), swap = order[k];
        order[k] = order[j]; order[j] = swap;
      }
      for (let o = 0; o < order.length && xs.length < edgeN; o++) {
        const x = order[o] % SW + .5, y = Math.floor(order[o] / SW) + .5;
        const gx = Math.floor(x / cell), gy = Math.floor(y / cell);
        let ok = true;
        for (let yy = Math.max(0, gy - 2); ok && yy <= Math.min(gh - 1, gy + 2); yy++) {
          for (let xx = Math.max(0, gx - 2); xx <= Math.min(gw - 1, gx + 2); xx++) {
            const q = grid[yy * gw + xx];
            if (q >= 0 && (xs[q] - x) * (xs[q] - x) + (ys[q] - y) * (ys[q] - y) < minGap * minGap) { ok = false; break; }
          }
        }
        if (ok) { grid[gy * gw + gx] = xs.length; xs.push(x); ys.push(y); edge.push(1); }
      }
      // Interior: one jittered sample per grid cell, kept a little inside the outline, at the
      // spacing that uses the rest of the budget.
      const fillN = target - xs.length;
      let fx = [], fy = [], step = s;
      const fill = size => {
        fx = []; fy = [];
        const d = size * .42;
        for (let gy = 0; gy * size < SH; gy++) {
          for (let gx = 0; gx * size < SW; gx++) {
            const id = gy * 4099 + gx;
            const x = (gx + .5 + (random(id, 41) - .5) * .8) * size, y = (gy + .5 + (random(id, 42) - .5) * .8) * size;
            if (inkAt(x, y) && inkAt(x - d, y) && inkAt(x + d, y) && inkAt(x, y - d) && inkAt(x, y + d)) { fx.push(x); fy.push(y); }
          }
        }
      };
      for (let attempt = 0; attempt < 6 && fillN > 0; attempt++) {
        fill(step);
        const ratio = fx.length / fillN;
        if (ratio >= 1 && ratio < 1.05) break;
        step *= Math.sqrt(Math.max(ratio, .05)) * (ratio < 1 ? .99 : 1);
      }
      // Trim the surplus at random; very thin strokes top up with random inked spots.
      while (fx.length > Math.max(0, fillN)) {
        const p = Math.floor(random(fx.length, 43) * fx.length), last = fx.length - 1;
        fx[p] = fx[last]; fy[p] = fy[last]; fx.length = fy.length = last;
      }
      for (let k = 0; fx.length < fillN && k < fillN * 40; k++) {
        const x = random(k, 44) * SW, y = random(k, 45) * SH;
        if (inkAt(x, y)) { fx.push(x); fy.push(y); }
      }
      for (let p = 0; p < fx.length; p++) { xs.push(fx[p]); ys.push(fy[p]); edge.push(0); }
      const total = xs.length;
      const px2 = new Float32Array(total), py2 = new Float32Array(total);
      for (let p = 0; p < total; p++) { px2[p] = boxL + xs[p] / scale; py2[p] = boxT + ys[p] / scale; }
      this.points = { x: px2, y: py2, edge: Uint8Array.from(edge), length: total };
      this.lockup = { cx, cy, halfW: lockW / 2, halfH: Math.max(1, (boxB - boxT) / 2 - pad), left };
      this.lockSize = clamp(step / scale * .56, .8, 1.6);
      this.wordBand = band;
      this.wordmarkReady = true;
    }

    // Assigns wordmark points to dots and builds each dot's inward and outward spiral. The spirals
    // turn about the visible band (on a tall enough screen, the whole canvas), like the lockup.
    prepareIntro(band = this.band()) {
      const last = this.wordBand;
      if (!this.wordmarkReady || band.top !== last.top || band.height !== last.height) this.makeWordmark(band);
      this.introBand = band;
      const n = this.count, w = this.width, h = this.height;
      // render() turns every intro spiral about this same ellipse.
      const ox = w * .5, oy = band.top + band.height * .48, rx = w * .54, ry = band.height * .32;
      this.frame = { ox, oy, rx, ry };
      const slow = this.clock * .025 + this.mode * .045;
      const centerX = w * .5 + this.pointerX * 10;
      const centerY = h * (.48 + this.progress * .008) + this.pointerY * 8;
      const pts = this.points, L = this.lockup;
      const lock = [], key = new Float32Array(n), restR = new Float32Array(n), restT = new Float32Array(n), restA = new Float32Array(n);
      for (let i = 0; i < n; i++) {
        this.rest(i, slow, centerX, centerY);
        const u = (this.rX - ox) / rx, v = (this.rY - oy) / ry;
        restR[i] = Math.sqrt(u * u + v * v);
        restT[i] = Math.atan2(v, u);
        restA[i] = this.rA;
        key[i] = wrap(restT[i] - LAG);
        this.role[i] = 0;
        if (random(i, 9) >= AMBIENT && lock.length < pts.length) lock.push(i);
      }
      // Points sorted by angle around the lockup, dots by resting angle: each dot leaves its
      // letter toward its own stretch of the membrane, so the unfold reads as one spiral.
      const used = lock.length;
      const order = [];
      for (let p = 0; p < pts.length; p++) order.push(p);
      if (used < pts.length) {
        // More points than dots (only on tiny screens): drop points evenly in a shuffled order.
        order.sort((a, b) => random(a, 21) - random(b, 21));
        order.length = used;
      }
      const angle = new Float32Array(pts.length);
      for (const p of order) angle[p] = Math.atan2((pts.y[p] - L.cy) / L.halfH, (pts.x[p] - L.cx) / L.halfW);
      order.sort((a, b) => angle[a] - angle[b]);
      lock.sort((a, b) => key[a] - key[b]);
      for (let k = 0; k < used; k++) {
        const i = lock[k], p = order[k];
        const x = pts.x[p], y = pts.y[p];
        const u = (x - ox) / rx, v = (y - oy) / ry;
        const xn = clamp((x - L.left) / (L.halfW * 2), 0, 1);
        this.role[i] = 1;
        this.textX[i] = x;
        this.textY[i] = y;
        this.lR[i] = Math.sqrt(u * u + v * v);
        this.lT[i] = Math.atan2(v, u);
        this.lockA[i] = pts.edge[p] ? .98 : .73 + this.light[i] * .08;
        // Letters land left to right. The unfold opens from the middle of the word outward, and dots
        // whose path heads up through the eyebrow and headline leave a little before those heading down.
        const heading = this.lT[i] + wrap(restT[i] - this.lT[i]) * .5;
        this.wD[i] = T.writeStart + xn * T.writeSpread + random(i, 12) * .08;
        this.uD[i] = T.unfold + T.unfoldSpread * (Math.abs(x - L.cx) / L.halfW * .6 + (1 + Math.sin(heading)) * .125 + random(i, 13) * .15);
        if (this.fromRest) {
          // Replays gather the visible membrane into the wordmark instead of cutting it.
          this.oR[i] = restR[i];
          this.oT[i] = restT[i];
          this.dT[i] = wrap(this.lT[i] - restT[i]);
          this.bend[i] = -.35;
          this.oA[i] = restA[i];
        } else {
          // First visits draw dust in from beyond the membrane on an inward spiral.
          this.oR[i] = 1.06 + random(i, 14) * .5;
          this.dT[i] = SWIRL + random(i, 15) * .45;
          this.oT[i] = this.lT[i] - this.dT[i];
          this.bend[i] = 0;
          this.oA[i] = 0;
        }
      }
      this.introReady = true;
    }

    startIntro(options = {}) {
      if (this.destroyed) return;
      this.fromRest = Boolean(options.fromRest);
      this.intro = true;
      this.completed = false;
      this.settling = false;
      this.elapsed = 0;
      this.last = 0;
      // The lockup and the spirals are built on the intro's first frame, not here, so starting the
      // intro while the page loads stays cheap. Until then the canvas shows what the intro's opening
      // frame shows: nothing on a first visit, the resting field on a replay.
      this.introReady = false;
      this.emitFrame();
      this.render();
      this.schedule();
    }

    emitFrame() {
      if (this.intro && typeof this.onIntroFrame === 'function') this.onIntroFrame(this.elapsed);
    }

    finishIntro() {
      this.intro = false;
      this.elapsed = INTRO_END;
      if (!this.completed) {
        this.completed = true;
        if (typeof this.onIntroEnd === 'function') this.onIntroEnd();
      }
    }

    skipIntro() {
      if (this.destroyed) return;
      // A skipped intro lets the dots settle into the membrane quickly instead of cutting, but only
      // while frames are actually running; paused, hidden or stalled scenes go straight to rest.
      if (this.intro && this.introReady && this.last && !this.paused && !document.hidden && this.visible) {
        this.fromX.set(this.drawX);
        this.fromY.set(this.drawY);
        this.fromA.set(this.opacity);
        this.fromS.set(this.size);
        this.settling = true;
        this.settleT = 0;
      }
      this.finishIntro();
      this.render();
      this.schedule();
    }

    setPaused(value) {
      this.paused = Boolean(value);
      this.last = 0;
      if (this.paused) {
        this.settling = false;
        this.pointerX = this.pointerY = this.pointerTargetX = this.pointerTargetY = 0;
        this.mode = this.modeTarget;
        this.progress = this.progressTarget;
        cancelAnimationFrame(this.raf);
        this.raf = 0;
        this.render();
      } else this.schedule();
    }

    setMode(value) {
      const modes = { isolation: 0, permissions: 1, revocation: 2 };
      if (!Object.prototype.hasOwnProperty.call(modes, value)) return;
      this.modeTarget = modes[value];
      if (this.paused) { this.mode = this.modeTarget; this.render(); }
      this.schedule();
    }

    setProgress(value) {
      if (!Number.isFinite(value)) return;
      this.progressTarget = clamp(value, 0, 1);
      if (this.paused) { this.progress = this.progressTarget; this.render(); }
      this.schedule();
    }

    schedule() {
      if (this.destroyed || this.paused || document.hidden || !this.visible) {
        if (this.raf) cancelAnimationFrame(this.raf);
        this.raf = 0;
        this.settling = false;
        return;
      }
      if (!this.raf) this.raf = requestAnimationFrame(this.tick);
    }

    tick(time) {
      this.raf = 0;
      if (this.destroyed || this.paused || document.hidden || !this.visible) return;
      // Normally the resize observer has sized the canvas by now; inside a frame this costs no extra layout.
      if (!this.count) { this.resize(); return; }
      // After the intro the field only drifts slowly, so about 30 fps is enough.
      if (!this.intro && !this.settling && this.last && time - this.last < 30) { this.schedule(); return; }
      const dt = this.last ? Math.min((time - this.last) / 1000, .05) : 0;
      this.last = time;
      if (this.intro && !this.introReady) this.prepareIntro();
      this.clock += dt;
      const smooth = 1 - Math.exp(-dt * 5);
      this.mode += (this.modeTarget - this.mode) * smooth;
      this.progress += (this.progressTarget - this.progress) * smooth;
      this.pointerX += (this.pointerTargetX - this.pointerX) * smooth;
      this.pointerY += (this.pointerTargetY - this.pointerY) * smooth;
      if (this.intro) {
        this.elapsed += dt;
        if (this.elapsed >= INTRO_END) this.finishIntro();
        else this.emitFrame();
      }
      if (this.settling) {
        this.settleT += dt;
        if (this.settleT >= T.settle) this.settling = false;
      }
      this.render();
      this.schedule();
    }

    render() {
      if (!this.ctx || this.destroyed) return;
      const ctx = this.ctx, w = this.width, h = this.height, n = this.count;
      ctx.clearRect(0, 0, w, h);
      const slow = this.clock * .025 + this.mode * .045;
      const centerX = w * .5 + this.pointerX * 10;
      const centerY = h * (.48 + this.progress * .008) + this.pointerY * 8;
      const intro = this.intro && this.introReady, e = this.elapsed, dpr = this.dpr;
      // Until an intro's first frame has built its lockup, a first visit shows what its opening frame
      // shows (no dust yet) and a replay shows the resting field it starts from.
      if (this.intro && !intro && !this.fromRest) return;
      const { ox, oy, rx, ry } = intro ? this.frame : { ox: 0, oy: 0, rx: 1, ry: 1 };
      const restSize = this.mobile ? .95 : 1.1, lockSize = this.lockSize || restSize;
      const settle = this.settling ? ease(this.settleT / T.settle) : 1;
      const fade = this.settling ? easeOut3(this.settleT / T.settleFade) : 1;
      let ambient = 1, dust = 0, sheen = 0, sheenX = 0, band = 1, clear = 0;
      const L = this.lockup;
      if (intro) {
        const early = ease(span(e, 0, .45)), late = ease(span(e, T.unfold + .25, 1.1));
        ambient = late >= 1 ? 1 : this.fromRest ? 1 - ease(span(e, 0, .5)) * .55 + late * .55 : early * .45 + late * .55;
        // First visits show the waiting dust at once, so the opening frame is never empty.
        dust = this.fromRest ? 0 : .3 * ease(e / T.dust);
        // While the lockup holds, one soft diagonal band of light crosses it from left to right.
        const sp = span(e, T.sheen[0], T.sheen[1] - T.sheen[0]);
        if (sp > 0 && sp < 1) {
          sheen = .34;
          band = L.halfW * .19;
          sheenX = L.left - band * 2 + (L.halfW * 2 + band * 4) * ease(sp);
        }
        // Just before the copy arrives, dust still crossing the headline zone fades out.
        clear = ease(span(e, T.copy - T.clear, T.clear));
      }
      for (let i = 0; i < n; i++) {
        this.rest(i, slow, centerX, centerY);
        let x = this.rX, y = this.rY, alpha = this.rA, size = i % 31 === 0 ? 1.65 : restSize;
        if (intro) {
          if (!this.role[i]) alpha *= ambient;
          else if (e < this.uD[i]) {
            // Inward spiral into the letter, then a short glint as the dot lands.
            const wp = span(e, this.wD[i], T.write);
            if (wp >= 1) {
              x = Math.round(this.textX[i] * dpr) / dpr;
              y = Math.round(this.textY[i] * dpr) / dpr;
            } else {
              const k = easeOut(wp);
              const r = this.oR[i] + (this.lR[i] - this.oR[i]) * k;
              const wait = this.fromRest ? 0 : Math.max(0, this.wD[i] - e) * DRIFT;
              const th = this.oT[i] - wait + this.dT[i] * k + this.bend[i] * Math.sin(Math.PI * k);
              x = ox + rx * r * Math.cos(th);
              y = oy + ry * r * Math.sin(th);
            }
            const shown = ease(wp * 1.7);
            const landed = e - this.wD[i] - T.write * .45;
            const from = this.fromRest ? this.oA[i] : dust * (.5 + this.light[i] * .5);
            alpha = from * (1 - shown) + this.lockA[i] * shown + (landed > 0 ? .5 * Math.exp(-landed * 5) : 0);
            size = lockSize;
            if (sheen) {
              const q = (this.textX[i] - sheenX + (this.textY[i] - L.cy) * .45) / band, glow = Math.exp(-q * q) * shown;
              alpha += sheen * glow;
              size = lockSize * (1 + .2 * glow);
            }
          } else {
            // Outward spiral from the letter to the live resting position. The radius opens early, so
            // the aperture empties the middle first; the angle turns later, curling dots into the membrane.
            const p = span(e, this.uD[i], T.unfoldLength);
            if (p < 1) {
              const ux = (x - ox) / rx, uy = (y - oy) / ry;
              const r1 = Math.sqrt(ux * ux + uy * uy), t1 = Math.atan2(uy, ux);
              const lr = this.lR[i], lt = this.lT[i], q = 1 - p;
              const open = 1 - q * q * q * q * (1 + 4 * p), turn = easeInOut(p);
              const r = lr + (r1 - lr) * open, th = lt + wrap(t1 - lt) * turn;
              x = ox + rx * r * Math.cos(th);
              y = oy + ry * r * Math.sin(th);
              // Opacity hands over on time, a little ahead of the position, so letters clear quickly.
              // The resting opacity is taken before the calm center and the center is applied where the
              // dot is now, so a dot ends exactly at its resting opacity, and as the copy nears, dust
              // still crossing the headline fades instead of cluttering it.
              const f = ease(span(e, this.uD[i], T.unfoldLength * .8));
              alpha = (this.lockA[i] * (1 - f) + this.rB * f) * (1 - Math.max(clear, f * f) * (1 - this.quietAt(x, y)));
              size = lockSize + (size - lockSize) * open;
            }
          }
        } else if (settle < 1) {
          // A skipped intro: each dot eases from where it was to its resting place. Its opacity gets
          // there sooner, and the calm centre is applied in full from the first settle frame, where the
          // dot is now, so the lockup clears the headline zone at once and its dots never ghost or
          // streak across the copy that is fading in. At the end this is exactly the resting opacity,
          // rA = rB * quietAt(rest).
          x = this.fromX[i] + (x - this.fromX[i]) * settle;
          y = this.fromY[i] + (y - this.fromY[i]) * settle;
          alpha = (this.fromA[i] + (this.rB - this.fromA[i]) * fade) * this.quietAt(x, y);
          size = this.fromS[i] + (size - this.fromS[i]) * settle;
        }
        this.drawX[i] = x;
        this.drawY[i] = y;
        this.size[i] = size;
        alpha = clamp(alpha, 0, .98);
        this.opacity[i] = alpha;
        this.bucket[i] = alpha < .025 ? 255 : Math.min(6, Math.floor(alpha * 7));
      }
      // Quantized silver batches keep the bounded 6500/3000-dot budget cheap.
      for (let bucket = 0; bucket < 7; bucket++) {
        ctx.fillStyle = `rgba(220,226,233,${(bucket + .65) / 7})`;
        ctx.beginPath();
        for (let i = 0; i < n; i++) {
          if (this.bucket[i] !== bucket) continue;
          const s = this.size[i];
          ctx.rect(this.drawX[i], this.drawY[i], s, s);
        }
        ctx.fill();
      }
    }

    destroy() {
      if (this.destroyed) return;
      this.destroyed = true;
      cancelAnimationFrame(this.raf);
      this.resizeObserver.disconnect();
      this.intersectionObserver.disconnect();
      this.parent.removeEventListener('pointermove', this.handlePointer);
      this.parent.removeEventListener('pointerleave', this.handleLeave);
      document.removeEventListener('visibilitychange', this.handleVisibility);
      window.removeEventListener('resize', this.handleWindowResize);
      this.ctx.clearRect(0, 0, this.width, this.height);
    }
  }

  // The intro timeline is shared with intro.js, which paces the page reveal from it.
  ScopehavenScene.TIMING = TIMING;
  window.ScopehavenScene = ScopehavenScene;
})();
