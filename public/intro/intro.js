/* Scopehaven presentation only. No provider, workbench API, storage or credential access. */
(() => {
  'use strict';
  const policies = {
    isolation: { label:'Data isolation', heading:'The same request.<br>A different boundary.', description:"The actor may read records belonging to their own tenant. Another tenant's records stay outside that scope.", actor:'Tenant A', actorDetail:'Authenticated actor', allowed:['Tenant A record','Within the permitted scope','Expected: access permitted'], forbidden:['Tenant B record','Outside the permitted scope','Expected: access denied'] },
    permissions: { label:'Tool permissions', heading:'The same actor.<br>A different authority.', description:'An actor may use a permitted action. An action requiring higher authority must remain unavailable to that actor.', actor:'Support agent', actorDetail:'Limited tool authority', allowed:['Read ticket','Permitted support action','Expected: action permitted'], forbidden:['Admin action','Requires higher authority','Expected: action denied'] },
    revocation: { label:'Cache revocation', heading:'The same record.<br>A changed permission.', description:'Cached content should respect current access. When access is revoked, the cache must not become a second way to retrieve the record.', actor:'Returning actor', actorDetail:'Current permission applies', allowed:['Access retained','Permission still valid','Expected: access permitted'], forbidden:['Access revoked','Cached copy stays protected','Expected: access denied'] }
  };
  let current = null;
  function mount() {
    if (current) return current;
    const aborter = new AbortController(), signal = aborter.signal;
    const $ = selector => document.querySelector(selector);
    const all = selector => [...document.querySelectorAll(selector)];
    const on = (target,type,handler,options={}) => target.addEventListener(type,handler,{...options,signal});
    const reduced = matchMedia('(prefers-reduced-motion: reduce)');
    const small = matchMedia('(max-width: 720px)');
    const body = document.body, main = $('#main'), header = $('#site-header');
    const ui = $('#intro-ui'), skip = $('#skip-intro'), replay = $('#replay-intro'), motion = $('#motion-toggle'), caption = $('.intro-caption');
    const status = $('#interaction-status'), menu = $('#nav-panel'), menuButtons = [$('#explore-menu'),$('#mobile-menu')];
    let scene = null, introActive = false, paused = reduced.matches, replaying = false, skipRequested = false, forceCut = false, frame = 0;
    let safetyTimer = 0, safetyLeft = 0, safetyFrom = 0, lastIntroFrame = 0, ghostUntil = 0, focusSkip = false, scrollDismiss = false;
    // The intro plays in place on the hero's own backdrop. Its last second crossfades the header,
    // the hero copy and anything below the hero in, driven by the scene clock, so the handoff to the
    // resting page changes nothing on screen. Every time comes from the scene's own timeline
    // (ScopehavenScene.TIMING, in seconds); without the scene there is no intro and nothing reads it.
    const T = window.ScopehavenScene && window.ScopehavenScene.TIMING;
    const hero = $('#hero'), controls = $('.hero-bottom'), revealItems = all('.hero .reveal-in').filter(element => element !== controls);
    const belowItems = all('#main > :not(.hero)'), fadeTargets = [header, controls, ...revealItems, ...belowItems];
    // The veil (styles.css) only exists on screens taller than the hero; elsewhere --intro-veil is never written.
    const tall = matchMedia('(min-width:721px) and (min-height:1101px),(max-width:720px) and (min-height:951px)');
    const unit = n => n < 0 ? 0 : n > 1 ? 1 : n;
    const outCubic = n => { n = 1 - unit(n); return 1 - n * n * n; };
    const smooth = n => { n = unit(n); return n * n * (3 - 2 * n); };
    const onScreen = element => { const r = element.getBoundingClientRect(); return r.bottom > 0 && r.top < innerHeight; };
    const fullyOnScreen = element => { const r = element.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; };
    let fades = [], belowShown = [];
    // Inline styles are written only when their value changes, so the long constant stretches of the
    // reveal (most of the first two seconds) restyle nothing.
    const written = new Map();
    function put(element, prop, value) {
      let last = written.get(element);
      if (!last) written.set(element, last = {});
      if (last[prop] === value) return;
      last[prop] = value;
      if (prop.startsWith('--')) element.style.setProperty(prop, value); else element.style[prop] = value;
    }
    // An element that only fades (no movement) gets its own compositor layer while it is partly
    // transparent, so each step changes a layer's opacity instead of repainting what is under it; at
    // 0 and 1 the hint is dropped again. Elements that also move (the hero copy) are not promoted: a
    // moving layer is drawn from whole-pixel tiles, and dropping it at rest would shift the text by a
    // fraction of a pixel just as it lands.
    function fadeTo(element, opacity) {
      put(element, 'opacity', String(opacity));
      put(element, 'willChange', opacity > 0 && opacity < 1 ? 'opacity' : '');
    }
    // Skip and the Replay/Pause controls crossfade. Focus on Skip moves to Replay halfway through,
    // so it is never left on a control that has faded away.
    function handOverFocus() {
      if (!ui.contains(document.activeElement)) return;
      main.inert = false; header.inert = false;
      replay.focus({preventScroll:true});
    }
    // Once Skip has faded out it leaves the page (hidden and inert), so it can neither catch clicks
    // meant for the header nor hold focus, and the page becomes usable.
    function retireSkip() {
      handOverFocus();
      ui.hidden = true; ui.inert = true; main.inert = false; header.inert = false;
    }
    function paintReveal(t) {
      lastIntroFrame = performance.now();
      // A replay fades the visible page out first instead of cutting it.
      const out = replaying ? 1 - outCubic(t / T.replayFade) : 0;
      const head = outCubic((t - T.header) / T.headerLength);
      put(header, 'opacity', String(Math.max(out, head)));
      put(header, 'transform', `translate(-50%,${head > 0 ? ((head - 1) * 10).toFixed(2) : 0}px)`);
      // The header takes clicks as soon as it is clearly visible, before the intro has fully ended.
      put(header, 'pointerEvents', head > .3 ? 'auto' : '');
      // Opacity and transform only, so the copy never changes layout.
      revealItems.forEach((element, i) => {
        const k = outCubic((t - (T.copy + i * T.copyStagger)) / T.copyLength);
        put(element, 'opacity', String(k > 0 ? k : out));
        put(element, 'transform', k > 0 && k < 1 ? `translate3d(0,${((1 - k) * 16).toFixed(2)}px,0)` : 'none');
      });
      const shown = outCubic((t - T.controls) / T.controlsLength);
      fadeTo(controls, shown > 0 ? shown : out);
      // Only the sections below the hero that are on screen fade; the rest stay hidden by .is-intro
      // until the intro ends, which is invisible because they are off screen.
      const below = outCubic((t - T.below) / T.belowLength);
      belowShown.forEach(element => fadeTo(element, below > 0 ? below : out));
      if (tall.matches) put(hero, '--intro-veil', String(below > 0 ? 1 - below : 1 - out));
      // Skip is fully visible from the first frame of a first visit. A replay brings it in only once
      // the fading header is below 5% opacity, so Skip and the intro label never print over the
      // header, and Skip joins the page (takes focus and clicks) only once it is half visible.
      const arrive = replaying ? smooth((t - T.replayUi) / T.replayUiLength) : 1;
      const leave = 1 - smooth((t - T.ui) / T.uiLength);
      put(ui, 'opacity', String(Math.min(arrive, leave)));
      // The caption leaves earlier than Skip, before the controls arrive where it sits on small screens.
      if (caption) fadeTo(caption, 1 - smooth((t - T.caption) / T.captionLength));
      if (arrive >= .5 && leave >= .5 && ui.inert && !ui.hidden) {
        ui.inert = false;
        if (focusSkip) { focusSkip = false; skip.focus({preventScroll:true}); }
      }
      if (leave < .5) handOverFocus();
      // Skip retires as soon as it is effectively invisible, never while it can still be seen.
      if (leave < .05 && !ui.hidden) retireSkip();
    }
    function clearReveal() {
      fades.forEach(animation => animation.cancel()); fades = [];
      [header, ui, caption, controls, ...revealItems, ...belowItems].forEach(element => {
        if (!element) return;
        element.style.removeProperty('opacity'); element.style.removeProperty('transform'); element.style.removeProperty('will-change');
      });
      header.style.removeProperty('pointer-events'); header.style.removeProperty('transition');
      hero.style.removeProperty('--intro-veil');
      written.clear();
    }
    // A skipped intro brings the copy in from wherever the reveal had reached over about 0.2 s,
    // instead of cutting. Opacity and transform only; paused motion and reduced motion cut directly.
    // Elements off screen are left out: they simply appear, unseen.
    function readReveal() {
      return fadeTargets.filter(onScreen).map(element => [element, +getComputedStyle(element).opacity, element.style.transform]);
    }
    function crossfade(from) {
      // The header's own CSS transition would otherwise take over at its slower pace.
      header.style.transition = 'none';
      const batch = [];
      from.forEach(([element, opacity, transform]) => {
        if (!(opacity < .98)) return;
        const start = { opacity };
        if (transform && transform !== 'none') start.transform = transform;
        batch.push(element.animate([start, { opacity: 1 }], { duration: T.skipFade * 1000, easing: 'cubic-bezier(.4,.1,.3,1)' }));
      });
      fades = batch;
      Promise.all(batch.map(animation => animation.finished)).then(() => {
        if (fades === batch) { fades = []; header.style.removeProperty('transition'); }
      }, () => {});
    }
    let policy = 'isolation', path = 'allowed', chapter = 0, scrollChapter = 0, lastY = 0;
    document.documentElement.classList.add('js');
    function announce(text) { status.textContent = text; }
    // shown: the page is already visible before any intro ran (true), or partly revealed by the
    // styles.css fallback (the readReveal() state it had reached, which then crossfades on instead of jumping).
    function finishIntro(shown) {
      // Focus on the disappearing Skip control, or lost during a replay, returns to Replay.
      const active = document.activeElement, lost = !active || active === body;
      const returnFocus = introActive && (ui.contains(active) || (replaying && lost));
      // A played intro has already revealed the copy, and a page the visitor has already seen must not
      // disappear again, so neither repeats the arrival animation.
      const revealed = shown === true || Array.isArray(shown) || skipRequested || introActive;
      const from = Array.isArray(shown) ? shown : introActive && skipRequested && !forceCut && !paused && !reduced.matches ? readReveal() : null;
      const cut = introActive && !from;
      introActive = false; focusSkip = false; clearTimeout(safetyTimer); safetyTimer = 0; clearReveal(); body.classList.remove('is-intro');
      body.classList.add('intro-done'); body.classList.toggle('skip-reveal',revealed); ui.hidden = true; ui.inert = false; main.inert = false; header.inert = false;
      if (from && T) crossfade(from);
      else if (cut) {
        // Paused motion, a stalled intro or a natural end: the header lands without its CSS transition.
        header.style.transition = 'none'; void getComputedStyle(header).opacity; header.style.removeProperty('transition');
      }
      if (returnFocus) replay.focus({preventScroll:true});
      // A replay scrolled to the top, so on a short or zoomed screen the focused Replay control can sit
      // below the fold. Bring it into view with the smallest scroll, smooth like other page scrolling,
      // unless the visitor ended the intro by scrolling (or touching) and is moving the page themselves.
      if (replaying && !scrollDismiss && document.activeElement === replay && !fullyOnScreen(replay)) replay.scrollIntoView({block:'nearest'});
      replaying = false;
    }
    // The scene's skip reports the end through onIntroEnd, which runs finishIntro once.
    function skipIntro() { if (introActive) { skipRequested = true; scene?.skipIntro(); if (introActive) finishIntro(); } }
    function scrollSkip() { scrollDismiss = true; try { skipIntro(); } finally { scrollDismiss = false; } }
    // Failure recovery must never leave the document inert behind a canvas. The safety timeout spends
    // only time the page is visible: a background tab draws no intro frames, so its intro waits and
    // plays in full once the tab is shown instead of being cut partway through.
    function armSafety() {
      clearTimeout(safetyTimer); safetyTimer = 0;
      if (!introActive || document.hidden) return;
      safetyFrom = performance.now();
      safetyTimer = setTimeout(safetyEnd, safetyLeft);
    }
    function holdSafety() {
      if (!safetyTimer) return;
      clearTimeout(safetyTimer); safetyTimer = 0;
      safetyLeft = Math.max(0, safetyLeft - (performance.now() - safetyFrom));
    }
    function safetyEnd() {
      safetyTimer = 0;
      // Frames still arriving (a slow device): end it like a skip, with the crossfade. Frames
      // stalled: cut straight to the resting page.
      forceCut = performance.now() - lastIntroFrame > 250;
      try { skipIntro(); } finally { forceCut = false; }
    }
    function syncMotion() {
      // Paused motion stops everything: a running skip crossfade jumps to its end state.
      if (paused) fades.forEach(animation => animation.finish());
      body.classList.toggle('motion-paused',paused);
      motion.setAttribute('aria-pressed',String(paused));
      motion.innerHTML = paused ? 'Resume motion <span aria-hidden="true">▶</span>' : 'Pause motion <span aria-hidden="true">Ⅱ</span>';
      replay.disabled = reduced.matches;
      replay.title = reduced.matches ? 'Opening animation is disabled by your reduced-motion preference.' : 'Replay the opening animation';
      scene?.setPaused(paused);
    }
    function startIntro(manual=false) {
      if (!scene || reduced.matches) { finishIntro(); return; }
      closeMenu();
      if (manual) {
        window.scrollTo({top:0,behavior:'instant'});
        // Replay's own return to the hero is not a user scroll dismissal.
        lastY = scrollY;
        paused = false; syncMotion();
      }
      introActive = true; replaying = manual; skipRequested = false;
      clearReveal();
      // A replay's Skip stays inert until it is visible (paintReveal), then takes focus.
      body.classList.remove('intro-done','skip-reveal'); body.classList.add('is-intro'); ui.hidden = false; ui.inert = manual;
      main.inert = true; header.inert = true; focusSkip = manual;
      // A first visit measures the page in its first frame instead (firstFrame), so loading forces no layout.
      belowShown = manual ? belowItems.filter(onScreen) : [];
      scene.startIntro({fromRest:manual});
      safetyLeft = (T.end + T.safety) * 1000; armSafety();
      if (!manual) requestAnimationFrame(firstFrame);
    }
    // The first frame of a first visit, where the browser lays the page out anyway: note the scroll
    // position the intro's scroll dismissal compares against and which sections below the hero are on
    // screen. A page the browser restored to a scroll position goes straight to rest instead.
    function firstFrame() {
      if (!introActive || replaying) return;
      lastY = scrollY;
      if (lastY >= 32) { forceCut = true; try { skipIntro(); } finally { forceCut = false; } return; }
      belowShown = belowItems.filter(onScreen);
    }
    on(skip,'click',skipIntro);
    on(replay,'click',() => startIntro(true));
    on(motion,'click',() => { paused = !paused; syncMotion(); if (paused) skipIntro(); announce(paused ? 'Decorative motion paused.' : 'Decorative motion resumed.'); });
    on(reduced,'change',() => { paused = reduced.matches; if (reduced.matches) skipIntro(); syncMotion(); syncChapters(); queueScroll(); });
    on(document,'visibilitychange',() => { if (document.hidden) holdSafety(); else armSafety(); });
    // These listeners dismiss the entrance; they never prevent or replace scrolling.
    on(window,'wheel',scrollSkip,{passive:true});
    // A tap that dismisses the intro reveals the page under the finger, so the click the browser
    // sends after that tap is swallowed: tapping Skip intro (or the hidden hero) never follows a link
    // or opens the menu underneath. The next touch clears it.
    on(window,'touchstart',event => {
      if (introActive) { ghostUntil = Infinity; scrollSkip(); }
      else if (ghostUntil !== Infinity || event.touches.length < 2) ghostUntil = 0;
    },{passive:true});
    const ghostEnd = () => { if (ghostUntil === Infinity) ghostUntil = performance.now() + 500; };
    on(window,'touchend',ghostEnd,{passive:true});
    on(window,'touchcancel',ghostEnd,{passive:true});
    on(window,'click',event => {
      if (performance.now() >= ghostUntil) return;
      ghostUntil = 0; event.preventDefault(); event.stopPropagation();
    },{capture:true});
    on(document,'keydown',event => {
      if (introActive && ['Escape','Tab','PageDown','PageUp','ArrowDown','ArrowUp','Home','End',' '].includes(event.key)) skipIntro();
      if (event.key === 'Escape' && !menu.hidden) { closeMenu(); menuButtons[small.matches?1:0].focus(); }
    });
    function closeMenu() { menu.hidden = true; menuButtons.forEach(b=>b.setAttribute('aria-expanded','false')); }
    menuButtons.forEach(button => on(button,'click',() => {
      const open = menu.hidden; menu.hidden = !open; menuButtons.forEach(b=>b.setAttribute('aria-expanded',String(open)));
    }));
    on(document,'click',event => { if (!header.contains(event.target)) closeMenu(); });
    on(header,'focusout',event => { if (event.relatedTarget && !header.contains(event.relatedTarget)) closeMenu(); });
    all('a[href^="#"]').forEach(link=>on(link,'click',()=>{skipIntro();closeMenu();}));
    const tabs = all('[data-policy]'), panel = $('#policy-panel');
    function renderPolicy(shouldAnnounce=true) {
      const data = policies[policy], target = data[path];
      tabs.forEach(tab => { const active=tab.dataset.policy===policy; tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1; });
      panel.setAttribute('aria-labelledby',`tab-${policy}`); panel.dataset.path = path;
      $('#policy-category').textContent = data.label.toUpperCase(); $('#policy-heading').innerHTML = data.heading;
      $('#policy-description').textContent=data.description;$('#actor-label').textContent=data.actor;$('#actor-detail').textContent=data.actorDetail;
      $('#resource-label').textContent=target[0];$('#resource-detail').textContent=target[1];$('#expected-text').textContent=target[2];
      $('#expected-symbol').textContent=path==='allowed'?'↗':'⊣';
      all('[data-path-choice]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.pathChoice===path)));
      scene?.setMode(policy);
      if (!paused && !reduced.matches) $('.policy-interaction').animate([{opacity:.25,transform:'translateY(8px)'},{opacity:1,transform:'translateY(0)'}],{duration:330,easing:'cubic-bezier(.2,.7,.2,1)'});
      if (shouldAnnounce) announce(`${data.label}. ${path} path. ${target[2]}. Illustration only; no assessment has run.`);
    }
    tabs.forEach((tab,index) => {
      on(tab,'click',()=>{policy=tab.dataset.policy;renderPolicy();});
      on(tab,'keydown',event=>{
        let next = index;
        if (event.key==='ArrowRight'||event.key==='ArrowDown') next=(index+1)%tabs.length;
        else if(event.key==='ArrowLeft'||event.key==='ArrowUp')next=(index+tabs.length-1)%tabs.length;
        else if(event.key==='Home')next=0;
        else if(event.key==='End')next=tabs.length-1;
        else return;
        event.preventDefault();tabs[next].focus();policy=tabs[next].dataset.policy;renderPolicy();
      });
      on(tab,'pointermove',event=>{if(paused||reduced.matches||event.pointerType!=='mouse')return;const r=tab.getBoundingClientRect();tab.style.setProperty('--px',`${event.clientX-r.left}px`);tab.style.setProperty('--py',`${event.clientY-r.top}px`);});
    });
    all('[data-path-choice]').forEach(button=>on(button,'click',()=>{path=button.dataset.pathChoice;renderPolicy();}));
    const chapterButtons = all('[data-chapter-button]'), chapters=all('[data-chapter-copy]'), sticky=$('#journey-sticky'), track=$('#journey-track');
    function syncChapters() {
      chapters.forEach((element,i)=>{element.classList.toggle('active',chapter===i);element.setAttribute('aria-hidden',String(!small.matches&&chapter!==i));});
      sticky.dataset.chapter=String(chapter);
      chapterButtons.forEach((b,i)=>b.setAttribute('aria-pressed',String(i===chapter)));
    }
    function selectChapter(index,manual=false) {
      chapter=index;syncChapters();
      if(manual)announce(['Define the requirement. Identify permitted and forbidden behaviour.','Inspect the evidence. Compare expected policy with observed backend effects.','Repair and retest. Compare compatible builds and preserve permitted use.'][index]);
    }
    chapterButtons.forEach((button,i)=>on(button,'click',()=>selectChapter(i,true)));
    function updateScroll() {
      frame=0;
      if(introActive && Math.abs(scrollY-lastY)>16) scrollSkip();
      lastY=scrollY;
      if(!paused && !reduced.matches) scene?.setProgress(Math.min(1,Math.max(0,scrollY/innerHeight)));
      if(!small.matches&&!reduced.matches) {
        const rect=track.getBoundingClientRect(), travel=Math.max(1,track.offsetHeight-innerHeight);
        const progress=Math.max(0,Math.min(1,(90-rect.top)/travel));
        const next=Math.min(2,Math.floor(progress*3));
        if(next!==scrollChapter){scrollChapter=next;selectChapter(next);}
      }
    }
    function queueScroll(){if(!frame)frame=requestAnimationFrame(updateScroll);}
    on(window,'scroll',queueScroll,{passive:true});on(window,'resize',queueScroll);
    on(small,'change',()=>{syncChapters();queueScroll();});
    // Canvas is decorative. A renderer failure preserves the complete HTML experience.
    try { scene=new window.ScopehavenScene($('#scene-canvas'),{onIntroEnd:finishIntro,onIntroFrame:paintReveal}); }
    catch { finishIntro();replay.hidden=true;motion.hidden=true; }
    syncMotion();syncChapters();
    // The intro does not start once the visitor has moved focus into the page (styles.css then stops
    // hiding it) or the styles.css fallback has begun to reveal it (about 2.5 s after the first rendered
    // frame, when the scripts are that late): the page goes straight to rest, so nothing already seen or
    // focused disappears again, and a partial reveal finishes as a short crossfade. Only scripts that
    // run that late read the page's state here, so a normal load forces no style or layout work.
    const active=document.activeElement, focused=Boolean(active) && active!==body && active!==document.documentElement;
    const firstPaint=performance.getEntriesByName('first-paint')[0];
    const late=performance.now()-(firstPaint ? firstPaint.startTime : 0)>2000;
    const shown=!focused && late && +getComputedStyle(header).opacity>.02 ? readReveal() : null;
    if(scene && !reduced.matches && !location.hash && !focused && !shown) startIntro(); else finishIntro(shown || focused);
    queueScroll();
    current = { destroy() {
      skipIntro();clearTimeout(safetyTimer);cancelAnimationFrame(frame);aborter.abort();scene?.destroy();clearReveal();
      $('.policy-interaction').getAnimations().forEach(animation=>animation.cancel());
      // The page is left at rest (intro-done, no arrival), so the pre-script hiding in styles.css never returns.
      body.classList.remove('is-intro','motion-paused');body.classList.add('intro-done','skip-reveal');document.documentElement.classList.remove('js');
      ui.hidden=true;ui.inert=false;main.inert=false;header.inert=false;closeMenu();
      tabs.forEach(t=>{t.style.removeProperty('--px');t.style.removeProperty('--py');});
      current=null;
    }, replay:()=>startIntro(true) };
    return current;
  }
  window.ScopehavenIntro={mount,destroy:()=>current?.destroy()};
  mount();
})();
