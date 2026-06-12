/* ═══════════════════════════════════════════════════════════
   LIQUID GLASS — SVG refraction filter injector
   Injects displacement-map filters used by backdrop-filter so
   the content BEHIND a glass surface visibly bends at the edges,
   the way Apple's iOS 26 "Liquid Glass" material refracts light.
   ═══════════════════════════════════════════════════════════ */
(function () {
  if (document.getElementById("liquid-glass-defs")) return;

  var SVG_NS = "http://www.w3.org/2000/svg";
  var svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("id", "liquid-glass-defs");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.style.cssText =
    "position:absolute;width:0;height:0;overflow:hidden;pointer-events:none;";

  /* Two strengths:
     #liquid-lens       → larger surfaces (cards, modals, hero)
     #liquid-lens-soft  → small controls (nav pill, toggle, chips)
     fractalNoise at a LOW baseFrequency produces large, smooth
     undulations (thick wavy glass) rather than gritty frost. */
  svg.innerHTML =
    '<defs>' +
      '<filter id="liquid-lens" x="-35%" y="-35%" width="170%" height="170%" ' +
        'color-interpolation-filters="linearRGB">' +
        '<feTurbulence type="fractalNoise" baseFrequency="0.006 0.009" ' +
          'numOctaves="2" seed="14" result="noise"/>' +
        '<feGaussianBlur in="noise" stdDeviation="5" result="noiseBlur"/>' +
        '<feDisplacementMap in="SourceGraphic" in2="noiseBlur" scale="22" ' +
          'xChannelSelector="R" yChannelSelector="G"/>' +
      '</filter>' +
      '<filter id="liquid-lens-soft" x="-35%" y="-35%" width="170%" height="170%" ' +
        'color-interpolation-filters="linearRGB">' +
        '<feTurbulence type="fractalNoise" baseFrequency="0.008 0.011" ' +
          'numOctaves="2" seed="8" result="noise"/>' +
        '<feGaussianBlur in="noise" stdDeviation="3.4" result="noiseBlur"/>' +
        '<feDisplacementMap in="SourceGraphic" in2="noiseBlur" scale="12" ' +
          'xChannelSelector="R" yChannelSelector="G"/>' +
      '</filter>' +
      /* Gooey metaball — blurs then sharpens alpha so nearby shapes
         merge and separate like drops of water (iOS-style fluid
         transitions: "water connecting and leaving"). */
      '<filter id="liquid-goo">' +
        '<feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur"/>' +
        '<feColorMatrix in="blur" mode="matrix" ' +
          'values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 20 -9" result="goo"/>' +
        '<feComposite in="SourceGraphic" in2="goo" operator="atop"/>' +
      '</filter>' +
    '</defs>';

  function inject() {
    (document.body || document.documentElement).appendChild(svg);
  }
  if (document.body) inject();
  else document.addEventListener("DOMContentLoaded", inject);
})();

/* ═══════════════════════════════════════════════════════════
   LIQUID NAV PILL
   A pure Liquid Glass capsule that flows between nav links
   like the iOS Dynamic Island — spring-eased, water-like.

   Design decisions vs. the old gooey blob approach:
   • Single element (no wrapper + blob + goo filter stacking)
   • requestAnimationFrame coalesces rapid scroll calls so the
     pill can never get stuck mid-stretch during fast scrolling
   • Spring cubic-bezier naturally overshoots and settles,
     giving the Dynamic Island "water drop morphing" feel
     without any fragile setTimeout two-phase hack
   ═══════════════════════════════════════════════════════════ */
window.LiquidGlassNav = function (container) {
  if (!container) return null;

  var pill = document.createElement("span");
  pill.className = "lg-nav-pill";
  pill.setAttribute("aria-hidden", "true");
  container.appendChild(pill);

  var visible = false;
  var curTarget = null;
  var rafId = 0;
  var pendingEl = null;
  /* While a deliberate link-switch spring is playing, the pin loop
     must not interrupt it. Matches the 0.46s CSS transform spring. */
  var lockUntil = 0;
  var lastL = 0, lastW = 0, lastT = 0, lastH = 0;

  function measure(linkEl) {
    var PADX = 12, PADY = 6;
    var cR = container.getBoundingClientRect();
    var lR = linkEl.getBoundingClientRect();
    return {
      left:   lR.left   - cR.left - PADX,
      width:  lR.width  + PADX * 2,
      top:    lR.top    - cR.top  - PADY,
      height: lR.height + PADY * 2
    };
  }

  function applyPos(linkEl, instant) {
    var m = measure(linkEl);
    lastL = m.left; lastW = m.width; lastT = m.top; lastH = m.height;

    pill.style.top    = m.top    + "px";
    pill.style.height = m.height + "px";

    if (instant) {
      /* Temporarily suppress transition so the pill snaps to position
         before becoming visible — avoids flying-in from (0,0). */
      var saved = pill.style.transition;
      pill.style.transition = "none";
      pill.style.transform  = "translateX(" + m.left  + "px)";
      pill.style.width      = m.width + "px";
      void pill.offsetWidth; // force reflow
      pill.style.transition = saved;
    } else {
      pill.style.transform = "translateX(" + m.left  + "px)";
      pill.style.width     = m.width + "px";
    }
  }

  /* ── Per-frame pinning ─────────────────────────────────────
     The nav itself animates (it collapses into / expands out of a
     pill on scroll), which moves the links AFTER scroll events stop
     firing. Scroll-driven placement alone leaves the pill stranded.
     This loop re-measures the active link every frame and snaps the
     pill onto it the moment the geometry drifts — so the pill is
     ALWAYS on the right link. The liquid spring is reserved for real
     section switches (guarded by lockUntil). */
  function pin() {
    if (visible && curTarget && performance.now() > lockUntil) {
      var m = measure(curTarget);
      if (Math.abs(m.left - lastL) > 0.5 || Math.abs(m.width  - lastW) > 0.5 ||
          Math.abs(m.top  - lastT) > 0.5 || Math.abs(m.height - lastH) > 0.5) {
        applyPos(curTarget, true);
      }
    }
    requestAnimationFrame(pin);
  }
  requestAnimationFrame(pin);

  return {
    place: function (linkEl) {
      if (!linkEl) {
        pill.style.opacity = "0";
        visible    = false;
        curTarget  = null;
        cancelAnimationFrame(rafId);
        pendingEl  = null;
        return;
      }

      /* Same link → nothing to animate; the pin loop keeps the pill
         glued to it through any nav layout changes. */
      if (linkEl === curTarget && visible) return;

      /* Coalesce rapid calls (e.g. many scroll events per frame)
         into a single paint — prevents the glitch where the pill
         gets stuck in an intermediate stretch during fast scrolling. */
      pendingEl = linkEl;
      cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(function () {
        var el = pendingEl;
        pendingEl = null;
        if (!el) return;

        if (!visible) {
          /* First appearance: snap to position then fade in so the
             pill doesn't animate in from nowhere. */
          applyPos(el, true);
          void pill.offsetWidth; // flush so opacity transition starts fresh
          pill.style.opacity = "1";
          visible = true;
        } else {
          /* Subsequent moves: spring-animated. The bezier naturally
             overshoots transform and width, creating the Dynamic
             Island "water connecting and leaving" morph feel.
             Lock the pin loop out until the spring settles. */
          lockUntil = performance.now() + 520;
          applyPos(el, false);
        }
        curTarget = el;
      });
    },

    refresh: function () {
      cancelAnimationFrame(rafId);
      if (!curTarget || !visible) return;
      applyPos(curTarget, true);
    }
  };
};
