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
   LIQUID NAV SPOTLIGHT
   A gooey accent blob that highlights the active nav link and
   flows between links like a drop of water — it stretches to
   bridge the old and new link, then pulls in (metaball merge,
   not wavy). The page feeds it the currently-active link.
   ═══════════════════════════════════════════════════════════ */
window.LiquidGlassNav = function (container) {
  if (!container) return null;
  var goo = document.createElement("span");
  goo.className = "lg-nav-goo";
  goo.setAttribute("aria-hidden", "true");
  var blob = document.createElement("span");
  blob.className = "lg-nav-spotlight";
  goo.appendChild(blob);
  container.appendChild(goo);

  var stretchTimer = 0;
  var visible = false;
  var curLeft = 0;
  var curWidth = 0;
  var curTarget = null;

  function setBox(left, width, instant) {
    if (instant) {
      blob.style.transition = "none";
      blob.style.transform = "translateX(" + left + "px)";
      blob.style.width = width + "px";
      void blob.offsetWidth;
      blob.style.transition = "";
    } else {
      /* Phase 1 — stretch to bridge old + new (liquid reaches across) */
      var bL = Math.min(curLeft, left);
      var bR = Math.max(curLeft + curWidth, left + width);
      blob.style.transform = "translateX(" + bL + "px)";
      blob.style.width = bR - bL + "px";
      /* Phase 2 — pull in to the target (drop settles) */
      clearTimeout(stretchTimer);
      stretchTimer = setTimeout(function () {
        blob.style.transform = "translateX(" + left + "px)";
        blob.style.width = width + "px";
      }, 200);
    }
    curLeft = left;
    curWidth = width;
  }

  return {
    /* Highlight a link element (or null to hide the spotlight). */
    place: function (linkEl) {
      if (!linkEl) {
        goo.style.opacity = "0";
        visible = false;
        curTarget = null;
        return;
      }
      /* Pad the highlight a little around the link text — gives
         breathing room and offsets the goo filter's edge erosion. */
      var PADX = 12, PADY = 7;
      var cR = container.getBoundingClientRect();
      var lR = linkEl.getBoundingClientRect();
      var left = lR.left - cR.left - PADX;
      var width = lR.width + PADX * 2;
      blob.style.top = lR.top - cR.top - PADY + "px";
      blob.style.height = lR.height + PADY * 2 + "px";
      if (linkEl === curTarget && visible) {
        /* Same link — the active section hasn't changed, but the nav
           layout may have (e.g. it collapsed into a pill on scroll).
           Keep the highlight locked to the link, snapping instantly
           with no liquid stretch. */
        if (Math.abs(left - curLeft) > 0.5 || Math.abs(width - curWidth) > 0.5) {
          setBox(left, width, true);
        }
        return;
      }
      var instant = !visible;
      goo.style.opacity = "0.32";
      visible = true;
      curTarget = linkEl;
      setBox(left, width, instant);
    },
    /* Snap to the current target without animation (resize/layout). */
    refresh: function () {
      if (!curTarget || !visible) return;
      var PADX = 12, PADY = 7;
      var cR = container.getBoundingClientRect();
      var lR = curTarget.getBoundingClientRect();
      blob.style.top = lR.top - cR.top - PADY + "px";
      blob.style.height = lR.height + PADY * 2 + "px";
      setBox(lR.left - cR.left - PADX, lR.width + PADX * 2, true);
    }
  };
};
