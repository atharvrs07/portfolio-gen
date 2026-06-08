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
