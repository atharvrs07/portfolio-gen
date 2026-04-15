(() => {
  const doc = document;
  const body = doc.body;

  if (!body) return;

  const supportsHover = window.matchMedia("(hover: hover)").matches;
  const finePointer = window.matchMedia("(pointer: fine)").matches;
  if (!supportsHover || !finePointer) return;

  const prefersReducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
  ).matches;

  const shell = doc.createElement("div");
  shell.className = "ll-site-cursor";
  shell.setAttribute("aria-hidden", "true");
  shell.innerHTML =
    '<span class="ll-site-cursor__ring"></span>' +
    '<span class="ll-site-cursor__ring ll-site-cursor__ring--outer"></span>' +
    '<span class="ll-site-cursor__core"></span>' +
    '<span class="ll-site-cursor__trail"></span>';

  body.appendChild(shell);
  body.classList.add("ll-site-cursor-enabled");
  body.classList.add("ll-site-cursor-loading");
  body.classList.add("ll-cursor-preset-blade");

  let x = window.innerWidth / 2;
  let y = window.innerHeight / 2;
  let tx = x;
  let ty = y;
  let raf = 0;
  const lerp = prefersReducedMotion ? 1 : 0.13;
  const minDelta = 0.065;
  const interactiveSelector =
    "a, button, .btn, input, textarea, select, summary, label[for], [role='button'], [data-cursor='interactive']";

  const isInteractive = (target) =>
    target instanceof Element && Boolean(target.closest(interactiveSelector));

  const getHoverType = (target) => {
    if (!(target instanceof Element)) return "";
    if (target.closest("a[href]")) return "link";
    if (target.closest("button, .btn, summary, [role='button']")) return "button";
    if (target.closest("input, textarea, select")) return "field";
    if (isInteractive(target)) return "interactive";
    return "";
  };

  const clearHoverClasses = () => {
    body.classList.remove("ll-site-cursor-hover");
    body.classList.remove("ll-site-cursor-hover-link");
    body.classList.remove("ll-site-cursor-hover-button");
    body.classList.remove("ll-site-cursor-hover-field");
    body.classList.remove("ll-site-cursor-hover-interactive");
  };

  const render = () => {
    const dx = x - tx;
    const dy = y - ty;

    tx += dx * lerp;
    ty += dy * lerp;
    shell.style.transform = `translate3d(${tx}px, ${ty}px, 0)`;

    if (Math.abs(dx) > minDelta || Math.abs(dy) > minDelta) {
      raf = window.requestAnimationFrame(render);
      return;
    }

    tx = x;
    ty = y;
    shell.style.transform = `translate3d(${tx}px, ${ty}px, 0)`;
    raf = 0;
  };

  const queue = () => {
    if (raf) return;
    raf = window.requestAnimationFrame(render);
  };

  doc.addEventListener(
    "pointermove",
    (event) => {
      x = event.clientX;
      y = event.clientY;
      body.classList.add("ll-site-cursor-visible");
      queue();
    },
    { passive: true }
  );

  doc.addEventListener("pointerleave", () => {
    body.classList.remove("ll-site-cursor-visible");
    clearHoverClasses();
  });

  doc.addEventListener(
    "pointerover",
    (event) => {
      const hoverType = getHoverType(event.target);
      if (!hoverType) return;
      clearHoverClasses();
      body.classList.add("ll-site-cursor-hover");
      body.classList.add(`ll-site-cursor-hover-${hoverType}`);
    },
    { passive: true }
  );

  doc.addEventListener(
    "pointerout",
    (event) => {
      if (!isInteractive(event.target)) return;
      if (isInteractive(event.relatedTarget)) return;
      clearHoverClasses();
    },
    { passive: true }
  );

  doc.addEventListener("pointerdown", () => {
    body.classList.add("ll-site-cursor-press");
    body.classList.add("ll-site-cursor-click");
    window.setTimeout(() => {
      body.classList.remove("ll-site-cursor-click");
    }, 260);
  });

  doc.addEventListener("pointerup", () => {
    body.classList.remove("ll-site-cursor-press");
  });

  doc.addEventListener("visibilitychange", () => {
    if (!doc.hidden || !raf) return;
    window.cancelAnimationFrame(raf);
    raf = 0;
  });

  window.addEventListener(
    "load",
    () => {
      window.setTimeout(() => {
        body.classList.remove("ll-site-cursor-loading");
      }, 420);
    },
    { once: true }
  );
})();

