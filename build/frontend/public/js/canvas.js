// ── CANVAS BACKGROUND ───────────────────────────────────────
// Performance notes:
// - Limit redraw rate (30fps) to reduce main-thread load while typing.
// - Avoid Math.sqrt for every pair; compute sqrt only for pairs within the max distance.
// - Pause animation when the tab is hidden.
// - Respect prefers-reduced-motion (draw once, no animation).
;(() => {
  const c = document.getElementById('cvs');
  if (!c) return;
  const ctx = c.getContext('2d');

  const DOT_COUNT = 45;
  const MAX_DIST = 100;
  const MAX_DIST2 = MAX_DIST * MAX_DIST;
  const TARGET_FPS = 30;
  const FRAME_MS = 1000 / TARGET_FPS;

  const reduceMotion = (() => {
    try { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
    catch { return false; }
  })();

  let pts = [];
  let raf = 0;
  let lastTs = 0;

  function resize() {
    c.width = innerWidth;
    c.height = innerHeight;
    pts = Array.from({ length: DOT_COUNT }, () => ({
      x: Math.random() * c.width,
      y: Math.random() * c.height,
      vx: (Math.random() - 0.5) * 0.2,
      vy: (Math.random() - 0.5) * 0.2,
      r: Math.random() * 1.2 + 0.4,
      a: Math.random() * 0.4 + 0.1,
    }));
  }

  function drawFrame() {
    const { width: W, height: H } = c;
    ctx.clearRect(0, 0, W, H);

    // Dots
    for (const p of pts) {
      p.x = (p.x + p.vx + W) % W;
      p.y = (p.y + p.vy + H) % H;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(94,240,200,${p.a * 0.25})`;
      ctx.fill();
    }

    // Links
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        const dx = pts[i].x - pts[j].x;
        const dy = pts[i].y - pts[j].y;
        const d2 = dx * dx + dy * dy;

        // Fast reject without sqrt
        if (d2 >= MAX_DIST2) continue;

        const d = Math.sqrt(d2);
        ctx.beginPath();
        ctx.moveTo(pts[i].x, pts[i].y);
        ctx.lineTo(pts[j].x, pts[j].y);
        ctx.strokeStyle = `rgba(94,240,200,${(1 - d / MAX_DIST) * 0.05})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }
  }

  function tick(ts) {
    // Always keep the RAF running (cheap), but skip rendering when hidden.
    if (document.hidden) {
      raf = requestAnimationFrame(tick);
      return;
    }

    // Reduced motion: draw once and stop.
    if (reduceMotion) {
      drawFrame();
      return;
    }

    // Throttle to TARGET_FPS.
    if (!lastTs) lastTs = ts;
    if (ts - lastTs >= FRAME_MS) {
      lastTs = ts;
      drawFrame();
    }

    raf = requestAnimationFrame(tick);
  }

  resize();
  drawFrame();
  raf = requestAnimationFrame(tick);

  window.addEventListener('resize', () => {
    cancelAnimationFrame(raf);
    lastTs = 0;
    resize();
    drawFrame();
    raf = requestAnimationFrame(tick);
  });
})();
