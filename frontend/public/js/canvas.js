// ── CANVAS BACKGROUND ───────────────────────────────────────
;(()=>{
  const c=document.getElementById('cvs'), ctx=c.getContext('2d'); let pts=[], raf;
  const resize=()=>{ c.width=innerWidth; c.height=innerHeight;
    pts=Array.from({length:45},()=>({x:Math.random()*c.width,y:Math.random()*c.height,
      vx:(Math.random()-.5)*.2,vy:(Math.random()-.5)*.2,r:Math.random()*1.2+.4,a:Math.random()*.4+.1})); };
  const draw=()=>{ const{width:W,height:H}=c; ctx.clearRect(0,0,W,H);
    pts.forEach(p=>{ p.x=(p.x+p.vx+W)%W; p.y=(p.y+p.vy+H)%H;
      ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=`rgba(94,240,200,${p.a*.25})`; ctx.fill(); });
    for(let i=0;i<pts.length;i++) for(let j=i+1;j<pts.length;j++){
      const dx=pts[i].x-pts[j].x, dy=pts[i].y-pts[j].y, d=Math.sqrt(dx*dx+dy*dy);
      if(d<100){ ctx.beginPath(); ctx.moveTo(pts[i].x,pts[i].y); ctx.lineTo(pts[j].x,pts[j].y);
        ctx.strokeStyle=`rgba(94,240,200,${(1-d/100)*.05})`; ctx.lineWidth=1; ctx.stroke(); }}
    raf=requestAnimationFrame(draw); };
  resize(); draw(); window.addEventListener('resize',()=>{ cancelAnimationFrame(raf); resize(); draw(); });
})();
