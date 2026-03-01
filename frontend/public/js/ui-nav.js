// ── HEALTH CHECK ─────────────────────────────────────────────
async function checkHealth(){
  try{
    const r=await fetch('/api/health'); const d=await r.json();
    document.getElementById('trivyDot').className='sdot '+(d.trivy?'ok':'err');
  }catch{ document.getElementById('trivyDot').className='sdot err'; }
}
checkHealth(); setInterval(checkHealth,20000);

// ── SHARED HELPERS ────────────────────────────────────────────
// Full radar (lib + dep empty states) — structure mirrors osa_hunter_no_text.html
function _emptyRadar(){
  return`
  <div class="er-stage">
    <div class="er-rings-rotate">
      <div class="er-ring er-lg"></div>
      <div class="er-ring er-md"></div>
      <div class="er-ring er-sm"></div>
    </div>
    <div class="er-blip er-b1"></div>
    <div class="er-blip er-b2"></div>
    <div class="er-blip er-b3"></div>
    <div class="er-sweep-mask">
      <div class="er-rotor" id="erRotor">
        <div class="er-beamglow"></div>
        <div class="er-needle"></div>
      </div>
    </div>
    <div class="er-crosshair"></div>
    <div class="er-frame"></div>
    <div class="er-wasp-wrap">
      <img class="er-wasp" src="assets/osa.png" alt=""/>
    </div>
  </div>`;
}

// ── NAVIGATION ────────────────────────────────────────────────
function navTo(page, opts={}){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+page).classList.add('active');

  const isLib=page.startsWith('lib');
  const isDep=page.startsWith('dep');
  const isImg=page.startsWith('img');
  const isOs =page.startsWith('os');
  const isGh =page.startsWith('gh');
  document.getElementById('nav-lib').classList.toggle('active',isLib);
  document.getElementById('nav-dep').classList.toggle('active',isDep);
  document.getElementById('nav-img').classList.toggle('active',isImg);
  document.getElementById('nav-os')?.classList.toggle('active',isOs);
  document.getElementById('nav-gh')?.classList.toggle('active',isGh);

  const tl=document.getElementById('topbarLeft');
  const ta=document.getElementById('topbarActions');

  if(page==='lib-list'){
    tl.innerHTML=`<span style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;color:#fff">Library Scan</span>`;
    ta.innerHTML=`<button class="btn-primary" onclick="openLibModal()">+ Add library</button>`;
    renderLibList();

  }else if(page==='lib-detail'){
    const s=opts.scan;
    tl.innerHTML=`
      <button class="back-btn" onclick="navTo('lib-list')">← Back</button>
      <div class="breadcrumb">
        <span class="bc-root" onclick="navTo('lib-list')">Library Scan</span>
        <span class="bc-sep">/</span>
        <span class="bc-current">${esc(s.pkg)}${s.ver?' @ v'+esc(s.ver):''}</span>
      </div>`;
    ta.innerHTML='';
    renderLibDetail(s);

  }else if(page==='dep-list'){
    tl.innerHTML=`<span style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;color:#fff">Dependency Scan</span>`;
    ta.innerHTML=`<button class="btn-primary" style="background:#a78bfa" onclick="openDepModal()">+ Add scan</button>`;
    renderDepList();

  }else if(page==='dep-detail'){
    const s=opts.scan;
    tl.innerHTML=`
      <button class="back-btn" onclick="navTo('dep-list')">← Back</button>
      <div class="breadcrumb">
        <span class="bc-root" onclick="navTo('dep-list')">Dependency Scan</span>
        <span class="bc-sep">/</span>
        <span class="bc-current">${esc(s.package)}${s.resolvedVersion?' @ v'+esc(s.resolvedVersion):''}</span>
      </div>`;
    ta.innerHTML='';
    renderDepDetail(s);

  }else if(page==='dep-pkg'){
    const {dep,scan}=opts;
    tl.innerHTML=`
      <button class="back-btn" onclick="navTo('dep-detail',{scan:currentDepScan})">← Back</button>
      <div class="breadcrumb">
        <span class="bc-root" onclick="navTo('dep-list')">Dependency Scan</span>
        <span class="bc-sep">/</span>
        <span class="bc-root" onclick="navTo('dep-detail',{scan:currentDepScan})" style="cursor:pointer">${esc(currentDepScan?.package||scan?.package||'')}</span>
        <span class="bc-sep">/</span>
        <span class="bc-current">${esc(dep.name)}</span>
      </div>`;
    ta.innerHTML='';
    renderDepPkg(dep, scan);

  }else if(page==='img-form'){
    tl.innerHTML=`<span style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;color:#fff">Image Scan</span>`;
    ta.innerHTML=imgScans.length?`<button class="btn-secondary" onclick="navTo('img-list')">← Back to results</button>`:'';

  }else if(page==='img-list'){
    tl.innerHTML=`<span style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;color:#fff">Image Scan</span>`;
    ta.innerHTML=`<button class="btn-primary blue-btn" onclick="navTo('img-form')">+ New scan</button>`;
    renderImgList();

  }else if(page==='img-detail'){
    const s=opts.scan;
    tl.innerHTML=`
      <button class="back-btn" onclick="navTo('img-list')">← Back</button>
      <div class="breadcrumb">
        <span class="bc-root" onclick="navTo('img-list')">Image Scan</span>
        <span class="bc-sep">/</span>
        <span class="bc-current">${esc(s.image)}:${esc(s.tag)}</span>
      </div>`;
    ta.innerHTML='';
    renderImgDetail(s);

  }else if(page==='os-list'){
    tl.innerHTML=`<span style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;color:#fff">OS Packages</span>`;
    ta.innerHTML=`<button class="btn-primary" style="background:#f97316" onclick="openOsModal()">+ Add scan</button>`;
    renderOsList();

  }else if(page==='os-detail'){
    const s=opts.scan;
    tl.innerHTML=`
      <button class="back-btn" onclick="navTo('os-list')">← Back</button>
      <div class="breadcrumb">
        <span class="bc-root" onclick="navTo('os-list')">OS Packages</span>
        <span class="bc-sep">/</span>
        <span class="bc-current">${esc(s.name)} ${esc(s.version||'')}</span>
      </div>`;
    ta.innerHTML='';
    renderOsDetail(s);

  }else if(page==='gh-form'){
    tl.innerHTML=`<span style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;color:#fff">GitHub Scan</span>`;
    ta.innerHTML=ghScans.length?`<button class="btn-secondary" onclick="navTo('gh-list')">← Back to results</button>`:'';

  }else if(page==='gh-list'){
    tl.innerHTML=`<span style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;color:#fff">GitHub Scan</span>`;
    ta.innerHTML=`<button class="btn-primary" style="background:#a78bfa;color:#07090f" onclick="navTo('gh-form')">+ New scan</button>`;
    renderGhList();

  }else if(page==='gh-detail'){
    const s=opts.scan;
    tl.innerHTML=`
      <button class="back-btn" onclick="navTo('gh-list')">← Back</button>
      <div class="breadcrumb">
        <span class="bc-root" onclick="navTo('gh-list')">GitHub Scan</span>
        <span class="bc-sep">/</span>
        <span class="bc-current">${esc(s.repo)}</span>
      </div>`;
    ta.innerHTML='';
    renderGhDetail(s);
  }
}

// ── RADAR BLIP HIT (empty state) ─────────────────────────────
function _initEmptyRadar(){
  const rotor=document.getElementById('erRotor');
  const stage=document.querySelector('.er-stage');
  if(!rotor||!stage)return;
  const blips=Array.from(stage.querySelectorAll('.er-blip'));
  function angle(){
    const t=getComputedStyle(rotor).transform;
    if(!t||t==='none')return 0;
    const m=t.match(/matrix\(([^)]+)\)/);
    if(!m)return 0;
    const p=m[1].split(',').map(Number);
    let deg=Math.atan2(p[1],p[0])*180/Math.PI;
    deg=(deg+360)%360;
    return(360-deg)%360;
  }
  function calcAngles(){
    const r=stage.getBoundingClientRect();
    const cx=r.left+r.width/2,cy=r.top+r.height/2;
    blips.forEach(b=>{
      const br=b.getBoundingClientRect();
      let ang=Math.atan2(br.top+br.height/2-cy,br.left+br.width/2-cx)*180/Math.PI;
      b.dataset.angle=String((360+(360-ang))%360);
    });
  }
  const hitUntil=new Map();const THR=6,HOLD=180;
  function tick(){
    const now=performance.now(),a=angle();
    blips.forEach(b=>{
      const diff=Math.abs(((a-parseFloat(b.dataset.angle||0)+540)%360)-180);
      if(diff<=THR){hitUntil.set(b,now+HOLD);b.classList.add('hit');}
      else if(now>(hitUntil.get(b)||0))b.classList.remove('hit');
    });
    requestAnimationFrame(tick);
  }
  calcAngles();
  window.addEventListener('resize',()=>setTimeout(calcAngles,60));
  setTimeout(calcAngles,200);
  requestAnimationFrame(tick);
}
