// ── DEP SCAN CONFIG ───────────────────────────────────────────
const DEP_SYSTEMS = [
  { id:'NPM',      label:'npm',      logo:'📦', hint:'express, lodash…' },
  { id:'PYPI',     label:'PyPI',     logo:'🐍', hint:'django, requests…' },
  { id:'GO',       label:'Go',       logo:'🐹', hint:'github.com/gin-gonic/gin' },
  { id:'CARGO',    label:'Rust',     logo:'🦀', hint:'tokio, serde…' },
  { id:'MAVEN',    label:'Maven',    logo:'☕', hint:'com.google.guava:guava' },
  { id:'NUGET',    label:'NuGet',    logo:'🔷', hint:'Newtonsoft.Json…' },
  { id:'COMPOSER', label:'Composer', logo:'🐘', hint:'monolog/monolog' },
];

let depScans  = safeLoad('es_dep', []);
let selDepSys = null;
let currentDepScan = null;
const saveDep = () => safeSave('es_dep', depScans);

// ── MODAL ─────────────────────────────────────────────────────
