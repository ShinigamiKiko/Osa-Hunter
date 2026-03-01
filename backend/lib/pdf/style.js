'use strict';

const EXPORT_SEV_COLORS = {
  CRITICAL: { bg: '#2d0a0a', border: '#ff4444', text: '#ff4444' },
  HIGH:     { bg: '#2d1500', border: '#ff8c32', text: '#ff8c32' },
  MEDIUM:   { bg: '#2a2000', border: '#fbbf24', text: '#fbbf24' },
  LOW:      { bg: '#0a2018', border: '#34d399', text: '#34d399' },
  NONE:     { bg: '#0a2018', border: '#34d399', text: '#34d399' },
  UNKNOWN:  { bg: '#111827', border: '#5a6478', text: '#5a6478' },
};

function sevBadge(sev) {
  const c = EXPORT_SEV_COLORS[sev] || EXPORT_SEV_COLORS.UNKNOWN;
  return `<span style="display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.06em;background:${c.bg};border:1px solid ${c.border};color:${c.text}">${sev}</span>`;
}

function epssBar(epss) {
  if (!epss) return '<span style="color:#5a6478;font-size:11px">—</span>';
  const pct = (epss.epss * 100).toFixed(2);
  const color = epss.epss >= 0.1 ? '#ff4444' : epss.epss >= 0.01 ? '#fbbf24' : '#34d399';
  return `<span style="font-size:12px;color:${color};font-weight:600">${pct}%</span><span style="color:#5a6478;font-size:10px;margin-left:5px">(${(epss.percentile * 100).toFixed(0)}th pct)</span>`;
}

function cvssLine(cvss) {
  if (!cvss || !cvss.cvss3) return '<span style="color:#5a6478;font-size:11px">—</span>';
  const s = cvss.cvss3.score;
  const color = s >= 9 ? '#ff4444' : s >= 7 ? '#ff8c32' : s >= 4 ? '#fbbf24' : '#34d399';
  return `<span style="color:${color};font-weight:700;font-size:13px">${s}</span><span style="color:#5a6478;font-size:10px;margin-left:4px">CVSSv${cvss.cvss3.version || 3}</span>`;
}

function activityLine(activity) {
  if (!activity || !activity.found || !activity.lastCommit) return '';
  const date = new Date(activity.lastCommit);
  const days = Math.floor((Date.now() - date) / 86400000);
  const years = Math.floor(days / 365);
  const age =
    days < 1 ? 'today' :
    days < 7 ? `${days}d ago` :
    days < 60 ? `${Math.floor(days / 7)}w ago` :
    years >= 1 ? `${years}y ago` :
    `${Math.floor(days / 30)}mo ago`;
  const stale = years >= 2;
  const color = stale ? '#ff8c32' : '#34d399';
  const label = stale ? '⚠ Possibly stale' : '● Active';
  const dateStr = date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  const repoLink = activity.repoUrl
    ? ` <a href="${activity.repoUrl}" style="color:${color};opacity:.7;font-size:10px;text-decoration:none">↗ repo</a>`
    : '';
  return `<span style="font-size:11px;color:${color}">${label} · last commit ${age} · ${dateStr}</span>${repoLink}`;
}

function toxicLine(toxic) {
  if (!toxic || !toxic.found) return '<span style="color:#34d399;font-size:11px">✅ Not in toxic-repos</span>';
  const labels = {
    ddos: 'DDoS tool',
    hostile_actions: 'Hostile actions',
    political_slogan: 'Political slogan',
    malware: 'Malware',
    ip_blocking: 'IP blocking',
  };
  const label = labels[toxic.problem_type] || toxic.problem_type || 'Toxic';
  const desc = toxic.description ? ` — ${toxic.description.slice(0, 120)}` : '';
  return `<span style="color:#ff3b30;font-size:11px;font-weight:600">☠ Toxic: ${label}${desc}</span>`;
}

function pocLinks(pocs) {
  if (!pocs || !pocs.length) return '<span style="color:#34d399;font-size:11px">No public PoC found</span>';
  return pocs.slice(0, 3).map(p =>
    `<a href="${p.url}" style="display:inline-block;background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;text-decoration:none;margin-right:4px">💥 ${p.name} ⭐${p.stars}</a>`
  ).join('');
}

module.exports = {
  EXPORT_SEV_COLORS,
  sevBadge,
  epssBar,
  cvssLine,
  activityLine,
  toxicLine,
  pocLinks,
};
