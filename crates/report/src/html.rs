use sentinel_core::{Lang, ScanResult, Verdict};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn generate_html_report(result: &ScanResult, path: &Path, lang: Lang) -> std::io::Result<()> {
    let html = render_html_string(result, lang);
    let mut file = File::create(path)?;
    file.write_all(html.as_bytes())?;
    Ok(())
}

pub fn render_html_string(result: &ScanResult, _lang: Lang) -> String {
    let findings_json = serde_json::to_string(&result.findings).unwrap_or_else(|_| "[]".to_string());
    let _skipped_json = serde_json::to_string(&result.skipped_checks).unwrap_or_else(|_| "[]".to_string());
    let _platform_json = serde_json::to_string(&result.platform).unwrap_or_else(|_| "{}".to_string());

    let verdict_class = match result.verdict {
        Verdict::Clean => "verdict-clean",
        Verdict::ReviewRecommended => "verdict-review",
        Verdict::SurveillanceLikely => "verdict-danger",
    };

    let verdict_icon = match result.verdict {
        Verdict::Clean => "🛡️",
        Verdict::ReviewRecommended => "⚠️",
        Verdict::SurveillanceLikely => "🚨",
    };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel — Security & Privacy Audit Report</title>
<style>
  :root {{
    --bg: #0f172a;
    --card-bg: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --danger: #f43f5e;
    --warning: #f59e0b;
    --success: #10b981;
    --code-bg: #090d16;
  }}
  .light {{
    --bg: #f8fafc;
    --card-bg: #ffffff;
    --border: #e2e8f0;
    --text: #0f172a;
    --text-muted: #64748b;
    --accent: #0284c7;
    --code-bg: #f1f5f9;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    line-height: 1.6;
    padding: 24px;
    transition: background-color 0.2s, color 0.2s;
  }}
  .container {{ max-width: 1040px; margin: 0 auto; }}
  header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 24px;
  }}
  .logo {{ display: flex; align-items: center; gap: 12px; font-size: 24px; font-weight: 700; color: var(--accent); }}
  .controls {{ display: flex; gap: 10px; }}
  button, .btn {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 14px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
  }}
  button:hover, .btn:hover {{ border-color: var(--accent); }}
  .verdict-banner {{
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 20px;
    border: 1px solid transparent;
  }}
  .verdict-clean {{ background: rgba(16, 185, 129, 0.1); border-color: var(--success); }}
  .verdict-review {{ background: rgba(245, 158, 11, 0.1); border-color: var(--warning); }}
  .verdict-danger {{ background: rgba(244, 63, 94, 0.15); border-color: var(--danger); }}
  .verdict-icon {{ font-size: 48px; }}
  .verdict-title {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
  .verdict-subtitle {{ color: var(--text-muted); font-size: 15px; }}
  .meta-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 24px;
    font-size: 14px;
  }}
  .meta-item span {{ color: var(--text-muted); display: block; font-size: 12px; text-transform: uppercase; margin-bottom: 2px; }}
  .search-filter-bar {{
    display: flex;
    gap: 12px;
    margin-bottom: 24px;
    flex-wrap: wrap;
  }}
  input[type="text"] {{
    flex: 1;
    min-width: 240px;
    background: var(--card-bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 14px;
  }}
  select {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 14px;
  }}
  .mitre-section-title {{ font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-bottom: 10px; display: flex; align-items: center; gap: 6px; }}
  .mitre-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }}
  .mitre-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
    text-align: left;
  }}
  .mitre-code {{ font-size: 11px; color: var(--text-muted); font-family: monospace; }}
  .mitre-name {{ font-size: 13px; font-weight: 600; margin: 4px 0 6px 0; }}
  .mitre-status {{
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 999px;
    display: inline-block;
  }}
  .status-clear {{ background: rgba(16, 185, 129, 0.15); color: var(--success); }}
  .status-detected {{ background: rgba(244, 63, 94, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
  }}
  .card-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 12px;
    gap: 12px;
  }}
  .card-title {{ font-size: 18px; font-weight: 600; display: flex; align-items: center; gap: 8px; }}
  .badge {{
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
  }}
  .badge-Critical, .badge-High {{ background: rgba(244, 63, 94, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
  .badge-Medium {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
  .badge-Low, .badge-Info {{ background: rgba(56, 189, 248, 0.2); color: var(--accent); border: 1px solid var(--accent); }}
  .explain-block {{ margin: 12px 0; font-size: 14px; }}
  .explain-title {{ font-weight: 600; color: var(--accent); margin-bottom: 4px; }}
  .evidence-box {{
    background: var(--code-bg);
    border-radius: 8px;
    padding: 12px;
    margin: 10px 0;
    font-family: monospace;
    font-size: 13px;
    max-height: 200px;
    overflow-y: auto;
  }}
  .action-box {{
    background: rgba(2, 132, 199, 0.08);
    border: 1px dashed var(--accent);
    border-radius: 8px;
    padding: 14px;
    margin-top: 14px;
    font-size: 14px;
  }}
  .cmd-line {{
    background: var(--code-bg);
    padding: 8px 12px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 13px;
    color: var(--accent);
    margin: 6px 0;
    display: block;
  }}
  .safety-box {{
    background: rgba(244, 63, 94, 0.08);
    border: 1px solid var(--danger);
    border-radius: 12px;
    padding: 20px;
    margin-top: 32px;
    font-size: 14px;
  }}
  .safety-box h3 {{ color: var(--danger); margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }}
  footer {{
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    font-size: 13px;
    color: var(--text-muted);
    text-align: center;
  }}
  @media print {{
    body {{ background: #fff; color: #000; padding: 0; }}
    .controls, .search-filter-bar {{ display: none; }}
    .card {{ break-inside: avoid; border: 1px solid #ccc; }}
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">
      <span>🛡️ Sentinel</span>
    </div>
    <div class="controls">
      <button onclick="toggleTheme()" id="themeBtn">🌓 Theme</button>
      <button onclick="toggleLang()" id="langBtn">🌐 Язык: RU</button>
      <button onclick="window.print()">🖨️ Print</button>
    </div>
  </header>

  <div class="verdict-banner {verdict_class}">
    <div class="verdict-icon">{verdict_icon}</div>
    <div>
      <div class="verdict-title" id="verdictTitle">Scan Completed: {verdict_class}</div>
      <div class="verdict-subtitle" id="verdictSubtitle">Detailed analysis of active processes, startup hooks, and background services.</div>
    </div>
  </div>

  <div class="meta-bar">
    <div class="meta-item"><span>Platform</span>{os_name} ({arch})</div>
    <div class="meta-item"><span>Privilege</span>{priv_level:?}</div>
    <div class="meta-item"><span>Scan Duration</span>{duration:.2}s</div>
    <div class="meta-item"><span>Total Findings</span><strong id="findingCount">0</strong></div>
  </div>

  <div class="mitre-section-title"><span>🎯 MITRE ATT&CK® Threat Surveillance Surface</span></div>
  <div class="mitre-grid">
    <div class="mitre-card" id="cardT1056">
      <div class="mitre-code">T1056.001</div>
      <div class="mitre-name">Keylogging</div>
      <div class="mitre-status status-clear" id="statusT1056">CLEAR</div>
    </div>
    <div class="mitre-card" id="cardT1113">
      <div class="mitre-code">T1113</div>
      <div class="mitre-name">Screen Capture</div>
      <div class="mitre-status status-clear" id="statusT1113">CLEAR</div>
    </div>
    <div class="mitre-card" id="cardT1125">
      <div class="mitre-code">T1125 / T1123</div>
      <div class="mitre-name">Camera & Mic</div>
      <div class="mitre-status status-clear" id="statusT1125">CLEAR</div>
    </div>
    <div class="mitre-card" id="cardT1219">
      <div class="mitre-code">T1219 / T1021</div>
      <div class="mitre-name">Remote Control</div>
      <div class="mitre-status status-clear" id="statusT1219">CLEAR</div>
    </div>
    <div class="mitre-card" id="cardT1020">
      <div class="mitre-code">T1020 / T1071</div>
      <div class="mitre-name">C2 Exfiltration</div>
      <div class="mitre-status status-clear" id="statusT1020">CLEAR</div>
    </div>
    <div class="mitre-card" id="cardT1562">
      <div class="mitre-code">T1562.001</div>
      <div class="mitre-name">Watchdog Protection</div>
      <div class="mitre-status status-clear" id="statusT1562">CLEAR</div>
    </div>
  </div>

  <div class="search-filter-bar">
    <input type="text" id="searchInput" placeholder="Search by name, process, path, or vendor..." oninput="filterCards()">
    <select id="severityFilter" onchange="filterCards()">
      <option value="ALL">All Severities</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
      <option value="Info">Info</option>
    </select>
    <select id="categoryFilter" onchange="filterCards()">
      <option value="ALL">All Categories</option>
      <option value="KeyboardCapture">Keyboard Capture</option>
      <option value="ScreenCapture">Screen Capture</option>
      <option value="RemoteAccess">Remote Access</option>
      <option value="OrganizationManaged">Organization Managed</option>
      <option value="SuspiciousPersistence">Suspicious Persistence</option>
      <option value="ProcessWatcher">Process Watcher</option>
    </select>
  </div>

  <div id="findingsContainer"></div>

  <div class="safety-box">
    <h3 id="safetyTitle">🚨 Suspecting personal surveillance by someone you know?</h3>
    <p id="safetyBody">
      <strong>Important Safety Advisory:</strong> Removing or disabling stalkerware may immediately alert the person monitoring you.
      If you are in danger, plan your safety steps using a separate, unmonitored device before taking action.
      <br><br>
      • <strong>Coalition Against Stalkerware:</strong> <a href="https://stopstalkerware.org" target="_blank" style="color:var(--accent);">stopstalkerware.org</a><br>
      • <strong>National Domestic Violence Hotline (US):</strong> 1-800-799-SAFE (7233) | Text START to 88788<br>
      • <strong>International Directory of Support:</strong> <a href="https://lila.help" target="_blank" style="color:var(--accent);">lila.help</a>
    </p>
  </div>

  <div class="card" style="margin-top: 24px;">
    <h4 style="margin-bottom: 8px;">⚖️ Technical Limitations & Transparency</h4>
    <p style="font-size: 13px; color: var(--text-muted);">
      This scan operated in user-mode with zero persistent footprint and zero cloud telemetry.
      User-mode scanners cannot reliably detect hardware keystroke loggers (physical inline USB dongles), UEFI firmware implants, or stealth kernel-mode rootkits.
      For maximum assurance, inspect hardware connections or scan using an offline trusted boot environment.
    </p>
  </div>

  <footer>
    Sentinel v{pkg_version} — Built for defensive auditing. 100% local, zero telemetry.
  </footer>
</div>

<script>
  const findings = {findings_json};
  let currentLang = 'EN';

  function renderFindings() {{
    const container = document.getElementById('findingsContainer');
    container.innerHTML = '';
    document.getElementById('findingCount').innerText = findings.length;

    // Update MITRE ATT&CK Matrix
    const hasKeylog = findings.some(f => f.category === 'KeyboardCapture');
    const hasScreen = findings.some(f => f.category === 'ScreenCapture');
    const hasHardware = findings.some(f => f.evidence && f.evidence.some(e => e.evidence_type === 'HardwareCaptureAccess'));
    const hasRemote = findings.some(f => f.category === 'RemoteAccess');
    const hasC2 = findings.some(f => f.rule_id === 'stalkerware_c2_network_beacon' || f.category === 'NetworkActivity');
    const hasWatchdog = findings.some(f => f.category === 'ProcessWatcher');

    function updateMitre(id, detected) {{
      const el = document.getElementById(id);
      if (el) {{
        if (detected) {{
          el.innerText = 'DETECTED';
          el.className = 'mitre-status status-detected';
        }} else {{
          el.innerText = 'CLEAR';
          el.className = 'mitre-status status-clear';
        }}
      }}
    }}

    updateMitre('statusT1056', hasKeylog);
    updateMitre('statusT1113', hasScreen);
    updateMitre('statusT1125', hasHardware);
    updateMitre('statusT1219', hasRemote);
    updateMitre('statusT1020', hasC2);
    updateMitre('statusT1562', hasWatchdog);

    if (findings.length === 0) {{
      container.innerHTML = '<div class="card" style="text-align:center; padding: 40px; color: var(--text-muted);">' +
        '<h3>🎉 No suspicious surveillance software found</h3>' +
        '<p>All inspected processes and persistence hooks appear clean.</p></div>';
      return;
    }}

    findings.forEach(f => {{
      const card = document.createElement('div');
      card.className = 'card finding-card';
      card.dataset.severity = f.severity;
      card.dataset.category = f.category;
      card.dataset.text = (f.name + ' ' + (f.vendor || '') + ' ' + f.explanation.what_is_it).toLowerCase();

      let actionHtml = '';
      if (f.removal_policy === 'DoNotRemove') {{
        actionHtml = '<div class="action-box" style="border-color: var(--warning);">' +
          '<strong>⚙️ Organization Managed:</strong> This tool is administered by your workplace or IT team. Automatic removal is disabled to prevent system downtime. Contact your IT administrator.</div>';
      }} else {{
        actionHtml = '<div class="action-box">' +
          '<strong>🛠️ Safe Remediation Commands:</strong>' +
          '<div style="margin: 6px 0;">To quarantine reversibly:</div>' +
          '<code class="cmd-line">sentinel quarantine ' + f.id + '</code>' +
          '<div style="margin: 6px 0;">To permanently remove:</div>' +
          '<code class="cmd-line">sentinel remove ' + f.id + '</code>' +
          '</div>';
      }}

      card.innerHTML = `
        <div class="card-header">
          <div>
            <div class="card-title">
              <span>${{f.name}}</span>
            </div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 2px;">
              ${{f.vendor ? f.vendor + ' • ' : ''}}${{f.category}} • Confidence: ${{Math.round(f.confidence.score * 100)}}%
            </div>
          </div>
          <span class="badge badge-${{f.severity}}">${{f.severity}}</span>
        </div>

        <div class="explain-block">
          <div class="explain-title">What is this?</div>
          <p>${{f.explanation.what_is_it}}</p>
        </div>

        <div class="explain-block">
          <div class="explain-title">Why was it flagged?</div>
          <p>${{f.explanation.why_flagged}}</p>
        </div>

        <div class="explain-block">
          <div class="explain-title">Is it legitimate?</div>
          <p>${{f.explanation.is_legitimate}}</p>
        </div>

        <details style="margin-top: 10px; cursor: pointer;">
          <summary style="font-weight: 600; color: var(--accent);">Technical Evidence (${{f.evidence.length}} item(s))</summary>
          <div class="evidence-box">
            ${{f.evidence.map(e => `• [${{e.evidence_type}}] ${{e.description}}\n  ${{e.technical_detail}}`).join('\n\n')}}
          </div>
        </details>

        ${{actionHtml}}
      `;

      container.appendChild(card);
    }});
  }}

  function filterCards() {{
    const q = document.getElementById('searchInput').value.toLowerCase();
    const sev = document.getElementById('severityFilter').value;
    const cat = document.getElementById('categoryFilter').value;

    document.querySelectorAll('.finding-card').forEach(c => {{
      const matchesQ = !q || c.dataset.text.includes(q);
      const matchesSev = sev === 'ALL' || c.dataset.severity === sev;
      const matchesCat = cat === 'ALL' || c.dataset.category === cat;
      c.style.display = (matchesQ && matchesSev && matchesCat) ? 'block' : 'none';
    }});
  }}

  function toggleTheme() {{
    document.body.classList.toggle('light');
  }}

  function toggleLang() {{
    currentLang = currentLang === 'EN' ? 'RU' : 'EN';
    document.getElementById('langBtn').innerText = currentLang === 'EN' ? '🌐 Язык: RU' : '🌐 Lang: EN';
    if (currentLang === 'RU') {{
      document.getElementById('verdictTitle').innerText = 'Аудит завершён';
      document.getElementById('verdictSubtitle').innerText = 'Подробный анализ процессов, автозагрузки и системных служб.';
      document.getElementById('safetyTitle').innerText = '🚨 Подозреваете личную слежку со стороны конкретного человека?';
    }} else {{
      document.getElementById('verdictTitle').innerText = 'Scan Completed';
      document.getElementById('verdictSubtitle').innerText = 'Detailed analysis of active processes, startup hooks, and background services.';
      document.getElementById('safetyTitle').innerText = '🚨 Suspecting personal surveillance by someone you know?';
    }}
  }}

  renderFindings();
</script>
</body>
</html>
"#,
        verdict_class = verdict_class,
        verdict_icon = verdict_icon,
        os_name = result.platform.os_name,
        arch = result.platform.architecture,
        priv_level = result.platform.privilege_level,
        duration = result.scan_duration.as_secs_f32(),
        findings_json = findings_json,
        pkg_version = env!("CARGO_PKG_VERSION"),
    )
}
