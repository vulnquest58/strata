package output

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"

	"github.com/echoforge/echoforge/internal/model"
	"github.com/echoforge/echoforge/internal/scorer"
)

// htmlTemplate is the embedded HTML report template with D3.js visualization.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EchoForge Report — {{.Domain}}</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
  <style>
    :root {
      --bg: #0a0a0f;
      --surface: #12121a;
      --surface2: #1a1a26;
      --border: #2a2a3e;
      --accent: #7c3aed;
      --accent2: #06b6d4;
      --green: #22c55e;
      --yellow: #eab308;
      --red: #ef4444;
      --cyan: #22d3ee;
      --text: #e2e8f0;
      --muted: #64748b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; }
    
    /* Header */
    .header {
      background: linear-gradient(135deg, #1a0533 0%, #0d1a3a 50%, #0a1a2e 100%);
      border-bottom: 1px solid var(--border);
      padding: 32px 48px;
      position: relative;
      overflow: hidden;
    }
    .header::before {
      content: '';
      position: absolute; inset: 0;
      background: radial-gradient(ellipse at 30% 50%, rgba(124,58,237,0.15) 0%, transparent 60%);
    }
    .header-content { position: relative; z-index: 1; }
    .logo { font-size: 32px; font-weight: 900; letter-spacing: -1px;
      background: linear-gradient(135deg, #a855f7, #06b6d4);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .tagline { color: var(--muted); font-size: 14px; margin-top: 4px; }
    .header-meta { display: flex; gap: 24px; margin-top: 20px; flex-wrap: wrap; }
    .meta-chip {
      background: rgba(255,255,255,0.05); border: 1px solid var(--border);
      border-radius: 8px; padding: 8px 16px; font-size: 13px;
    }
    .meta-chip span { color: var(--muted); margin-right: 6px; }
    
    /* Stats */
    .stats-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px; padding: 32px 48px; background: var(--surface);
      border-bottom: 1px solid var(--border);
    }
    .stat-card {
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 12px; padding: 20px;
    }
    .stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-value { font-size: 32px; font-weight: 700; margin-top: 8px; }
    .stat-value.green { color: var(--green); }
    .stat-value.yellow { color: var(--yellow); }
    .stat-value.cyan { color: var(--cyan); }
    .stat-value.purple { color: #a855f7; }

    /* Graph */
    .section { padding: 32px 48px; border-bottom: 1px solid var(--border); }
    .section-title { font-size: 18px; font-weight: 700; margin-bottom: 20px;
      display: flex; align-items: center; gap: 10px;
    }
    .section-title::before { content: ''; display: block; width: 4px; height: 20px;
      background: linear-gradient(var(--accent), var(--accent2)); border-radius: 2px;
    }
    #graph-container {
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 12px; overflow: hidden; height: 500px;
    }
    #graph-container svg { width: 100%; height: 100%; }
    
    /* Table */
    .table-controls {
      display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;
      align-items: center;
    }
    .filter-input {
      background: var(--surface2); border: 1px solid var(--border);
      color: var(--text); border-radius: 8px; padding: 8px 16px;
      font-size: 14px; outline: none; flex: 1; min-width: 200px;
    }
    .filter-input:focus { border-color: var(--accent); }
    .filter-btn {
      background: var(--surface2); border: 1px solid var(--border);
      color: var(--text); border-radius: 8px; padding: 8px 16px;
      font-size: 12px; cursor: pointer; white-space: nowrap;
    }
    .filter-btn.active { background: var(--accent); border-color: var(--accent); }
    
    table { width: 100%; border-collapse: collapse; }
    thead { background: var(--surface2); }
    th {
      padding: 12px 16px; font-size: 11px; text-transform: uppercase;
      letter-spacing: 0.05em; color: var(--muted); text-align: left;
      border-bottom: 1px solid var(--border); cursor: pointer; user-select: none;
    }
    th:hover { color: var(--text); }
    td { padding: 12px 16px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.03); }
    tr:hover td { background: rgba(255,255,255,0.02); }
    
    .badge {
      display: inline-block; padding: 2px 10px; border-radius: 100px;
      font-size: 11px; font-weight: 600;
    }
    .badge-high { background: rgba(34,197,94,0.15); color: var(--green); }
    .badge-medium { background: rgba(234,179,8,0.15); color: var(--yellow); }
    .badge-low { background: rgba(34,211,238,0.15); color: var(--cyan); }
    .badge-uncertain { background: rgba(100,116,139,0.15); color: var(--muted); }
    
    .conf-bar { height: 4px; border-radius: 2px; background: var(--border); width: 80px; display: inline-block; vertical-align: middle; margin-left: 8px; }
    .conf-fill { height: 100%; border-radius: 2px; }
    .conf-fill-high { background: var(--green); }
    .conf-fill-medium { background: var(--yellow); }
    .conf-fill-low { background: var(--cyan); }
    
    .ip-tag { font-family: 'Fira Code', monospace; font-size: 12px; color: var(--muted); }
    .source-tag { font-size: 11px; color: var(--muted); font-style: italic; }
    
    .resolve-yes { color: var(--green); }
    .resolve-no { color: var(--muted); }
    
    /* Footer */
    .footer {
      padding: 24px 48px; color: var(--muted); font-size: 12px;
      display: flex; justify-content: space-between; align-items: center;
    }

    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap');
  </style>
</head>
<body>
  <div class="header">
    <div class="header-content">
      <div class="logo">⚡ EchoForge</div>
      <div class="tagline">Evolutionary Echo Discovery Engine — Reconnaissance Report</div>
      <div class="header-meta">
        <div class="meta-chip"><span>🎯 Target</span>{{.Domain}}</div>
        <div class="meta-chip"><span>🆔 Scan ID</span>{{.ScanID}}</div>
        <div class="meta-chip"><span>⏱ Duration</span>{{.Duration}}</div>
        <div class="meta-chip"><span>📅 Date</span>{{.StartTime.Format "2006-01-02 15:04"}}</div>
      </div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Discovered</div>
      <div class="stat-value purple">{{.TotalDiscovered}}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">DNS Resolved</div>
      <div class="stat-value cyan">{{.TotalResolved}}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High Confidence</div>
      <div class="stat-value green">{{.HighConfidence}}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Avg Confidence</div>
      <div class="stat-value yellow">{{printf "%.0f" .AvgConfidence}}%</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Echo Discovery Graph</div>
    <div id="graph-container">
      <svg id="graph"></svg>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Subdomain Results</div>
    <div class="table-controls">
      <input class="filter-input" id="searchInput" type="text" placeholder="🔍 Filter subdomains..." oninput="filterTable()">
      <button class="filter-btn active" onclick="filterByLevel('all', this)">All</button>
      <button class="filter-btn" onclick="filterByLevel('HIGH', this)">🟢 High</button>
      <button class="filter-btn" onclick="filterByLevel('MEDIUM', this)">🟡 Medium</button>
      <button class="filter-btn" onclick="filterByLevel('LOW', this)">🔵 Low</button>
      <button class="filter-btn" onclick="filterByLevel('resolved', this)">✓ Resolved</button>
    </div>
    <table id="resultsTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Subdomain ↕</th>
          <th onclick="sortTable(1)">Confidence ↕</th>
          <th onclick="sortTable(2)">Level ↕</th>
          <th onclick="sortTable(3)">Source ↕</th>
          <th onclick="sortTable(4)">Resolves ↕</th>
          <th onclick="sortTable(5)">HTTP ↕</th>
          <th>IPs</th>
        </tr>
      </thead>
      <tbody id="tableBody">
      {{range .Subdomains}}
        <tr data-level="{{.Level}}" data-resolves="{{.Resolves}}">
          <td style="font-family: monospace; font-size: 13px;">{{.Name}}</td>
          <td>
            {{printf "%.1f" .Confidence}}%
            <span class="conf-bar"><span class="conf-fill conf-fill-{{lower .Level}}" style="width:{{printf "%.0f" .Confidence}}%"></span></span>
          </td>
          <td><span class="badge badge-{{lower .Level}}">{{.Level}}</span></td>
          <td class="source-tag">{{.Source}}</td>
          <td class="{{if .Resolves}}resolve-yes{{else}}resolve-no{{end}}">{{if .Resolves}}✓{{else}}✗{{end}}</td>
          <td>{{if gt .HTTPStatus 0}}{{.HTTPStatus}}{{else}}-{{end}}</td>
          <td class="ip-tag">{{index .IPAddresses 0 | default "-"}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </div>

  <div class="footer">
    <div>⚡ Generated by EchoForge v1.0.0 — Evolutionary Echo Discovery Engine</div>
    <div>{{.StartTime.Format "Mon, 02 Jan 2006 15:04:05 MST"}}</div>
  </div>

<script>
  // ── Graph Data ──────────────────────────────────────────────────────────────
  const graphData = {{.GraphJSON}};
  
  // ── D3 Force Graph ──────────────────────────────────────────────────────────
  (function() {
    const svg = d3.select("#graph");
    const container = document.getElementById("graph-container");
    const width = container.clientWidth || 900;
    const height = 500;

    const simulation = d3.forceSimulation(graphData.nodes)
      .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(30));

    const defs = svg.append("defs");
    ["high", "medium", "low"].forEach(function(level) {
      const colors = { high: ["#22c55e", "#16a34a"], medium: ["#eab308", "#ca8a04"], low: ["#22d3ee", "#0891b2"] };
      const grad = defs.append("radialGradient").attr("id", "grad-" + level);
      grad.append("stop").attr("offset", "0%").attr("stop-color", colors[level][0]).attr("stop-opacity", 0.9);
      grad.append("stop").attr("offset", "100%").attr("stop-color", colors[level][1]).attr("stop-opacity", 0.6);
    });

    const link = svg.append("g")
      .selectAll("line")
      .data(graphData.links)
      .join("line")
      .attr("stroke", "#2a2a3e")
      .attr("stroke-width", 1.5)
      .attr("stroke-opacity", 0.6);

    const node = svg.append("g")
      .selectAll("g")
      .data(graphData.nodes)
      .join("g")
      .call(d3.drag()
        .on("start", (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end", (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

    node.append("circle")
      .attr("r", function(d) { return d.root ? 18 : Math.max(6, d.confidence / 10); })
      .attr("fill", function(d) { return d.root ? "url(#grad-high)" : "url(#grad-" + d.level.toLowerCase() + ")"; })
      .attr("stroke", function(d) { return d.root ? "#7c3aed" : "none"; })
      .attr("stroke-width", 2);

    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", d => (d.root ? 28 : 22))
      .attr("fill", "#94a3b8")
      .attr("font-size", d => d.root ? 12 : 10)
      .attr("font-family", "monospace")
      .text(d => d.label);

    node.append("title").text(function(d) { return d.id + "\nConfidence: " + d.confidence + "%\nSource: " + d.source; });

    simulation.on("tick", function() {
      link.attr("x1", function(d) { return d.source.x; }).attr("y1", function(d) { return d.source.y; })
          .attr("x2", function(d) { return d.target.x; }).attr("y2", function(d) { return d.target.y; });
      node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
    });
  })();

  // ── Table Filtering ─────────────────────────────────────────────────────────
  let currentLevel = 'all';

  function filterTable() {
    const query = document.getElementById('searchInput').value.toLowerCase();
    const rows = document.querySelectorAll('#tableBody tr');
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      const level = row.dataset.level;
      const resolves = row.dataset.resolves === 'true';
      const matchText = text.includes(query);
      const matchLevel = currentLevel === 'all' || 
                         (currentLevel === 'resolved' ? resolves : level === currentLevel);
      row.style.display = matchText && matchLevel ? '' : 'none';
    });
  }

  function filterByLevel(level, btn) {
    currentLevel = level;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterTable();
  }

  // ── Table Sorting ───────────────────────────────────────────────────────────
  let sortDir = {};
  function sortTable(col) {
    const tbody = document.getElementById('tableBody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    sortDir[col] = !sortDir[col];
    rows.sort((a, b) => {
      const aVal = a.cells[col].textContent.trim();
      const bVal = b.cells[col].textContent.trim();
      const aNum = parseFloat(aVal);
      const bNum = parseFloat(bVal);
      if (!isNaN(aNum) && !isNaN(bNum)) return sortDir[col] ? aNum - bNum : bNum - aNum;
      return sortDir[col] ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
    rows.forEach(r => tbody.appendChild(r));
  }
</script>
</body>
</html>`

// HTMLSubdomain is a template-friendly version of model.Subdomain.
type HTMLSubdomain struct {
	model.Subdomain
	Level string
}

// HTMLData is passed to the HTML template.
type HTMLData struct {
	model.ScanResult
	Subdomains    []HTMLSubdomain
	AvgConfidence float64
	GraphJSON     template.JS
}

// WriteHTML generates a rich interactive HTML report with a D3.js graph.
func WriteHTML(result *model.ScanResult, path string) error {
	sort.Slice(result.Subdomains, func(i, j int) bool {
		return result.Subdomains[i].Confidence > result.Subdomains[j].Confidence
	})

	// Build template subdomains with level annotation
	subs := make([]HTMLSubdomain, len(result.Subdomains))
	totalConf := 0.0
	for i, s := range result.Subdomains {
		subs[i] = HTMLSubdomain{
			Subdomain: s,
			Level:     scorer.Category(s.Confidence),
		}
		totalConf += s.Confidence
	}
	avgConf := 0.0
	if len(subs) > 0 {
		avgConf = totalConf / float64(len(subs))
	}

	// Build graph JSON
	graphJSON := buildGraphJSON(result)

	data := HTMLData{
		ScanResult:    *result,
		Subdomains:    subs,
		AvgConfidence: avgConf,
		GraphJSON:     template.JS(graphJSON),
	}

	// Custom template functions
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"firstIP": func(ips []string) string {
			if len(ips) == 0 {
				return "-"
			}
			return ips[0]
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("html: parse template: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("html: create file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("html: execute template: %w", err)
	}
	return nil
}

// buildGraphJSON builds the D3.js-compatible node/link JSON for the discovery graph.
func buildGraphJSON(result *model.ScanResult) string {
	var sb strings.Builder

	// Root node
	rootLabel := strings.Split(result.Domain, ".")[0]
	sb.WriteString(`{"nodes":[`)
	sb.WriteString(fmt.Sprintf(`{"id":%q,"label":%q,"confidence":100,"level":"HIGH","source":"root","root":true}`,
		result.Domain, rootLabel))

	// Add up to 80 subdomains as graph nodes (keep it performant)
	limit := len(result.Subdomains)
	if limit > 80 {
		limit = 80
	}
	for _, sub := range result.Subdomains[:limit] {
		label := strings.Split(sub.Name, ".")[0]
		if len(label) > 12 {
			label = label[:12] + "…"
		}
		sb.WriteString(fmt.Sprintf(`,{"id":%q,"label":%q,"confidence":%.1f,"level":%q,"source":%q,"root":false}`,
			sub.Name, label, sub.Confidence, scorer.Category(sub.Confidence), sub.Source))
	}

	sb.WriteString(`],"links":[`)
	first := true
	for _, sub := range result.Subdomains[:limit] {
		source := result.Domain
		if len(sub.EchoFrom) > 0 {
			source = sub.EchoFrom[0]
		}
		if first {
			first = false
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(`{"source":%q,"target":%q}`, source, sub.Name))
	}
	sb.WriteString(`]}`)

	return sb.String()
}


