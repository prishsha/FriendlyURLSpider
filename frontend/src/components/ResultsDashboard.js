import { useState } from "react";
import VulnCard from "./VulnCard";
import "./ResultsDashboard.css";

function RiskMeter({ score, level }) {
  const pct = (score / 10) * 100;
  const colorMap = {
    Low: "#16a34a",
    Medium: "#d97706",
    High: "#ea580c",
    Critical: "#dc2626",
  };
  const color = colorMap[level] || "#6b7280";

  return (
    <div className="risk-meter">
      <div className="risk-score-val" style={{ color }}>
        {score}<span>/10</span>
      </div>
      <div className="risk-bar-outer">
        <div className="risk-bar-inner" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className={`badge badge-${level?.toLowerCase()}`}>{level}</span>
    </div>
  );
}

function StatBox({ label, value, severity }) {
  const badgeClass = severity ? `badge badge-${severity.toLowerCase()}` : "";
  return (
    <div className={`stat-box ${value > 0 ? "has-findings" : ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {severity && value > 0 && <span className={badgeClass}>{severity}</span>}
    </div>
  );
}

function ResultsDashboard({ results, urls, targetUrl, jobId, onReset }) {
  const [activeTab, setActiveTab] = useState("overview");

  const risk = results?.risk || {};
  const sqli = results?.sqli || [];
  const xss = results?.xss || [];
  const csrf = results?.csrf || [];
  const headers = results?.headers || [];
  const redirect = results?.open_redirect || [];
  const dirs = results?.directories || [];
  const ssrf = results?.ssrf || [];
  const auth = results?.auth || [];
  const explanations = results?.explanations || {};

  const totalFindings = sqli.length + xss.length + csrf.length + redirect.length +
    dirs.length + ssrf.length + auth.length;

  const tabs = ["overview", "findings", "headers", "urls"];

  return (
    <div className="dashboard">
      <div className="dashboard-topbar">
        <div>
          <h2 className="dashboard-title">Scan Results</h2>
          <span className="dashboard-url">{targetUrl}</span>
        </div>
        <div className="dashboard-actions">
          <a
            href={`/api/pdf/${jobId}`}
            target="_blank"
            rel="noreferrer"
            className="btn-secondary"
          >
            ⬇ Download PDF
          </a>
          <button className="btn-secondary" onClick={onReset}>
            New Scan
          </button>
        </div>
      </div>

      {/* Summary strip */}
      <div className="summary-strip">
        <div className="summary-risk">
          <div className="summary-section-label">Overall Risk</div>
          <RiskMeter score={risk.score} level={risk.level} />
        </div>
        <div className="summary-stats">
          <StatBox label="SQL Injection" value={sqli.length} severity="Critical" />
          <StatBox label="XSS" value={xss.length} severity="High" />
          <StatBox label="CSRF" value={csrf.length} severity="Medium" />
          <StatBox label="SSRF" value={ssrf.length} severity="High" />
          <StatBox label="Auth Issues" value={auth.length} severity="Critical" />
          <StatBox label="Exposed Paths" value={dirs.length} severity="High" />
          <StatBox label="Open Redirect" value={redirect.length} severity="Medium" />
          <StatBox label="Header Issues" value={headers.length} severity="Medium" />
        </div>
      </div>

      {/* Tab nav */}
      <div className="tab-nav">
        {tabs.map((tab) => (
          <button
            key={tab}
            className={`tab-btn ${activeTab === tab ? "active" : ""}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* Tab: Overview */}
      {activeTab === "overview" && (
        <div className="tab-content">
          <div className="overview-grid">
            {totalFindings === 0 && headers.length === 0 && (
              <div className="card all-clear">
                <span style={{ fontSize: 24 }}>✅</span>
                <strong>No major vulnerabilities detected.</strong>
                <p>The scanner didn't find obvious issues. This doesn't mean the site is fully secure.</p>
              </div>
            )}

            {/* Breakdown table */}
            <div className="card">
              <div className="card-title">Risk Breakdown</div>
              <table className="breakdown-table">
                <thead>
                  <tr>
                    <th>Vulnerability</th>
                    <th>Findings</th>
                    <th>Severity</th>
                    <th>OWASP Ref</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ["SQL Injection", sqli.length, "Critical", "A03:2021"],
                    ["XSS", xss.length, "High", "A03:2021"],
                    ["CSRF", csrf.length, "Medium", "A01:2021"],
                    ["Open Redirect", redirect.length, "Medium", "A01:2021"],
                    ["SSRF", ssrf.length, "High", "A10:2021"],
                    ["Auth Weaknesses", auth.length, "Critical", "A07:2021"],
                    ["Exposed Paths", dirs.length, "High", "A05:2021"],
                    ["Header Issues", headers.length, "Medium", "A05:2021"],
                  ].map(([name, count, sev, owasp]) => (
                    <tr key={name}>
                      <td>{name}</td>
                      <td className={count > 0 ? "count-bad" : "count-ok"}>{count}</td>
                      <td><span className={`badge badge-${sev.toLowerCase()}`}>{sev}</span></td>
                      <td className="owasp-ref">{owasp}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Crawled URLs mini */}
            <div className="card">
              <div className="card-title">
                URLs Crawled <span className="card-count">{urls.length}</span>
              </div>
              <ul className="url-mini-list">
                {urls.slice(0, 8).map((u) => (
                  <li key={u}><span className="url-dot">•</span> {u}</li>
                ))}
                {urls.length > 8 && (
                  <li className="more-urls">...and {urls.length - 8} more</li>
                )}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Tab: Findings */}
      {activeTab === "findings" && (
        <div className="tab-content">
          {totalFindings === 0 ? (
            <div className="card all-clear">
              <span style={{ fontSize: 24 }}>✅</span>
              <strong>No vulnerability findings to display.</strong>
            </div>
          ) : (
            <div className="findings-list">
              {sqli.length > 0 && (
                <VulnCard
                  title="SQL Injection"
                  severity="Critical"
                  findings={sqli}
                  explanation={explanations.sqli}
                  renderFinding={(f) => (
                    <div>
                      <div className="finding-url">{f.url || f}</div>
                      {f.payload && <div className="finding-detail">Payload: <code>{f.payload}</code></div>}
                      {f.reason && <div className="finding-reason">{f.reason}</div>}
                    </div>
                  )}
                />
              )}

              {xss.length > 0 && (
                <VulnCard
                  title="Cross-Site Scripting (XSS)"
                  severity="High"
                  findings={xss}
                  explanation={explanations.xss}
                  renderFinding={(f) => (
                    <div>
                      <div className="finding-url">{f.url || f}</div>
                      {f.type && <div className="finding-detail">Type: {f.type}</div>}
                      {f.reason && <div className="finding-reason">{f.reason}</div>}
                    </div>
                  )}
                />
              )}

              {csrf.length > 0 && (
                <VulnCard
                  title="CSRF (Cross-Site Request Forgery)"
                  severity="Medium"
                  findings={csrf}
                  explanation={explanations.csrf}
                  renderFinding={(f) => (
                    <div>
                      <div className="finding-url">{f.url || f}</div>
                      {f.reason && <div className="finding-reason">{f.reason}</div>}
                    </div>
                  )}
                />
              )}

              {redirect.length > 0 && (
                <VulnCard
                  title="Open Redirect"
                  severity="Medium"
                  findings={redirect}
                  explanation={explanations.open_redirect}
                  renderFinding={(f) => (
                    <div>
                      <div className="finding-url">{f.url || f}</div>
                      {f.param && <div className="finding-detail">Parameter: <code>{f.param}</code></div>}
                      {f.reason && <div className="finding-reason">{f.reason}</div>}
                    </div>
                  )}
                />
              )}

              {ssrf.length > 0 && (
                <VulnCard
                  title="SSRF (Server-Side Request Forgery)"
                  severity="High"
                  findings={ssrf}
                  explanation={explanations.ssrf}
                  renderFinding={(f) => (
                    <div>
                      <div className="finding-url">{f.url || f}</div>
                      {f.param && <div className="finding-detail">Param: <code>{f.param}</code></div>}
                      {f.reason && <div className="finding-reason">{f.reason}</div>}
                    </div>
                  )}
                />
              )}

              {auth.length > 0 && (
                <VulnCard
                  title="Authentication Weaknesses"
                  severity="Critical"
                  findings={auth}
                  explanation={explanations.auth}
                  renderFinding={(f) => (
                    <div>
                      <div className="finding-url">{f.url || f}</div>
                      {f.issue && <div className="finding-detail">{f.issue}</div>}
                      {f.reason && <div className="finding-reason">{f.reason}</div>}
                    </div>
                  )}
                />
              )}

              {dirs.length > 0 && (
                <VulnCard
                  title="Exposed Directories / Paths"
                  severity="High"
                  findings={dirs}
                  explanation={explanations.directories}
                  renderFinding={(f) => (
                    <div>
                      <div className="finding-url">{f.url || f}</div>
                      {f.severity && <span className={`badge badge-${f.severity?.toLowerCase()}`}>{f.severity}</span>}
                      {f.description && <div className="finding-reason">{f.description}</div>}
                    </div>
                  )}
                />
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab: Headers */}
      {activeTab === "headers" && (
        <div className="tab-content">
          {headers.length === 0 ? (
            <div className="card all-clear">
              <span style={{ fontSize: 24 }}>✅</span>
              <strong>All security headers are present.</strong>
            </div>
          ) : (
            <div className="card">
              <div className="card-title">Security Header Issues ({headers.length})</div>
              {explanations.headers && (
                <div className="explanation-box">
                  <strong>Fix:</strong> {explanations.headers.fix}
                </div>
              )}
              <table className="header-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Header / Issue</th>
                    <th>Severity</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {headers.map((h, i) => (
                    <tr key={i}>
                      <td>{h.type}</td>
                      <td><code>{h.header}</code></td>
                      <td><span className={`badge badge-${h.severity?.toLowerCase()}`}>{h.severity}</span></td>
                      <td className="header-desc">{h.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab: URLs */}
      {activeTab === "urls" && (
        <div className="tab-content">
          <div className="card">
            <div className="card-title">Crawled URLs ({urls.length})</div>
            <ul className="full-url-list">
              {urls.map((u) => (
                <li key={u}>
                  <a href={u} target="_blank" rel="noreferrer">{u}</a>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default ResultsDashboard;
