import { useState } from "react";
import "./VulnCard.css";

function VulnCard({ title, severity, findings, explanation, renderFinding }) {
  const [expanded, setExpanded] = useState(true);
  const [showExplain, setShowExplain] = useState(false);

  return (
    <div className="vuln-card">
      <div className="vuln-card-header" onClick={() => setExpanded(!expanded)}>
        <div className="vuln-card-left">
          <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>
          <span className="vuln-card-title">{title}</span>
          <span className="vuln-card-count">{findings.length} finding{findings.length !== 1 ? "s" : ""}</span>
        </div>
        <span className="vuln-card-toggle">{expanded ? "▲" : "▼"}</span>
      </div>

      {expanded && (
        <div className="vuln-card-body">
          {/* Findings */}
          <div className="vuln-findings">
            {findings.map((f, i) => (
              <div key={i} className="vuln-finding-item">
                {renderFinding ? renderFinding(f) : <div>{String(f)}</div>}
              </div>
            ))}
          </div>

          {/* Explainability section */}
          {explanation && (
            <div className="vuln-explain">
              <button
                className="explain-toggle"
                onClick={() => setShowExplain(!showExplain)}
              >
                {showExplain ? "▲ Hide explanation" : "▼ Why is this a vulnerability?"}
              </button>

              {showExplain && (
                <div className="explain-content">
                  <div className="explain-section">
                    <strong>Why it matters</strong>
                    <p>{explanation.why}</p>
                  </div>
                  <div className="explain-section">
                    <strong>How it was detected</strong>
                    <p>{explanation.how_detected}</p>
                  </div>
                  <div className="explain-section">
                    <strong>How to fix it</strong>
                    <p style={{ whiteSpace: "pre-line" }}>{explanation.fix}</p>
                  </div>
                  {explanation.reference && (
                    <div className="explain-ref">
                      Reference: {explanation.reference}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default VulnCard;
