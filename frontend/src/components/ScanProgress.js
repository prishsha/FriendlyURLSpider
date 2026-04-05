import { useEffect, useState } from "react";
import "./ScanProgress.css";

function ScanProgress({ jobId, targetUrl, onComplete, onError }) {
  const [progress, setProgress] = useState(0);
  const [log, setLog] = useState([]);
  const [status, setStatus] = useState("running");

  useEffect(() => {
    if (!jobId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/scan/${jobId}`);
        const data = await res.json();

        setProgress(data.progress || 0);
        setLog(data.log || []);
        setStatus(data.status);

        if (data.status === "done") {
          clearInterval(interval);
          onComplete(data);
        } else if (data.status === "error") {
          clearInterval(interval);
          onError();
        }
      } catch (err) {
        clearInterval(interval);
        onError();
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [jobId, onComplete, onError]);

  return (
    <div className="progress-container">
      <div className="progress-header">
        <h2>Scanning...</h2>
        <span className="progress-url">{targetUrl}</span>
      </div>

      <div className="progress-bar-outer">
        <div
          className="progress-bar-inner"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="progress-percent">{progress}%</div>

      <div className="scan-log">
        <div className="scan-log-title">Scan log</div>
        {log.length === 0 && (
          <div className="log-line muted">Initializing...</div>
        )}
        {log.map((line, i) => (
          <div key={i} className={`log-line ${i === log.length - 1 ? "active" : ""}`}>
            <span className="log-arrow">&gt;</span> {line}
          </div>
        ))}
      </div>

      <div className="progress-note">
        This may take 30-60 seconds depending on the target site.
      </div>
    </div>
  );
}

export default ScanProgress;
