import { useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanProgress from "./components/ScanProgress";
import ResultsDashboard from "./components/ResultsDashboard";
import Chatbot from "./components/Chatbot";
import "./App.css";

function App() {
  const [jobId, setJobId] = useState(null);
  const [scanStatus, setScanStatus] = useState("idle"); // idle | running | done | error
  const [results, setResults] = useState(null);
  const [targetUrl, setTargetUrl] = useState("");

  const handleScanStart = async (url) => {
    setTargetUrl(url);
    setScanStatus("running");
    setResults(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (data.job_id) {
        setJobId(data.job_id);
      } else {
        setScanStatus("error");
      }
    } catch (err) {
      setScanStatus("error");
    }
  };

  const handleScanComplete = (jobData) => {
    setResults(jobData);
    setScanStatus("done");
  };

  const handleReset = () => {
    setJobId(null);
    setScanStatus("idle");
    setResults(null);
    setTargetUrl("");
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-inner">
          <div className="logo">
            <span className="logo-text">Web App Vulnerability Scanner</span>
          </div>
        </div>
      </header>

      <main className="main-content">
        {scanStatus === "idle" && (
          <div className="landing">
            <div className="landing-hero">
              <h1>Scan your web app for vulnerabilities</h1>
            </div>
            <ScanForm onScan={handleScanStart} />
          </div>
        )}

        {scanStatus === "running" && jobId && (
          <ScanProgress
            jobId={jobId}
            targetUrl={targetUrl}
            onComplete={handleScanComplete}
            onError={() => setScanStatus("error")}
          />
        )}

        {scanStatus === "done" && results && (
          <ResultsDashboard
            results={results.results}
            urls={results.urls}
            targetUrl={results.target_url}
            jobId={jobId}
            onReset={handleReset}
          />
        )}

        {scanStatus === "error" && (
          <div className="error-screen">
            <h2>Scan failed</h2>
            <p>Could not connect to the target or an internal error occurred.</p>
            <button className="btn-primary" onClick={handleReset}>Try Again</button>
          </div>
        )}
      </main>

      {scanStatus === "done" && results && (
        <Chatbot jobId={jobId} />
      )}
    </div>
  );
}

export default App;
