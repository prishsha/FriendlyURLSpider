import { useState } from "react";
import "./ScanForm.css";

const EXAMPLE_URLS = [
  "http://localhost:9000",
  "http://testphp.vulnweb.com",
  "http://zero.webappsecurity.com",
];

function ScanForm({ onScan }) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    const trimmed = url.trim();

    if (!trimmed) {
      setError("Please enter a URL.");
      return;
    }
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      setError("URL must start with http:// or https://");
      return;
    }

    setError("");
    onScan(trimmed);
  };

  return (
    <div className="scan-form-container">
      <form className="scan-form" onSubmit={handleSubmit}>
        <div className="scan-input-row">
          <input
            type="text"
            className="scan-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            spellCheck={false}
          />
          <button type="submit" className="btn-primary scan-btn">
            Start Scan
          </button>
        </div>
        {error && <div className="scan-error">{error}</div>}
      </form>

      <div className="example-urls">
        <span className="example-label">Try:</span>
        {EXAMPLE_URLS.map((u) => (
          <button
            key={u}
            className="example-url-btn"
            onClick={() => setUrl(u)}
            type="button"
          >
            {u}
          </button>
        ))}
      </div>
    </div>
  );
}

export default ScanForm;
