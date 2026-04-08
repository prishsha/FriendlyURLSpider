import { useState, useRef, useEffect } from "react";
import "./Chatbot.css";

function Chatbot({ jobId }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      from: "bot",
      text: "Hi! I'm the WebSpidey assistant. Ask me about the scan results or any vulnerability type. Try 'show risk score' or 'what is XSS'.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    if (open && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, open]);

  const send = async () => {
    const text = input.trim();
    if (!text || loading) return;

    setMessages((prev) => [...prev, { from: "user", text }]);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, job_id: jobId }),
      });
      const data = await res.json();
      setMessages((prev) => [...prev, { from: "bot", text: data.reply }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { from: "bot", text: "Error connecting to chatbot." },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  // Quick question buttons
  const quickQuestions = [
    "show risk score",
    "how many XSS issues",
    "what is SQL injection",
    "show summary",
  ];

  return (
    <>
      {/* Floating button */}
      <button
        className="chat-fab"
        onClick={() => setOpen(!open)}
        title="Open chatbot"
      >
        {open ? "✕" : "💬"}
      </button>

      {open && (
        <div className="chat-window">
          <div className="chat-header">
            <span>Chatbot</span>
            <button className="chat-close" onClick={() => setOpen(false)}>✕</button>
          </div>

          <div className="chat-messages">
            {messages.map((msg, i) => (
              <div key={i} className={`chat-msg ${msg.from}`}>
                <pre className="chat-msg-text">{msg.text}</pre>
              </div>
            ))}
            {loading && (
              <div className="chat-msg bot">
                <span className="chat-msg-text typing">...</span>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <div className="quick-questions">
            {quickQuestions.map((q) => (
              <button
                key={q}
                className="quick-btn"
                onClick={() => { setInput(q); }}
              >
                {q}
              </button>
            ))}
          </div>

          <div className="chat-input-row">
            <input
              className="chat-input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Ask about the scan..."
              disabled={loading}
            />
            <button className="btn-primary chat-send" onClick={send} disabled={loading}>
              Send
            </button>
          </div>
        </div>
      )}
    </>
  );
}

export default Chatbot;
