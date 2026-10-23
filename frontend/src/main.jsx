import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("AegisAuth ErrorBoundary caught:", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: "40px", color: "#ef4444", background: "#090d16", fontFamily: "monospace", minHeight: "100vh" }}>
          <h1 style={{ color: "#f59e0b", fontSize: "24px", marginBottom: "16px" }}>🛡️ AegisAuth React Component Error:</h1>
          <div style={{ background: "#131d31", padding: "20px", borderRadius: "10px", border: "1px solid #ef4444", color: "#f87171", fontSize: "14px", lineHeight: "1.6" }}>
            <strong>Message:</strong> {this.state.error?.message || String(this.state.error)}
            <pre style={{ marginTop: "12px", whiteSpace: "pre-wrap", color: "#94a3b8", fontSize: "12px" }}>
              {this.state.error?.stack}
            </pre>
          </div>
          <button 
            onClick={() => { localStorage.clear(); window.location.reload(); }}
            style={{ marginTop: "20px", background: "#d97706", color: "#fff", border: "none", padding: "10px 20px", borderRadius: "6px", cursor: "pointer", fontWeight: "bold" }}
          >
            Clear Cache &amp; Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

const rootElement = document.getElementById("root");

if (rootElement) {
  try {
    const root = ReactDOM.createRoot(rootElement);
    root.render(
      <React.StrictMode>
        <ErrorBoundary>
          <App />
        </ErrorBoundary>
      </React.StrictMode>
    );
  } catch (err) {
    console.error("Fatal Root Mount Error:", err);
  }
}
