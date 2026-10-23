import React, { useState, useEffect } from "react";
import { Database, Search, Filter, ShieldAlert, Eye, RefreshCw, X, FileText } from "lucide-react";
import { api } from "../api";

export default function AuditTrail() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = { limit: 50 };
      if (searchQuery.trim()) params.query = searchQuery.trim();
      if (decisionFilter !== "all") params.decision = decisionFilter;

      const res = await api.getAuditLogs(params);
      if (res.status === "success") {
        setLogs(res.logs || []);
        setTotal(res.total || 0);
      }
    } catch (err) {
      console.error("Failed to load audit trail:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [decisionFilter]);

  const handleSearch = (e) => {
    e.preventDefault();
    fetchLogs();
  };

  return (
    <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 space-y-6">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30">
              <Database className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Zero-Trust Forensics & Immutable Audit Trail</h1>
              <p className="text-xs text-slate-400">
                Cryptographically indexed audit trail storing all context vectors, device entropy, and policy decisions
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={fetchLogs}
          disabled={loading}
          className="btn-secondary text-xs py-2 px-3 self-start md:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh Audit Trail</span>
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="cyber-card p-4 border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row items-center justify-between gap-4">
        <form onSubmit={handleSearch} className="flex items-center gap-2 w-full sm:max-w-md">
          <div className="relative w-full">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by identity email, IP, or event ID..."
              className="cyber-input pl-9 py-2 text-xs"
            />
          </div>
          <button type="submit" className="btn-secondary text-xs py-2 px-3 shrink-0">
            Search
          </button>
        </form>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <span className="text-xs text-slate-400 shrink-0">Decision:</span>
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="cyber-input py-1.5 px-3 text-xs bg-slate-900 cursor-pointer"
          >
            <option value="all">All Policy Decisions</option>
            <option value="ALLOW">ALLOW (Safe Baseline)</option>
            <option value="CHALLENGE_MFA">CHALLENGE_MFA (Step-Up)</option>
            <option value="DENY_QUARANTINE">DENY_QUARANTINE (Critical Violation)</option>
            <option value="DENY_RATE_LIMIT">DENY_RATE_LIMIT (Brute Force)</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="cyber-card p-6 border-slate-800">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
          <span className="text-xs font-semibold text-slate-300">
            Total Captured Events: <strong className="text-amber-400 font-mono">{total}</strong>
          </span>
          <span className="text-[11px] text-slate-500 font-mono">NIST SP 800-207 Audit Standard</span>
        </div>

        {loading ? (
          <div className="text-center py-12 text-slate-400 font-mono text-xs">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-amber-400" />
            <span>Querying Immutable Event Store...</span>
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs font-mono">
            No audit records matching query parameters found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Identity Email</th>
                  <th className="py-2.5 px-3">Resolved Origin</th>
                  <th className="py-2.5 px-3">Client IP</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">PDP Policy Decision</th>
                  <th className="py-2.5 px-3">Forensic Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 px-3 text-slate-400 text-[11px]">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-3 font-semibold text-white">
                      {log.email}
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      {log.location}
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {log.ip}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`font-bold ${log.risk_score >= 71 ? "text-red-400" : log.risk_score >= 31 ? "text-amber-400" : "text-emerald-400"}`}>
                        {log.risk_score} / 100
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      {log.decision === "ALLOW" && <span className="badge-allow">ALLOW</span>}
                      {log.decision === "CHALLENGE_MFA" && <span className="badge-challenge">CHALLENGE MFA</span>}
                      {(log.decision === "DENY_QUARANTINE" || log.decision === "DENY_RATE_LIMIT") && (
                        <span className="badge-deny">DENY & QUARANTINE</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <button
                        onClick={() => setSelectedEvent(log)}
                        className="btn-secondary text-[11px] py-1 px-2.5 flex items-center gap-1.5"
                        title="View Full JSON Context Vectors"
                      >
                        <Eye className="w-3 h-3 text-amber-400" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Forensic Evidence Modal */}
      {selectedEvent && (
        <div className="modal-overlay">
          <div className="cyber-card p-6 sm:p-8 max-w-2xl w-full border-slate-700 max-h-[85vh] overflow-y-auto">
            
            <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-4">
              <div className="flex items-center gap-2.5">
                <FileText className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-bold text-white">Forensic Context Inspector</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 font-mono text-xs">
              <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div>
                  <span className="text-slate-500 block text-[10px]">EVENT ID</span>
                  <span className="text-slate-200">{selectedEvent.event_id || selectedEvent.id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">TIMESTAMP</span>
                  <span className="text-slate-200">{selectedEvent.timestamp}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">IDENTITY EMAIL</span>
                  <span className="text-amber-400 font-bold">{selectedEvent.email}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">DECISION & RISK</span>
                  <span className="text-white font-bold">{selectedEvent.decision} ({selectedEvent.risk_score}/100)</span>
                </div>
              </div>

              {selectedEvent.threat_vectors && selectedEvent.threat_vectors.length > 0 && (
                <div>
                  <span className="text-slate-400 font-bold block mb-2">Evaluated Threat Vectors:</span>
                  <div className="space-y-2">
                    {selectedEvent.threat_vectors.map((tv, idx) => (
                      <div key={idx} className="p-3 rounded bg-slate-950/80 border border-slate-800 text-[11px] space-y-1">
                        <div className="flex justify-between font-bold">
                          <span className="text-red-400">{tv.vector}</span>
                          <span className="text-amber-400 font-mono">Weight: +{tv.weight}</span>
                        </div>
                        <p className="text-slate-300">{tv.details}</p>
                        {tv.metrics && (
                          <div className="text-slate-500 text-[10px] pt-1">
                            Metrics: {JSON.stringify(tv.metrics)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <span className="text-slate-400 font-bold block mb-2">Full Immutable Document:</span>
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto text-[11px] text-emerald-400">
                  <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="btn-secondary text-xs"
              >
                Close Inspector
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
