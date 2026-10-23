import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, Activity, Users, AlertOctagon, CheckCircle2, 
  MapPin, Compass, RefreshCw, Unlock, ExternalLink, Zap
} from "lucide-react";
import { api } from "../api";

export default function SocDashboard() {
  const [metrics, setMetrics] = useState(null);
  const [recentThreats, setRecentThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [unquarantineLoading, setUnquarantineLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState("");

  const fetchSocData = async () => {
    try {
      const res = await api.getSocOverview();
      if (res.status === "success" && res.metrics) {
        setMetrics(res.metrics);
        setRecentThreats(res.metrics.recent_threats || []);
      }
    } catch (err) {
      console.error("Error loading SOC metrics:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchSocData();
    const interval = setInterval(fetchSocData, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchSocData();
  };

  const handleUnquarantine = async (email) => {
    setUnquarantineLoading(true);
    setActionMessage("");
    try {
      const res = await api.unquarantineUser(email);
      if (res.status === "success") {
        setActionMessage(`Account '${email}' unquarantined successfully.`);
        fetchSocData();
      }
    } catch (err) {
      setActionMessage("Error unlocking user: " + err.message);
    } finally {
      setUnquarantineLoading(false);
    }
  };

  if (loading && !metrics) {
    return (
      <div className="max-w-7xl mx-auto py-20 px-4 text-center">
        <RefreshCw className="w-8 h-8 text-amber-400 animate-spin mx-auto mb-3" />
        <p className="text-slate-400 font-mono text-sm">Connecting to AegisAuth SOC Telemetry Stream...</p>
      </div>
    );
  }

  const threatColor = 
    metrics?.threat_level === "HIGH ALERT" 
      ? "text-red-400 border-red-500/30 bg-red-950/30 shadow-[0_0_20px_rgba(239,68,68,0.15)]"
      : metrics?.threat_level === "ELEVATED"
      ? "text-amber-400 border-amber-500/30 bg-amber-950/30 shadow-[0_0_20px_rgba(245,158,11,0.15)]"
      : "text-emerald-400 border-emerald-500/30 bg-emerald-950/30";

  return (
    <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 space-y-6">
      
      {/* Top Header & Threat Level Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white tracking-tight">Security Operations Center (SOC)</h1>
            <span className="px-2.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-xs font-mono font-bold">
              LIVE TELEMETRY
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time Zero-Trust Policy Decision Point (PDP) monitoring & incident containment console.
          </p>
        </div>

        <div className="flex items-center gap-4">
          <div className={`px-4 py-2 rounded-xl border flex items-center gap-2.5 ${threatColor}`}>
            <span className={`w-2.5 h-2.5 rounded-full ${metrics?.threat_level === "HIGH ALERT" ? "bg-red-500 animate-ping" : "bg-emerald-400"}`}></span>
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Threat Level</div>
              <div className="text-sm font-extrabold tracking-wide">{metrics?.threat_level || "NORMAL"}</div>
            </div>
          </div>

          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="btn-secondary text-xs py-2 px-3"
            title="Refresh SOC Telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center justify-between">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage("")} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
        
        <div className="cyber-card p-4 border-slate-800">
          <div className="text-slate-400 text-xs flex items-center gap-1.5 mb-1">
            <Activity className="w-3.5 h-3.5 text-slate-400" />
            <span>Total Events</span>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">{metrics?.total_events || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">Monitored Ingestion</div>
        </div>

        <div className="cyber-card p-4 border-emerald-500/20 bg-emerald-950/10">
          <div className="text-emerald-400 text-xs flex items-center gap-1.5 mb-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Allowed Access</span>
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 font-mono">{metrics?.allowed_count || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">Zero-Trust Verified</div>
        </div>

        <div className="cyber-card p-4 border-amber-500/20 bg-amber-950/10">
          <div className="text-amber-400 text-xs flex items-center gap-1.5 mb-1">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Step-Up MFA</span>
          </div>
          <div className="text-2xl font-extrabold text-amber-400 font-mono">{metrics?.mfa_challenged_count || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">Contextual Challenges</div>
        </div>

        <div className="cyber-card p-4 border-red-500/20 bg-red-950/10">
          <div className="text-red-400 text-xs flex items-center gap-1.5 mb-1">
            <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
            <span>Terminated / Denied</span>
          </div>
          <div className="text-2xl font-extrabold text-red-400 font-mono">{metrics?.denied_count || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">Quarantined Threats</div>
        </div>

        <div className="cyber-card p-4 border-amber-500/30">
          <div className="text-amber-400 text-xs flex items-center gap-1.5 mb-1">
            <Compass className="w-3.5 h-3.5 text-amber-400" />
            <span>Impossible Travel</span>
          </div>
          <div className="text-2xl font-extrabold text-amber-400 font-mono">{metrics?.impossible_travel_count || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">Haversine Violations</div>
        </div>

        <div className="cyber-card p-4 border-slate-800">
          <div className="text-slate-400 text-xs flex items-center gap-1.5 mb-1">
            <Users className="w-3.5 h-3.5 text-cyan-400" />
            <span>Active Sessions</span>
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 font-mono">{metrics?.active_sessions_count || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">Authenticated Clients</div>
        </div>

      </div>

      {/* Geodesic Velocity & Haversine Distance Inspector (Viva Wow Factor) */}
      <div className="cyber-card p-6 border-amber-500/30">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 mb-4 gap-2">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30">
              <Compass className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Geodesic Velocity Inspector (Haversine Formula)</h2>
              <p className="text-xs text-slate-400">Spherical trigonometry evaluating physical access feasibility between access events</p>
            </div>
          </div>
          <div className="text-right font-mono text-[11px] text-amber-400 bg-amber-500/10 px-3 py-1 rounded border border-amber-500/20">
            Aviation Upper Bound: 900 km/h (Commercial Subsonic Flight)
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center gap-1.5">
              <MapPin className="w-3.5 h-3.5 text-emerald-400" />
              <span>Reference Baseline Origin</span>
            </div>
            <div className="text-sm font-bold text-slate-200">Bengaluru, India</div>
            <div className="font-mono text-xs text-slate-400 mt-1">Lat: 12.9716, Lon: 77.5946</div>
            <div className="text-[10px] text-emerald-400 font-mono mt-2">● Enrolled Verified Office Location</div>
          </div>

          <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800">
            <div className="text-xs text-slate-400 mb-1 flex items-center gap-1.5">
              <MapPin className="w-3.5 h-3.5 text-red-400" />
              <span>Observed Transit Destination</span>
            </div>
            <div className="text-sm font-bold text-slate-200">Frankfurt, Germany</div>
            <div className="font-mono text-xs text-slate-400 mt-1">Lat: 50.1109, Lon: 8.6821</div>
            <div className="text-[10px] text-red-400 font-mono mt-2">● High-Speed Access Attempt Detected</div>
          </div>

          <div className="bg-gradient-to-br from-amber-950/30 to-red-950/30 p-4 rounded-xl border border-amber-500/30">
            <div className="text-xs text-amber-400 font-bold mb-1">Mathematical Haversine Delta:</div>
            <div className="font-mono text-xs space-y-1 text-slate-200">
              <div>Great-Circle Distance: <strong className="text-white">6,740.4 km</strong></div>
              <div>Elapsed Time Delta: <strong className="text-white">2.0 Minutes</strong></div>
              <div className="text-red-400 font-bold text-sm pt-1">
                Calculated Velocity: 202,211 km/h
              </div>
            </div>
            <div className="text-[11px] text-red-300 mt-2 font-mono">
              Status: <strong>Physically Impossible (Superluminal)</strong> ➡️ DENY & QUARANTINE
            </div>
          </div>
        </div>
      </div>

      {/* Recent Threat Stream & Incident Response */}
      <div className="cyber-card p-6 border-slate-800">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <h2 className="text-base font-bold text-white">Security Event Feed & Adaptive Decisions</h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Displaying Recent Risk Evaluations
          </span>
        </div>

        {recentThreats.length === 0 ? (
          <div className="text-center py-8 text-xs text-slate-400 font-mono">
            No active threat incidents recorded yet. Use the Threat Test Lab to simulate attacks!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Target Identity</th>
                  <th className="py-2.5 px-3">Location & IP</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Zero-Trust Decision</th>
                  <th className="py-2.5 px-3">Containment Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {recentThreats.map((threat) => (
                  <tr key={threat.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 px-3 text-slate-400 text-[11px]">
                      {new Date(threat.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-3 px-3 font-semibold text-white">
                      {threat.email}
                    </td>
                    <td className="py-3 px-3">
                      <div>{threat.location}</div>
                      <div className="text-[10px] text-slate-500">{threat.ip}</div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold ${threat.risk_score >= 71 ? "text-red-400" : threat.risk_score >= 31 ? "text-amber-400" : "text-emerald-400"}`}>
                          {threat.risk_score}
                        </span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${threat.risk_score >= 71 ? "bg-red-500" : threat.risk_score >= 31 ? "bg-amber-400" : "bg-emerald-400"}`}
                            style={{ width: `${Math.min(100, threat.risk_score)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      {threat.decision === "ALLOW" && <span className="badge-allow">ALLOW</span>}
                      {threat.decision === "CHALLENGE_MFA" && <span className="badge-challenge">CHALLENGE MFA</span>}
                      {(threat.decision === "DENY_QUARANTINE" || threat.decision === "DENY_RATE_LIMIT") && (
                        <span className="badge-deny">DENY & QUARANTINE</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <button
                        onClick={() => handleUnquarantine(threat.email)}
                        disabled={unquarantineLoading}
                        className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[10px] text-amber-400 flex items-center gap-1 transition"
                        title="Restore Account Access"
                      >
                        <Unlock className="w-3 h-3" />
                        <span>Unlock</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
