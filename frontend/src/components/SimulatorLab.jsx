import React, { useState } from "react";
import { 
  Terminal, Compass, ShieldAlert, Cpu, RotateCcw, 
  Play, CheckCircle2, AlertTriangle, ArrowRight, Zap, Code
} from "lucide-react";
import { api } from "../api";

export default function SimulatorLab() {
  const [targetEmail, setTargetEmail] = useState("analyst@aegisauth.local");
  const [travelMinutes, setTravelMinutes] = useState(2.0);
  const [bruteForceAttempts, setBruteForceAttempts] = useState(6);
  const [activeScenario, setActiveScenario] = useState(null);
  const [loadingScenario, setLoadingScenario] = useState("");
  const [consoleOutput, setConsoleOutput] = useState(null);
  const [resetMessage, setResetMessage] = useState("");

  const handleSimulateTravel = async () => {
    setLoadingScenario("travel");
    setActiveScenario("travel");
    setResetMessage("");
    setConsoleOutput(null);

    try {
      const res = await api.simulateImpossibleTravel({
        email: targetEmail,
        origin_ip: "103.21.124.1",      // Bengaluru, India
        destination_ip: "194.154.200.1", // Frankfurt, Germany
        time_delta_minutes: parseFloat(travelMinutes)
      });
      setConsoleOutput(res);
    } catch (err) {
      setConsoleOutput({ error: err.message });
    } finally {
      setLoadingScenario("");
    }
  };

  const handleSimulateBruteForce = async () => {
    setLoadingScenario("brute");
    setActiveScenario("brute");
    setResetMessage("");
    setConsoleOutput(null);

    try {
      const res = await api.simulateBruteForce({
        email: targetEmail,
        attacker_ip: "45.33.32.156",
        attempts: parseInt(bruteForceAttempts)
      });
      setConsoleOutput(res);
    } catch (err) {
      setConsoleOutput({ error: err.message });
    } finally {
      setLoadingScenario("");
    }
  };

  const handleSimulateUnfamiliarDevice = async () => {
    setLoadingScenario("device");
    setActiveScenario("device");
    setResetMessage("");
    setConsoleOutput(null);

    try {
      const res = await api.simulateUnrecognizedDevice({
        email: targetEmail,
        ip: "103.21.124.1"
      });
      setConsoleOutput(res);
    } catch (err) {
      setConsoleOutput({ error: err.message });
    } finally {
      setLoadingScenario("");
    }
  };

  const handleResetDemo = async () => {
    setLoadingScenario("reset");
    try {
      const res = await api.resetDemo(targetEmail);
      if (res.status === "success") {
        setResetMessage(`Test account '${targetEmail}' & sliding rate-limits successfully reset to ACTIVE.`);
        setConsoleOutput(null);
      }
    } catch (err) {
      setResetMessage("Reset error: " + err.message);
    } finally {
      setLoadingScenario("");
    }
  };

  return (
    <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 space-y-6">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30">
              <Terminal className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Zero-Trust Threat Test Lab</h1>
              <p className="text-xs text-slate-400">
                Interactive Attack Simulation Suite for MCA Viva Demonstration & Examiner Verification
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleResetDemo}
            disabled={loadingScenario === "reset"}
            className="btn-secondary text-xs py-2 px-3.5 border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
            title="Reset target account back to clean baseline state"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loadingScenario === "reset" ? "animate-spin" : ""}`} />
            <span>Reset Demo State</span>
          </button>
        </div>
      </div>

      {resetMessage && (
        <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{resetMessage}</span>
          </div>
          <button onClick={() => setResetMessage("")} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Target Account Config */}
      <div className="cyber-card p-4 border-slate-800 bg-slate-950/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Target User Identity for Simulations:</span>
          <input
            type="email"
            value={targetEmail}
            onChange={(e) => setTargetEmail(e.target.value)}
            className="cyber-input py-1.5 px-3 max-w-[260px] font-mono text-xs"
          />
        </div>
        <div className="text-slate-500 font-mono text-[11px]">
          Sliding-Window Rate Tracking Active (10-min window)
        </div>
      </div>

      {/* 3 Interactive Attack Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Scenario 1: Impossible Travel */}
        <div className="cyber-card p-6 border-amber-500/30 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <div className="flex items-center gap-2">
                <Compass className="w-4 h-4 text-amber-400" />
                <span className="font-bold text-white text-sm">Scenario 1: Impossible Travel</span>
              </div>
              <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded font-mono font-bold">
                HAVERSINE
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Simulates a login attempt in Frankfurt, Germany immediately after legitimate access in Bengaluru, India.
            </p>

            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-2 text-xs font-mono mb-4">
              <div className="flex justify-between">
                <span className="text-slate-400">Origin:</span>
                <span className="text-emerald-400">Bengaluru (India)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Destination:</span>
                <span className="text-red-400">Frankfurt (Germany)</span>
              </div>
              <div className="flex justify-between items-center pt-1 border-t border-slate-800">
                <span className="text-slate-400">Time Gap:</span>
                <div className="flex items-center gap-1">
                  <input
                    type="number"
                    min="1"
                    max="60"
                    value={travelMinutes}
                    onChange={(e) => setTravelMinutes(e.target.value)}
                    className="cyber-input py-1 px-2 w-16 text-center text-xs"
                  />
                  <span className="text-slate-400 text-[10px]">mins</span>
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={handleSimulateTravel}
            disabled={loadingScenario === "travel"}
            className="btn-primary w-full text-xs py-2.5 justify-center"
          >
            {loadingScenario === "travel" ? "Executing Haversine Engine..." : "Simulate Impossible Travel"}
            <Play className="w-3.5 h-3.5 ml-1" />
          </button>
        </div>

        {/* Scenario 2: Brute Force */}
        <div className="cyber-card p-6 border-red-500/30 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <span className="font-bold text-white text-sm">Scenario 2: Credential Brute Force</span>
              </div>
              <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded font-mono font-bold">
                RATE LIMIT
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Simulates a rapid burst of failed authentication attempts from a botnet IP to trigger sliding-window quarantine.
            </p>

            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-2 text-xs font-mono mb-4">
              <div className="flex justify-between">
                <span className="text-slate-400">Attacker IP:</span>
                <span className="text-amber-400">45.33.32.156</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Lockout Threshold:</span>
                <span className="text-slate-200">5 Failed Logins</span>
              </div>
              <div className="flex justify-between items-center pt-1 border-t border-slate-800">
                <span className="text-slate-400">Burst Attempts:</span>
                <div className="flex items-center gap-1">
                  <input
                    type="number"
                    min="3"
                    max="10"
                    value={bruteForceAttempts}
                    onChange={(e) => setBruteForceAttempts(e.target.value)}
                    className="cyber-input py-1 px-2 w-16 text-center text-xs"
                  />
                  <span className="text-slate-400 text-[10px]">tries</span>
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={handleSimulateBruteForce}
            disabled={loadingScenario === "brute"}
            className="btn-danger w-full text-xs py-2.5 justify-center flex items-center gap-1"
          >
            {loadingScenario === "brute" ? "Flooding Sliding Window..." : "Launch Brute Force Burst"}
            <Play className="w-3.5 h-3.5 ml-1" />
          </button>
        </div>

        {/* Scenario 3: Unfamiliar Device Entropy */}
        <div className="cyber-card p-6 border-cyan-500/30 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-white text-sm">Scenario 3: Unfamiliar Device</span>
              </div>
              <span className="text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded font-mono font-bold">
                ADAPTIVE MFA
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Simulates access from an unverified hardware profile (different cores, screen, GPU) from a valid IP address.
            </p>

            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-2 text-xs font-mono mb-4">
              <div className="flex justify-between">
                <span className="text-slate-400">Hardware Profile:</span>
                <span className="text-cyan-400">Linux 16-Core</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Origin IP:</span>
                <span className="text-emerald-400">Bengaluru (Known)</span>
              </div>
              <div className="flex justify-between pt-1 border-t border-slate-800">
                <span className="text-slate-400">Zero-Trust Action:</span>
                <span className="text-amber-400 font-bold">Step-Up MFA (35/100)</span>
              </div>
            </div>
          </div>

          <button
            onClick={handleSimulateUnfamiliarDevice}
            disabled={loadingScenario === "device"}
            className="btn-secondary w-full text-xs py-2.5 justify-center border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10"
          >
            {loadingScenario === "device" ? "Hashing Device Entropy..." : "Test Unknown Hardware"}
            <Zap className="w-3.5 h-3.5 ml-1 text-cyan-400" />
          </button>
        </div>

      </div>

      {/* Live Math & JSON Execution Terminal (Viva Defense Console) */}
      <div className="cyber-card p-6 border-slate-800 bg-slate-950/90 font-mono">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
          <div className="flex items-center gap-2">
            <Code className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-bold text-white">Policy Decision Point (PDP) Evidence & Telemetry Output</h2>
          </div>
          <span className="text-[11px] text-slate-500">Live Mathematical Verification</span>
        </div>

        {consoleOutput ? (
          <div className="space-y-4">
            
            {/* Structured Evidence Highlight */}
            {consoleOutput.mathematical_breakdown && (
              <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-200 space-y-2">
                <div className="font-bold text-amber-400 text-sm flex items-center gap-2">
                  <Compass className="w-4 h-4" />
                  <span>Mathematical Haversine Formula Verification:</span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2">
                  <div>
                    <span className="text-slate-400 block text-[10px]">Great Circle Distance:</span>
                    <strong className="text-white text-sm">{consoleOutput.mathematical_breakdown.distance_km} km</strong>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Elapsed Time:</span>
                    <strong className="text-white text-sm">{consoleOutput.mathematical_breakdown.elapsed_minutes} mins</strong>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Computed Velocity:</span>
                    <strong className="text-red-400 text-sm font-bold">{consoleOutput.mathematical_breakdown.calculated_speed_kmh} km/h</strong>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Commercial Flight Limit:</span>
                    <strong className="text-slate-300 text-sm">{consoleOutput.mathematical_breakdown.threshold_kmh} km/h</strong>
                  </div>
                </div>
                <div className="text-[11px] text-slate-300 pt-2 border-t border-amber-500/20">
                  Formula: <code className="text-amber-300">{consoleOutput.mathematical_breakdown.formula}</code>
                </div>
              </div>
            )}

            {/* Raw JSON Response */}
            <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800 text-xs overflow-x-auto text-emerald-400 max-h-96">
              <pre>{JSON.stringify(consoleOutput, null, 2)}</pre>
            </div>
          </div>
        ) : (
          <div className="text-center py-10 text-slate-500 text-xs">
            Run any attack scenario above to see live Zero-Trust PDP evaluation evidence.
          </div>
        )}
      </div>

    </div>
  );
}
