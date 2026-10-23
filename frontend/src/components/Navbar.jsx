import React from "react";
import { Shield, Activity, Terminal, Database, LogOut, UserCheck } from "lucide-react";

export default function Navbar({ activeTab, setActiveTab, currentUser, onLogout, systemOnline }) {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand & NIST Architecture Standard */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-600 to-amber-400 p-0.5 flex items-center justify-center shadow-lg shadow-amber-500/20">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-amber-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-lg tracking-wider text-white">AEGIS<span className="text-amber-400">AUTH</span></span>
              <span className="text-[10px] px-2 py-0.5 font-bold rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 tracking-wider">
                ZTA PDP
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium tracking-tight">
              Zero-Trust Identity Threat Detection • NIST SP 800-207
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1">
          <button
            onClick={() => setActiveTab("portal")}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all ${
              activeTab === "portal"
                ? "bg-amber-500/15 text-amber-400 border border-amber-500/30 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>Access Portal</span>
          </button>

          <button
            onClick={() => setActiveTab("soc")}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all ${
              activeTab === "soc"
                ? "bg-amber-500/15 text-amber-400 border border-amber-500/30 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>SOC Console</span>
          </button>

          <button
            onClick={() => setActiveTab("simulator")}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all ${
              activeTab === "simulator"
                ? "bg-amber-500/15 text-amber-400 border border-amber-500/30 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Threat Test Lab</span>
          </button>

          <button
            onClick={() => setActiveTab("audit")}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all ${
              activeTab === "audit"
                ? "bg-amber-500/15 text-amber-400 border border-amber-500/30 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Database className="w-4 h-4" />
            <span>Forensics Audit</span>
          </button>
        </nav>

        {/* User Session & System Status */}
        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center gap-2 text-xs">
            <span className={`w-2 h-2 rounded-full ${systemOnline ? "bg-emerald-400 shadow-[0_0_8px_#34d399]" : "bg-red-500"}`}></span>
            <span className="text-slate-400 font-mono text-[11px]">{systemOnline ? "PDP ONLINE" : "OFFLINE"}</span>
          </div>

          {currentUser ? (
            <div className="flex items-center gap-3 pl-3 border-l border-slate-800">
              <div className="text-right">
                <div className="text-xs font-bold text-slate-200">{currentUser.name}</div>
                <div className="text-[10px] text-amber-400/90 font-mono capitalize">{currentUser.role}</div>
              </div>
              <button
                onClick={onLogout}
                title="Terminate Session"
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-red-950/40 text-slate-400 hover:text-red-400 border border-slate-800 transition"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="text-xs text-slate-500 flex items-center gap-1 font-mono">
              <UserCheck className="w-3.5 h-3.5 text-slate-400" />
              <span>UNAUTHENTICATED</span>
            </div>
          )}
        </div>

      </div>
    </header>
  );
}
