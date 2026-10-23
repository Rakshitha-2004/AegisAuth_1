import React, { useState, useEffect } from "react";
import { 
  ShieldCheck, Lock, Mail, Globe, Eye, EyeOff, 
  ArrowRight, CheckCircle2, ShieldAlert, Cpu, AlertTriangle, RefreshCw
} from "lucide-react";
import { harvestClientFingerprint } from "../utils/fingerprint";
import { api } from "../api";

export default function AccessPortal({ currentUser, setCurrentUser, onLoginSuccess }) {
  const [email, setEmail] = useState("analyst@aegisauth.local");
  const [password, setPassword] = useState("SecurePassword123!");
  const [simulatedLocation, setSimulatedLocation] = useState("local");
  const [showPassword, setShowPassword] = useState(false);
  const [fingerprint, setFingerprint] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  // Step-Up MFA Challenge State
  const [mfaChallenge, setMfaChallenge] = useState(null);
  const [otpCode, setOtpCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);
  const [mfaError, setMfaError] = useState("");

  // Quarantine Lockdown State
  const [quarantineAlert, setQuarantineAlert] = useState(null);

  // Registration Toggle
  const [isRegistering, setIsRegistering] = useState(false);
  const [regName, setRegName] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regRole, setRegRole] = useState("analyst");
  const [regSuccess, setRegSuccess] = useState("");

  useEffect(() => {
    const fp = harvestClientFingerprint();
    setFingerprint(fp);
  }, []);

  const handleAutofill = (type) => {
    setErrorMsg("");
    if (type === "analyst") {
      setEmail("analyst@aegisauth.local");
      setPassword("SecurePassword123!");
      setSimulatedLocation("local");
    } else if (type === "travel") {
      setEmail("analyst@aegisauth.local");
      setPassword("SecurePassword123!");
      setSimulatedLocation("frankfurt");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setErrorMsg("");
    setQuarantineAlert(null);
    setMfaChallenge(null);
    setLoading(true);

    try {
      const payload = {
        email,
        password,
        simulated_location: simulatedLocation,
        fingerprint: fingerprint || {}
      };

      const res = await api.login(payload);

      if (res.status === "allow" || res.status === "success" || res.decision === "ALLOW") {
        localStorage.setItem("aegis_token", res.token);
        localStorage.setItem("aegis_user", JSON.stringify(res.user));
        if (onLoginSuccess) onLoginSuccess(res.user);
      } else if (res.status === "challenge") {
        setMfaChallenge(res);
        if (res.dev_hint) {
          const match = res.dev_hint.match(/\b\d{6}\b/);
          if (match) setOtpCode(match[0]);
        }
      } else if (res.status === "quarantine") {
        setQuarantineAlert(res);
      } else {
        setErrorMsg(res.message || "Authentication rejected by Zero-Trust Policy.");
      }
    } catch (err) {
      setErrorMsg("Unable to reach Zero-Trust PDP server. Please ensure backend is active.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMfa = async (e) => {
    e.preventDefault();
    setMfaError("");
    setMfaLoading(true);

    try {
      const res = await api.verifyMfa({
        email,
        code: otpCode,
        otp_code: otpCode,
        mfa_token: mfaChallenge?.mfa_token
      });

      if (res.status === "success") {
        localStorage.setItem("aegis_token", res.token);
        localStorage.setItem("aegis_user", JSON.stringify(res.user));
        setMfaChallenge(null);
        if (onLoginSuccess) onLoginSuccess(res.user);
      } else {
        setMfaError(res.message || "Invalid verification code.");
      }
    } catch (err) {
      setMfaError("Verification failed. Please retry.");
    } finally {
      setMfaLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setErrorMsg("");
    setRegSuccess("");
    setLoading(true);

    try {
      const res = await api.register({
        name: regName,
        email: regEmail,
        password: regPassword,
        confirmPassword: regPassword,
        role: regRole,
        fingerprint: fingerprint || {}
      });

      if (res.status === "success") {
        setRegSuccess("Account enrolled in Zero-Trust Identity Store! You can now sign in.");
        setEmail(regEmail);
        setPassword(regPassword);
        setIsRegistering(false);
      } else {
        setErrorMsg(res.message || "Registration failed.");
      }
    } catch (err) {
      setErrorMsg("Failed to connect to enrollment service.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 flex flex-col items-center justify-center px-4 py-12 relative min-h-[calc(100vh-4rem)]">
      
      {/* Centered Luxury Glassmorphic Card */}
      <div className="cyber-card w-full max-w-[460px] p-8 sm:p-10 relative z-10 border border-amber-500/25 shadow-2xl">
        
        {/* Golden Lock Icon Crest */}
        <div className="text-center mb-6">
          <div className="w-14 h-14 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto mb-4 shadow-[0_0_20px_rgba(212,175,55,0.2)]">
            <Lock className="w-6 h-6 text-amber-400" />
          </div>
          
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mb-1.5">
            {isRegistering ? "Enroll Identity" : "Sign In to Console"}
          </h1>
          <p className="text-xs sm:text-sm text-slate-400">
            {isRegistering 
              ? "Register baseline device entropy and credentials" 
              : "Context-Aware Zero-Trust Identity Threat Detection (NIST SP 800-207)"}
          </p>
        </div>

        {/* Quick Demo Autofill Pills */}
        {!isRegistering && (
          <div className="flex items-center justify-center gap-2 mb-6">
            <button
              type="button"
              onClick={() => handleAutofill("analyst")}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-700 hover:border-amber-500/50 text-slate-300 hover:text-white transition-all flex items-center gap-1.5"
            >
              <span>⚡ Analyst Normal</span>
            </button>
            <button
              type="button"
              onClick={() => handleAutofill("travel")}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 hover:border-amber-400 text-amber-300 transition-all flex items-center gap-1.5"
            >
              <span>✈️ Frankfurt Travel</span>
            </button>
          </div>
        )}

        {/* Alert Messages */}
        {regSuccess && (
          <div className="alert-success mb-5">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>{regSuccess}</span>
          </div>
        )}

        {errorMsg && (
          <div className="alert-error mb-5">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Login / Registration Form */}
        {!isRegistering ? (
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  placeholder="analyst@aegisauth.local"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="form-input pl-10"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type={showPassword ? "text" : "password"}
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="form-input pl-10 pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-amber-400" />
                  <span>Access Origin Location (Viva Trigger)</span>
                </span>
                <span className="text-[10px] text-amber-400 font-mono">Geodesic Resolver</span>
              </label>
              <select
                value={simulatedLocation}
                onChange={(e) => setSimulatedLocation(e.target.value)}
                className="form-input cursor-pointer bg-slate-900 text-xs"
              >
                <option value="local">Bengaluru, India (Local Office Baseline - Normal)</option>
                <option value="frankfurt">Frankfurt, Germany (Simulate Impossible Travel - 28,000+ km/h)</option>
                <option value="new_york">New York, USA (Transatlantic Anomaly)</option>
                <option value="tokyo">Tokyo, Japan (Pacific Geo Deviation)</option>
                <option value="datacenter_aws">Ashburn AWS Datacenter (Hosting/Proxy Flag)</option>
              </select>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={loading}
                className="btn-gold w-full py-3.5 font-bold shadow-lg shadow-amber-500/20"
              >
                {loading ? (
                  <>
                    <div className="spin w-4 h-4 border-2 border-black border-t-transparent rounded-full" />
                    <span>Evaluating Zero-Trust Context...</span>
                  </>
                ) : (
                  <>
                    <span>Sign In to Console</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Full Name</label>
              <input
                type="text"
                required
                placeholder="Security Analyst"
                value={regName}
                onChange={(e) => setRegName(e.target.value)}
                className="form-input"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Email Address</label>
              <input
                type="email"
                required
                placeholder="analyst@organization.com"
                value={regEmail}
                onChange={(e) => setRegEmail(e.target.value)}
                className="form-input"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Secret Password</label>
              <input
                type="password"
                required
                placeholder="Minimum 8 characters"
                value={regPassword}
                onChange={(e) => setRegPassword(e.target.value)}
                className="form-input"
              />
            </div>
            <div className="pt-2">
              <button type="submit" disabled={loading} className="btn-gold w-full py-3 font-bold">
                {loading ? "Enrolling..." : "Enroll New Identity"}
              </button>
            </div>
          </form>
        )}

        {/* Toggle Register / Login */}
        <div className="mt-6 pt-5 border-t border-slate-800/80 text-center text-xs text-slate-400">
          {!isRegistering ? (
            <>
              Need to test a new account?{" "}
              <button
                type="button"
                onClick={() => setIsRegistering(true)}
                className="text-amber-400 hover:text-amber-300 font-semibold underline underline-offset-4 ml-1"
              >
                Enroll New Account
              </button>
            </>
          ) : (
            <>
              Already have credentials?{" "}
              <button
                type="button"
                onClick={() => setIsRegistering(false)}
                className="text-amber-400 hover:text-amber-300 font-semibold underline underline-offset-4 ml-1"
              >
                Back to Sign In
              </button>
            </>
          )}
        </div>

        {/* Sleek Live Hardware Telemetry Footer */}
        <div className="mt-5 pt-3 border-t border-slate-800/40 flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Entropy Engine Active</span>
          </span>
          <span className="font-mono text-amber-400/90 text-[10px]">
            {fingerprint ? `${fingerprint.cpu_cores || 4} Cores • ${fingerprint.timezone || 'UTC'}` : 'SHA-256 Non-Invasive'}
          </span>
        </div>

      </div>

      {/* STEP-UP MFA MODAL */}
      {mfaChallenge && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-md flex items-center justify-center p-4 z-50">
          <div className="cyber-card w-full max-w-md p-8 border-amber-500/40 shadow-2xl">
            <div className="text-center mb-6">
              <div className="w-14 h-14 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto mb-3 shadow-[0_0_20px_rgba(245,158,11,0.2)]">
                <ShieldCheck className="w-7 h-7 text-amber-400" />
              </div>
              <h2 className="text-xl font-bold text-white">Adaptive Step-Up Verification</h2>
              <p className="text-xs text-slate-400 mt-1">
                Zero-Trust PDP evaluated risk score: <strong className="text-amber-400">{mfaChallenge.risk_score}/100</strong>
              </p>
            </div>

            {mfaChallenge.dev_hint && (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 mb-5 text-center">
                <span className="text-[11px] font-semibold text-amber-400 block mb-0.5">Viva Demonstration Code:</span>
                <span className="font-mono text-lg font-bold tracking-widest text-amber-300">
                  {mfaChallenge.dev_hint.match(/\b\d{6}\b/)?.[0] || mfaChallenge.dev_hint}
                </span>
              </div>
            )}

            {mfaError && (
              <div className="alert-error mb-4 text-xs">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>{mfaError}</span>
              </div>
            )}

            <form onSubmit={handleVerifyMfa} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 text-center">
                  Enter 6-Digit Challenge Code
                </label>
                <input
                  type="text"
                  maxLength={6}
                  required
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ""))}
                  placeholder="000000"
                  className="form-input text-center text-2xl font-mono tracking-widest font-bold text-amber-400"
                />
              </div>

              <button type="submit" disabled={mfaLoading} className="btn-gold w-full py-3 font-bold">
                {mfaLoading ? "Verifying..." : "Confirm & Authorize Session"}
              </button>

              <button
                type="button"
                onClick={() => setMfaChallenge(null)}
                className="w-full text-center text-xs text-slate-400 hover:text-slate-200 pt-2"
              >
                Cancel Authentication
              </button>
            </form>
          </div>
        </div>
      )}

      {/* QUARANTINE LOCKDOWN MODAL */}
      {quarantineAlert && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-md flex items-center justify-center p-4 z-50">
          <div className="cyber-card w-full max-w-lg p-8 border-red-500/50 shadow-2xl">
            <div className="text-center mb-6">
              <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/40 flex items-center justify-center mx-auto mb-3 shadow-[0_0_25px_rgba(239,68,68,0.3)]">
                <ShieldAlert className="w-8 h-8 text-red-400" />
              </div>
              <span className="badge-high mb-2">ACCESS TERMINATED • QUARANTINE</span>
              <h2 className="text-2xl font-extrabold text-white mt-1">Zero-Trust Lockdown Triggered</h2>
              <p className="text-xs text-slate-300 mt-2">
                The Policy Decision Point (PDP) detected a severe anomalous threat vector.
              </p>
            </div>

            <div className="bg-red-950/40 border border-red-500/30 rounded-xl p-4 mb-6 space-y-2 text-xs">
              <div className="flex justify-between border-b border-red-500/20 pb-2">
                <span className="text-slate-400">Calculated Risk Score:</span>
                <span className="font-bold text-red-400 font-mono text-sm">{quarantineAlert.risk_score} / 100</span>
              </div>
              <div className="flex justify-between border-b border-red-500/20 pb-2">
                <span className="text-slate-400">Policy Violation:</span>
                <span className="font-semibold text-slate-200">{quarantineAlert.reason || "Impossible Travel Velocity"}</span>
              </div>
              <div className="text-[11px] text-slate-400 pt-1 leading-relaxed">
                {quarantineAlert.action_summary || "Session denied. Account moved to quarantine isolation until unlocked by an authorized Security Operations Center (SOC) analyst."}
              </div>
            </div>

            <button
              type="button"
              onClick={() => setQuarantineAlert(null)}
              className="btn-secondary w-full py-3 justify-center text-xs font-semibold"
            >
              Dismiss Alert &amp; Return to Portal
            </button>
          </div>
        </div>
      )}

    </div>
  );
}
