import React, { useState, useEffect } from "react";
import Navbar from "./components/Navbar";
import AccessPortal from "./components/AccessPortal";
import SocDashboard from "./components/SocDashboard";
import SimulatorLab from "./components/SimulatorLab";
import AuditTrail from "./components/AuditTrail";
import { api } from "./api";

export default function App() {
  const [activeTab, setActiveTab] = useState("portal");
  const [currentUser, setCurrentUser] = useState(null);
  const [systemOnline, setSystemOnline] = useState(true);

  // Check stored user session on load
  useEffect(() => {
    const storedUser = localStorage.getItem("aegis_user");
    const storedToken = localStorage.getItem("aegis_token");
    if (storedUser && storedToken) {
      try {
        setCurrentUser(JSON.parse(storedUser));
      } catch (e) {
        localStorage.removeItem("aegis_user");
      }
    }

    // Ping health endpoint
    api.getHealth()
      .then((data) => {
        setSystemOnline(data.status === "ONLINE");
      })
      .catch(() => {
        setSystemOnline(false);
      });
  }, []);

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (e) {
      // ignore
    } finally {
      localStorage.removeItem("aegis_token");
      localStorage.removeItem("aegis_user");
      setCurrentUser(null);
      setActiveTab("portal");
    }
  };

  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    setActiveTab("soc");
  };

  return (
    <div className="min-h-screen flex flex-col bg-transparent text-slate-100 selection:bg-amber-500/30 selection:text-amber-200">
      
      {/* Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentUser={currentUser}
        onLogout={handleLogout}
        systemOnline={systemOnline}
      />

      {/* Main Content Body */}
      <main className="flex-1">
        {activeTab === "portal" && (
          <AccessPortal
            currentUser={currentUser}
            setCurrentUser={setCurrentUser}
            onLoginSuccess={handleLoginSuccess}
          />
        )}

        {activeTab === "soc" && (
          <SocDashboard />
        )}

        {activeTab === "simulator" && (
          <SimulatorLab />
        )}

        {activeTab === "audit" && (
          <AuditTrail />
        )}
      </main>

      {/* Professional Cybersecurity Project Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 mt-12 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-400"></span>
            <span className="font-semibold text-slate-400">AegisAuth</span>
            <span>— Context-Aware Zero-Trust Identity Threat Detection & Access Management</span>
          </div>

          <div className="flex items-center gap-4 font-mono text-[11px]">
            <span>NIST SP 800-207</span>
            <span>•</span>
            <span>Spherical Haversine Geodesic Engine</span>
            <span>•</span>
            <span className="text-amber-400">MCA Final Year Defense</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
