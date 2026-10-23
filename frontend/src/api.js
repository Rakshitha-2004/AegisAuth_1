/**
 * AegisAuth - Unified API Client
 * Wraps fetch calls to Flask backend with JWT bearer token management.
 */

const BASE_URL = "/api";

function getHeaders(token = null) {
  const headers = {
    "Content-Type": "application/json",
  };
  const activeToken = token || localStorage.getItem("aegis_token");
  if (activeToken) {
    headers["Authorization"] = `Bearer ${activeToken}`;
  }
  return headers;
}

export const api = {
  // Health
  async getHealth() {
    const res = await fetch(`${BASE_URL}/health`);
    return res.json();
  },

  // Auth Endpoints
  async register(data) {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async login(payload) {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return res.json();
  },

  async verifyMfa(payload) {
    const res = await fetch(`${BASE_URL}/auth/verify-mfa`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return res.json();
  },

  async logout() {
    const res = await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
      headers: getHeaders(),
    });
    return res.json();
  },

  // SOC Endpoints
  async getSocOverview() {
    const res = await fetch(`${BASE_URL}/soc/overview`, {
      headers: getHeaders(),
    });
    return res.json();
  },

  async getAuditLogs(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`${BASE_URL}/soc/audit-trail?${query}`, {
      headers: getHeaders(),
    });
    return res.json();
  },

  async getActiveSessions() {
    const res = await fetch(`${BASE_URL}/soc/sessions`, {
      headers: getHeaders(),
    });
    return res.json();
  },

  async terminateSession(sessionId) {
    const res = await fetch(`${BASE_URL}/soc/terminate-session`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ session_id: sessionId }),
    });
    return res.json();
  },

  async unquarantineUser(email) {
    const res = await fetch(`${BASE_URL}/soc/unquarantine-user`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ email }),
    });
    return res.json();
  },

  // Simulator Endpoints
  async simulateImpossibleTravel(payload) {
    const res = await fetch(`${BASE_URL}/simulate/impossible-travel`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return res.json();
  },

  async simulateBruteForce(payload) {
    const res = await fetch(`${BASE_URL}/simulate/brute-force`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return res.json();
  },

  async simulateUnrecognizedDevice(payload) {
    const res = await fetch(`${BASE_URL}/simulate/unrecognized-device`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return res.json();
  },

  async resetDemo(email) {
    const res = await fetch(`${BASE_URL}/simulate/reset-demo`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ email }),
    });
    return res.json();
  },
};
