/**
 * AegisAuth - Client Digital Entropy Harvester
 * Collects browser & hardware entropy indicators for Zero-Trust device authentication.
 * 100% digital: Zero biometric or physical hardware requirements.
 */

export function harvestClientFingerprint() {
  try {
    const nav = typeof window !== "undefined" ? window.navigator || {} : {};
    const screen = typeof window !== "undefined" ? window.screen || {} : {};
    
    let tz = "UTC";
    try {
      if (typeof Intl !== "undefined" && Intl.DateTimeFormat) {
        tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
      }
    } catch (e) {
      tz = "UTC";
    }

    return {
      screen_res: `${screen.width || 1920}x${screen.height || 1080}`,
      color_depth: `${screen.colorDepth || 24}-bit`,
      cpu_cores: nav.hardwareConcurrency || 8,
      timezone: tz,
      platform: nav.platform || "unknown",
      user_agent: nav.userAgent || "Mozilla/5.0",
      language: nav.language || "en-US",
      device_memory_gb: nav.deviceMemory || 8,
      touch_points: nav.maxTouchPoints || 0
    };
  } catch (err) {
    return {
      screen_res: "1920x1080",
      color_depth: "24-bit",
      cpu_cores: 8,
      timezone: "UTC",
      platform: "unknown",
      user_agent: "Mozilla/5.0",
      language: "en-US",
      device_memory_gb: 8,
      touch_points: 0
    };
  }
}
