export const CONSTANTS = {
  API_ENDPOINTS: {
    NVD: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    EPSS: 'https://api.first.org/data/v1/epss',
    GEMINI: 'https://generativelanguage.googleapis.com/v1beta/models',
    OPENAI: 'https://api.openai.com/v1'
  },
  RATE_LIMITS: {
    GEMINI_COOLDOWN: 60000, // 1 minute
    MAX_RETRIES: 3
  },
  CVSS_THRESHOLDS: {
    CRITICAL: 9.0,
    HIGH: 7.0,
    MEDIUM: 4.0,
    LOW: 0.1
  },
  EPSS_THRESHOLDS: {
    HIGH: 0.5,
    MEDIUM: 0.1
  }
};

export const COLORS = {
  blue: '#3b82f6',
  purple: '#8b5cf6',
  green: '#22c55e',
  red: '#ef4444',
  yellow: '#f59e0b',
  dark: {
    background: '#0f172a',
    surface: '#1e293b',
    primaryText: '#f1f5f9',
    secondaryText: '#94a3b8',
    tertiaryText: '#64748b',
    border: '#334155',
    shadow: 'rgba(0, 0, 0, 0.2)',
  },
  light: {
    background: '#f8fafc',
    surface: '#ffffff',
    primaryText: '#0f172a',
    secondaryText: '#64748b',
    tertiaryText: '#94a3b8',
    border: '#e2e8f0',
    shadow: 'rgba(0, 0, 0, 0.07)',
  }
};
