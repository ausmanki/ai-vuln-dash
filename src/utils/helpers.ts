import { CONSTANTS, COLORS } from './constants';

export const utils = {
  hexToRgb: (hex) => {
    let r = 0, g = 0, b = 0;
    if (hex.length === 4) {
      r = parseInt(hex[1] + hex[1], 16);
      g = parseInt(hex[2] + hex[2], 16);
      b = parseInt(hex[3] + hex[3], 16);
    } else if (hex.length === 7) {
      r = parseInt(hex[1] + hex[2], 16);
      g = parseInt(hex[3] + hex[4], 16);
      b = parseInt(hex[5] + hex[6], 16);
    }
    return `${r}, ${g}, ${b}`;
  },

  validateCVE: (cveId) => {
    const id = cveId.trim();
    return /^CVE-\d{4}-\d{4,}$/i.test(id) || /^BDSA-\d{4}-\d{4,}$/i.test(id);
  },

  getVulnerabilityUrl: (id) => {
    const upper = id.trim().toUpperCase();
    if (upper.startsWith('BDSA-')) {
      return `https://openhub.net/vulnerabilities/bdsa/${upper}`;
    }
    return `https://nvd.nist.gov/vuln/detail/${upper}`;
  },

  getSeverityLevel: (score) => {
    if (score >= CONSTANTS.CVSS_THRESHOLDS.CRITICAL) return 'CRITICAL';
    if (score >= CONSTANTS.CVSS_THRESHOLDS.HIGH) return 'HIGH';
    if (score >= CONSTANTS.CVSS_THRESHOLDS.MEDIUM) return 'MEDIUM';
    return 'LOW';
  },

  getSeverityColor: (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return COLORS.red;
      case 'HIGH': return COLORS.yellow;
      case 'MEDIUM': return COLORS.blue;
      case 'LOW': return COLORS.green;
      default: return COLORS.blue;
    }
  },

  formatDate: (dateString) => new Date(dateString).toLocaleString(),

  debounce: (func, wait) => {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },

  sleep: (ms) => new Promise(resolve => setTimeout(resolve, ms))
};
