import { describe, it, expect } from 'vitest';
import { vendorPortalMap, getVendorPortal } from './vendorPortals';

describe('vendorPortalMap', () => {
  it('returns Apache portal information', () => {
    const portal = getVendorPortal('apache');
    expect(portal?.securityUrl).toBe('https://httpd.apache.org/security/');
    expect(portal?.downloadUrl).toBe('https://httpd.apache.org/download.cgi');
  });

  it('map contains microsoft entry', () => {
    expect(vendorPortalMap.microsoft.name).toBe('Microsoft Security Response Center');
  });
});
