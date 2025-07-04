export interface VendorPortal {
  name: string;
  securityUrl: string;
  downloadUrl: string;
  description: string;
  searchTips: string;
  updateGuidance: string;
  relevantFor?: string;
  ecosystem?: string;
  componentType?: string;
}

export type VendorPortalMap = Record<string, VendorPortal>;
