import { EventEmitter } from 'events';
import * as crypto from 'crypto';

export interface CVEDatabase {
  name: string;
  type: 'api' | 'rss' | 'json' | 'xml' | 'scraper' | 'git' | 'database';
  url: string;
  apiKey?: string;
  rateLimitPerMinute: number;
  enabled: boolean;
  priority: number;
  lastSync?: Date;
  headers?: Record<string, string>;
  region?: string;
  language?: string;
  category: 'official' | 'vendor' | 'commercial' | 'community' | 'research' | 'government';
}

export interface CVEPatchMapping {
  cveId: string;
  component: string;
  affectedVersions: string[];
  patchedVersions: string[];
  patches: PatchInfo[];
  advisories: AdvisoryInfo[];
  workarounds: WorkaroundInfo[];
  lastUpdated: Date;
  confidence: number; // 0-100
  sources: string[];
  cvssScore?: number;
  severity?: string;
  exploitAvailable?: boolean;
  ransomwareUsed?: boolean;
  activelyExploited?: boolean;
}

export interface PatchInfo {
  type: 'version_update' | 'security_patch' | 'hotfix' | 'configuration_change' | 'workaround';
  downloadUrl?: string;
  version?: string;
  description: string;
  releaseDate: Date;
  vendor: string;
  checksum?: string;
  installInstructions?: string;
  prerequisites?: string[];
  testingNotes?: string;
  size?: number;
  compatibility?: string[];
  criticality?: 'critical' | 'high' | 'medium' | 'low';
}

export interface AdvisoryInfo {
  id: string;
  title: string;
  url: string;
  publishedDate: Date;
  severity: string;
  cvssScore?: number;
  description: string;
  solution?: string;
  vendor: string;
  references?: string[];
  cweIds?: string[];
  exploitMaturity?: string;
  targetedIndustries?: string[];
}

export interface WorkaroundInfo {
  description: string;
  steps: string[];
  effectiveness: 'full' | 'partial' | 'minimal';
  complexity: 'low' | 'medium' | 'high';
  temporaryOnly: boolean;
  limitations?: string[];
  riskLevel?: string;
  validUntil?: Date;
}

export interface InstalledComponent {
  name: string;
  version: string;
  ecosystem: string;
  path: string;
  critical: boolean;
  dependencies: string[];
  usedBy: string[];
  license?: string;
  repository?: string;
  vendor?: string;
  cpe?: string;
}

export class IntelligentCVEPatchAgent extends EventEmitter {
  private cveDatabase: Map<string, CVEPatchMapping> = new Map();
  private databases: CVEDatabase[];
  private rateLimiters = new Map<string, number[]>();
  private cacheTimeout = 6 * 60 * 60 * 1000; // 6 hours
  private userAgent = 'Intelligent-CVE-Patch-Agent/4.0 (Security Research)';
  private maxConcurrentRequests = 3;
  private requestQueue: Array<() => Promise<any>> = [];
  private activeRequests = 0;

  constructor(apiKeys?: Record<string, string>) {
    super();
    this.databases = this.initializeProductionDatabases(apiKeys);
  }

  private initializeProductionDatabases(apiKeys?: Record<string, string>): CVEDatabase[] {
    return [
      // TIER 1: Official Government Sources
      {
        name: 'NIST NVD',
        type: 'api',
        url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        rateLimitPerMinute: 50,
        enabled: true,
        priority: 1,
        category: 'official',
        headers: {
          'Accept': 'application/json'
        }
      },
      {
        name: 'CISA KEV',
        type: 'json',
        url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 2,
        category: 'government'
      },
      
      // TIER 2: Major Community Sources
      {
        name: 'GitHub Security Advisories',
        type: 'api',
        url: 'https://api.github.com/advisories',
        rateLimitPerMinute: 5000,
        enabled: true,
        priority: 3,
        category: 'community',
        headers: {
          'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          ...(apiKeys?.github ? { 'Authorization': `Bearer ${apiKeys.github}` } : {})
        }
      },
      {
        name: 'OSV Database',
        type: 'api',
        url: 'https://api.osv.dev/v1',
        rateLimitPerMinute: 1000,
        enabled: true,
        priority: 4,
        category: 'community',
        headers: {
          'Content-Type': 'application/json'
        }
      },
      
      // TIER 3: Ecosystem-Specific Sources
      {
        name: 'NPM Security Advisories',
        type: 'api',
        url: 'https://registry.npmjs.org/-/npm/v1/security/advisories',
        rateLimitPerMinute: 300,
        enabled: true,
        priority: 5,
        category: 'community'
      },
      {
        name: 'PyPI Safety DB',
        type: 'json',
        url: 'https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 6,
        category: 'community'
      },
      {
        name: 'Ruby Advisory Database',
        type: 'api',
        url: 'https://rubysec.com/advisories.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 7,
        category: 'community'
      },
      {
        name: 'Go Vulnerability Database',
        type: 'api',
        url: 'https://vuln.go.dev/ID',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 8,
        category: 'official'
      },
      {
        name: 'Rust Security Advisory Database',
        type: 'json',
        url: 'https://raw.githubusercontent.com/RustSec/advisory-db/main/crates.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 9,
        category: 'community'
      },
      
      // TIER 4: Linux Distribution Sources
      {
        name: 'Ubuntu Security Notices',
        type: 'api',
        url: 'https://ubuntu.com/security/notices.json',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 10,
        category: 'vendor'
      },
      {
        name: 'Debian Security Tracker',
        type: 'json',
        url: 'https://security-tracker.debian.org/tracker/data/json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 11,
        category: 'vendor'
      },
      {
        name: 'Red Hat Security Data',
        type: 'api',
        url: 'https://access.redhat.com/hydra/rest/securitydata/cve.json',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 12,
        category: 'vendor'
      },
      {
        name: 'Alpine SecDB',
        type: 'json',
        url: 'https://secdb.alpinelinux.org/alpine-secdb.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 13,
        category: 'vendor'
      },
      
      // TIER 5: Vendor-Specific Sources
      {
        name: 'Microsoft Security Response Center',
        type: 'api',
        url: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 14,
        category: 'vendor',
        headers: {
          'Accept': 'application/json'
        }
      },
      {
        name: 'Oracle Security Alerts',
        type: 'rss',
        url: 'https://www.oracle.com/security-alerts/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 15,
        category: 'vendor'
      },
      
      // TIER 6: Additional Intelligence Sources
      {
        name: 'CVE Circl',
        type: 'api',
        url: 'https://cve.circl.lu/api',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 16,
        category: 'community'
      },
      {
        name: 'VulnCheck NVD++',
        type: 'api',
        url: 'https://api.vulncheck.com/v3/index/vulncheck-nvd2',
        rateLimitPerMinute: 100,
        enabled: !!apiKeys?.vulncheck,
        priority: 17,
        category: 'commercial',
        headers: {
          ...(apiKeys?.vulncheck ? { 'Authorization': `Bearer ${apiKeys.vulncheck}` } : {})
        }
      },
      {
        name: 'Snyk Vulnerability Database',
        type: 'api',
        url: 'https://api.snyk.io/v1/vuln',
        rateLimitPerMinute: 1000,
        enabled: !!apiKeys?.snyk,
        priority: 18,
        category: 'commercial',
        headers: {
          ...(apiKeys?.snyk ? { 'Authorization': `token ${apiKeys.snyk}` } : {})
        }
      }
    ];
  }

  // Main intelligence discovery method
  async discoverIntelligentPatches(components: InstalledComponent[]): Promise<Map<string, CVEPatchMapping[]>> {
    this.emit('agent_started', { 
      componentCount: components.length,
      enabledSources: this.databases.filter(db => db.enabled).length
    });
    
    const discoveredVulnerabilities = new Map<string, CVEPatchMapping[]>();
    
    // Phase 1: CVE Discovery with intelligent prioritization
    this.emit('phase_started', { phase: 'cve_discovery', components: components.length });
    
    for (const component of components) {
      try {
        this.emit('component_analysis_started', { component: component.name, ecosystem: component.ecosystem });
        
        const componentCVEs = await this.intelligentCVEDiscovery(component);
        
        if (componentCVEs.length > 0) {
          // Phase 2: Comprehensive Patch & Advisory Enrichment
          this.emit('phase_started', { phase: 'patch_enrichment', cveCount: componentCVEs.length });
          
          const enrichedCVEs = await this.intelligentPatchEnrichment(componentCVEs, component);
          
          if (enrichedCVEs.length > 0) {
            discoveredVulnerabilities.set(component.name, enrichedCVEs);
            
            this.emit('component_analysis_completed', {
              component: component.name,
              cves: enrichedCVEs.length,
              patches: enrichedCVEs.reduce((sum, cve) => sum + cve.patches.length, 0),
              advisories: enrichedCVEs.reduce((sum, cve) => sum + cve.advisories.length, 0),
              highSeverity: enrichedCVEs.filter(cve => ['CRITICAL', 'HIGH'].includes(cve.severity || '')).length
            });
          }
        }
        
        // Respect rate limits between components
        await this.intelligentDelay();
        
      } catch (error) {
        this.emit('component_analysis_failed', { component: component.name, error: error.message });
      }
    }
    
    // Phase 3: Cross-reference and validation
    await this.crossReferenceAndValidate(discoveredVulnerabilities);
    
    const totalVulnerabilities = Array.from(discoveredVulnerabilities.values()).reduce((sum, cves) => sum + cves.length, 0);
    
    this.emit('agent_completed', {
      componentsAnalyzed: components.length,
      vulnerabilitiesFound: totalVulnerabilities,
      componentsAffected: discoveredVulnerabilities.size,
      sourcesUtilized: this.getSourceUtilization()
    });
    
    return discoveredVulnerabilities;
  }

  // Intelligent CVE discovery with adaptive search strategies
  private async intelligentCVEDiscovery(component: InstalledComponent): Promise<CVEPatchMapping[]> {
    const searchStrategies = this.generateSearchStrategies(component);
    const allCVEs: CVEPatchMapping[] = [];
    
    // Execute searches with priority-based approach
    for (const strategy of searchStrategies) {
      const strategyCVEs = await this.executeSearchStrategy(strategy, component);
      allCVEs.push(...strategyCVEs);
      
      // Early termination if we find enough high-confidence results
      if (allCVEs.filter(cve => cve.confidence > 80).length >= 10) {
        this.emit('early_termination', { component: component.name, reason: 'sufficient_high_confidence_results' });
        break;
      }
    }
    
    return this.consolidateAndDeduplicate(allCVEs);
  }

  // Generate intelligent search strategies based on component characteristics
  private generateSearchStrategies(component: InstalledComponent): Array<{
    query: string;
    ecosystem: string;
    databases: string[];
    weight: number;
    priority: number;
  }> {
    const strategies = [];
    
    // Strategy 1: Exact component match (highest priority)
    strategies.push({
      query: component.name,
      ecosystem: component.ecosystem,
      databases: ['NIST NVD', 'GitHub Security Advisories', 'OSV Database'],
      weight: 1.0,
      priority: 1
    });
    
    // Strategy 2: Ecosystem-specific search
    const ecosystemDB = this.getEcosystemSpecificDatabases(component.ecosystem);
    if (ecosystemDB.length > 0) {
      strategies.push({
        query: `${component.ecosystem}:${component.name}`,
        ecosystem: component.ecosystem,
        databases: ecosystemDB,
        weight: 0.95,
        priority: 2
      });
    }
    
    // Strategy 3: CPE-based search
    const cpe = this.generateCPE(component);
    if (cpe) {
      strategies.push({
        query: cpe,
        ecosystem: component.ecosystem,
        databases: ['NIST NVD', 'CVE Circl'],
        weight: 0.9,
        priority: 3
      });
    }
    
    // Strategy 4: Vendor-specific search
    if (component.vendor || component.repository) {
      const vendor = this.extractVendor(component);
      strategies.push({
        query: `${vendor} ${component.name}`,
        ecosystem: component.ecosystem,
        databases: this.getVendorSpecificDatabases(vendor),
        weight: 0.85,
        priority: 4
      });
    }
    
    // Strategy 5: Alternative naming patterns
    const alternatives = this.generateAlternativeNames(component);
    for (const alt of alternatives.slice(0, 3)) { // Limit to top 3 alternatives
      strategies.push({
        query: alt,
        ecosystem: component.ecosystem,
        databases: ['GitHub Security Advisories', 'OSV Database'],
        weight: 0.7,
        priority: 5
      });
    }
    
    return strategies.sort((a, b) => a.priority - b.priority);
  }

  // Execute search strategy across specified databases
  private async executeSearchStrategy(strategy: any, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    const results: CVEPatchMapping[] = [];
    
    for (const dbName of strategy.databases) {
      const database = this.databases.find(db => db.name === dbName && db.enabled);
      if (!database || !this.canMakeRequest(database)) continue;
      
      try {
        const cves = await this.searchDatabaseForCVEs(database, strategy.query, component);
        
        // Apply strategy weight to confidence scores
        const weightedCVEs = cves.map(cve => ({
          ...cve,
          confidence: Math.min(100, cve.confidence * strategy.weight)
        }));
        
        results.push(...weightedCVEs);
        this.recordRequest(database);
        
        this.emit('database_search_completed', {
          database: dbName,
          query: strategy.query,
          results: cves.length
        });
        
      } catch (error) {
        this.emit('database_search_failed', {
          database: dbName,
          query: strategy.query,
          error: error.message
        });
      }
    }
    
    return results;
  }

  // Intelligent patch enrichment with comprehensive source coverage
  private async intelligentPatchEnrichment(cves: CVEPatchMapping[], component: InstalledComponent): Promise<CVEPatchMapping[]> {
    const enrichedCVEs: CVEPatchMapping[] = [];
    
    for (const cve of cves) {
      this.emit('cve_enrichment_started', { cveId: cve.cveId });
      
      const enrichmentTasks = this.databases
        .filter(db => db.enabled)
        .map(db => this.enrichCVEFromDatabase(db, cve, component));
      
      // Execute enrichment tasks with controlled concurrency
      const enrichmentResults = await this.executeWithConcurrencyLimit(enrichmentTasks, 3);
      
      // Merge all enrichment data
      const mergedCVE = this.mergeEnrichmentData(cve, enrichmentResults);
      
      // Validate and score the enriched CVE
      const validatedCVE = await this.validateAndScoreCVE(mergedCVE, component);
      
      enrichedCVEs.push(validatedCVE);
      
      this.emit('cve_enrichment_completed', {
        cveId: cve.cveId,
        patches: validatedCVE.patches.length,
        advisories: validatedCVE.advisories.length,
        confidence: validatedCVE.confidence
      });
    }
    
    return enrichedCVEs;
  }

  // Actual API implementations for real data sources
  
  // NIST NVD Implementation
  private async searchNISTNVD(query: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      const encodedQuery = encodeURIComponent(query);
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodedQuery}&resultsPerPage=50`;
      
      const response = await this.makeQueuedRequest(url, {
        headers: { 'Accept': 'application/json' }
      });
      
      if (!response.ok) {
        throw new Error(`NVD API error: ${response.status}`);
      }
      
      const data = await response.json();
      const cves: CVEPatchMapping[] = [];
      
      for (const vuln of data.vulnerabilities || []) {
        const cve = vuln.cve;
        
        // Extract version information from configurations
        const affectedVersions = this.extractAffectedVersionsFromNVD(cve, component);
        const patchedVersions = this.extractPatchedVersionsFromNVD(cve, component);
        
        cves.push({
          cveId: cve.id,
          component: `${component.ecosystem}:${component.name}`,
          affectedVersions,
          patchedVersions,
          patches: this.extractPatchesFromNVD(cve),
          advisories: this.extractAdvisoriesFromNVD(cve),
          workarounds: [],
          lastUpdated: new Date(cve.lastModified),
          confidence: this.calculateNVDConfidence(cve, component),
          sources: ['NIST NVD'],
          cvssScore: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                     cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore,
          severity: this.mapCVSSToSeverity(cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore),
          exploitAvailable: cve.references?.some(ref => 
            ref.tags?.includes('Exploit') || 
            ref.url?.includes('exploit-db.com')
          ) || false
        });
      }
      
      return cves;
    } catch (error) {
      this.emit('api_error', { source: 'NIST NVD', error: error.message });
      return [];
    }
  }

  // GitHub Security Advisories Implementation
  private async searchGitHubAdvisories(query: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      // Search by ecosystem and package name
      const url = `https://api.github.com/advisories?ecosystem=${component.ecosystem}&affects=${encodeURIComponent(component.name)}&per_page=50`;
      
      const response = await this.makeQueuedRequest(url, {
        headers: this.databases.find(db => db.name === 'GitHub Security Advisories')?.headers || {}
      });
      
      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status}`);
      }
      
      const advisories = await response.json();
      const cves: CVEPatchMapping[] = [];
      
      for (const advisory of advisories) {
        // Extract CVE ID from identifiers
        const cveId = advisory.identifiers?.find(id => id.type === 'CVE')?.value;
        if (!cveId) continue;
        
        // Extract affected and patched versions
        const affectedVersions = [];
        const patchedVersions = [];
        const patches = [];
        
        for (const vuln of advisory.vulnerabilities || []) {
          if (vuln.package?.name === component.name) {
            affectedVersions.push(...(vuln.vulnerable_version_range?.split(',') || []));
            patchedVersions.push(...(vuln.patched_versions || []));
            
            // Create patches from patched versions
            for (const version of vuln.patched_versions || []) {
              patches.push({
                type: 'version_update',
                version: version,
                description: `Update to patched version ${version}`,
                releaseDate: new Date(advisory.published_at),
                vendor: 'GitHub Security Advisory',
                downloadUrl: this.generatePackageDownloadUrl(component.ecosystem, component.name, version),
                criticality: advisory.severity?.toLowerCase() as any
              });
            }
          }
        }
        
        cves.push({
          cveId,
          component: `${component.ecosystem}:${component.name}`,
          affectedVersions: [...new Set(affectedVersions.filter(v => v))],
          patchedVersions: [...new Set(patchedVersions.filter(v => v))],
          patches,
          advisories: [{
            id: advisory.ghsa_id,
            title: advisory.summary,
            url: advisory.html_url,
            publishedDate: new Date(advisory.published_at),
            severity: advisory.severity?.toUpperCase() || 'UNKNOWN',
            cvssScore: advisory.cvss?.score,
            description: advisory.description,
            vendor: 'GitHub Security Advisory',
            references: advisory.references?.map(r => r.url) || []
          }],
          workarounds: this.extractWorkaroundsFromText(advisory.description),
          lastUpdated: new Date(advisory.updated_at),
          confidence: 95, // High confidence for GitHub advisories
          sources: ['GitHub Security Advisories'],
          severity: advisory.severity?.toUpperCase(),
          cvssScore: advisory.cvss?.score
        });
      }
      
      return cves;
    } catch (error) {
      this.emit('api_error', { source: 'GitHub Advisories', error: error.message });
      return [];
    }
  }

  // OSV Database Implementation
  private async searchOSVDatabase(query: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      const requestBody = {
        package: {
          ecosystem: this.mapToOSVEcosystem(component.ecosystem),
          name: component.name
        }
      };
      
      const response = await this.makeQueuedRequest('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });
      
      if (!response.ok) {
        throw new Error(`OSV API error: ${response.status}`);
      }
      
      const data = await response.json();
      const cves: CVEPatchMapping[] = [];
      
      for (const vuln of data.vulns || []) {
        const cveId = vuln.aliases?.find(alias => alias.startsWith('CVE-')) || vuln.id;
        
        const affectedVersions = [];
        const patchedVersions = [];
        const patches = [];
        
        // Extract version information from affected packages
        for (const affected of vuln.affected || []) {
          if (affected.package?.name === component.name) {
            for (const range of affected.ranges || []) {
              for (const event of range.events || []) {
                if (event.introduced) affectedVersions.push(`>=${event.introduced}`);
                if (event.fixed) {
                  patchedVersions.push(event.fixed);
                  patches.push({
                    type: 'version_update',
                    version: event.fixed,
                    description: `Fixed in version ${event.fixed}`,
                    releaseDate: new Date(vuln.published),
                    vendor: 'OSV Database',
                    downloadUrl: this.generatePackageDownloadUrl(component.ecosystem, component.name, event.fixed)
                  });
                }
              }
            }
          }
        }
        
        cves.push({
          cveId,
          component: `${component.ecosystem}:${component.name}`,
          affectedVersions: [...new Set(affectedVersions)],
          patchedVersions: [...new Set(patchedVersions)],
          patches,
          advisories: [{
            id: vuln.id,
            title: vuln.summary || `Vulnerability in ${component.name}`,
            url: `https://osv.dev/vulnerability/${vuln.id}`,
            publishedDate: new Date(vuln.published),
            severity: this.extractSeverityFromOSV(vuln),
            description: vuln.details || vuln.summary || 'No description available',
            vendor: 'OSV Database',
            references: vuln.references?.map(r => r.url) || []
          }],
          workarounds: this.extractWorkaroundsFromText(vuln.details),
          lastUpdated: new Date(vuln.modified || vuln.published),
          confidence: 90,
          sources: ['OSV Database'],
          severity: this.extractSeverityFromOSV(vuln)
        });
      }
      
      return cves;
    } catch (error) {
      this.emit('api_error', { source: 'OSV Database', error: error.message });
      return [];
    }
  }

  // CISA KEV Implementation
  private async searchCISAKEV(query: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      const response = await this.makeQueuedRequest('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      
      if (!response.ok) {
        throw new Error(`CISA API error: ${response.status}`);
      }
      
      const data = await response.json();
      const cves: CVEPatchMapping[] = [];
      
      for (const vuln of data.vulnerabilities || []) {
        // Check if vulnerability affects our component
        if (this.isComponentAffected(vuln, component)) {
          cves.push({
            cveId: vuln.cveID,
            component: `${component.ecosystem}:${component.name}`,
            affectedVersions: [component.version],
            patchedVersions: [],
            patches: [{
              type: 'security_patch',
              description: vuln.requiredAction,
              releaseDate: new Date(vuln.dueDate),
              vendor: 'CISA',
              criticality: 'critical'
            }],
            advisories: [{
              id: vuln.cveID,
              title: vuln.vulnerabilityName,
              url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
              publishedDate: new Date(vuln.dateAdded),
              severity: 'CRITICAL',
              description: vuln.shortDescription,
              vendor: 'CISA',
              exploitMaturity: 'Active Exploitation'
            }],
            workarounds: [],
            lastUpdated: new Date(),
            confidence: 99, // Highest confidence for CISA KEV
            sources: ['CISA KEV'],
            severity: 'CRITICAL',
            exploitAvailable: true,
            activelyExploited: true
          });
        }
      }
      
      return cves;
    } catch (error) {
      this.emit('api_error', { source: 'CISA KEV', error: error.message });
      return [];
    }
  }

  // Ecosystem-specific implementations
  
  // NPM Security Advisory implementation
  private async searchNPMAdvisories(component: InstalledComponent): Promise<CVEPatchMapping[]> {
    if (component.ecosystem !== 'npm') return [];
    
    try {
      const response = await this.makeQueuedRequest(`https://registry.npmjs.org/-/npm/v1/security/advisories/search?text=${encodeURIComponent(component.name)}`);
      
      if (!response.ok) return [];
      
      const data = await response.json();
      const cves: CVEPatchMapping[] = [];
      
      for (const advisory of data.objects || []) {
        if (advisory.package_name === component.name) {
          cves.push({
            cveId: advisory.cves?.[0] || `NPM-${advisory.id}`,
            component: `npm:${component.name}`,
            affectedVersions: advisory.vulnerable_versions ? [advisory.vulnerable_versions] : [],
            patchedVersions: advisory.patched_versions || [],
            patches: (advisory.patched_versions || []).map(version => ({
              type: 'version_update' as const,
              version,
              description: `Update to patched version ${version}`,
              releaseDate: new Date(advisory.created),
              vendor: 'NPM Security Team',
              downloadUrl: `https://registry.npmjs.org/${component.name}/-/${component.name}-${version}.tgz`
            })),
            advisories: [{
              id: `NPM-${advisory.id}`,
              title: advisory.title,
              url: advisory.url,
              publishedDate: new Date(advisory.created),
              severity: advisory.severity?.toUpperCase() || 'UNKNOWN',
              cvssScore: advisory.cvss_score,
              description: advisory.overview,
              vendor: 'NPM Security Advisory'
            }],
            workarounds: this.extractWorkaroundsFromText(advisory.recommendation),
            lastUpdated: new Date(advisory.updated),
            confidence: 92,
            sources: ['NPM Security Advisories'],
            severity: advisory.severity?.toUpperCase(),
            cvssScore: advisory.cvss_score
          });
        }
      }
      
      return cves;
    } catch (error) {
      this.emit('api_error', { source: 'NPM Advisories', error: error.message });
      return [];
    }
  }

  // PyPI Safety DB implementation
  private async searchPyPISafetyDB(component: InstalledComponent): Promise<CVEPatchMapping[]> {
    if (component.ecosystem !== 'pypi') return [];
    
    try {
      const response = await this.makeQueuedRequest('https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json');
      
      if (!response.ok) return [];
      
      const data = await response.json();
      const cves: CVEPatchMapping[] = [];
      
      for (const [packageName, vulnerabilities] of Object.entries(data)) {
        if (packageName === component.name) {
          for (const vuln of vulnerabilities as any[]) {
            cves.push({
              cveId: vuln.cve || `PYUP-${vuln.id}`,
              component: `pypi:${component.name}`,
              affectedVersions: vuln.specs || [],
              patchedVersions: [],
              patches: [],
              advisories: [{
                id: `PYUP-${vuln.id}`,
                title: `PyUp.io advisory for ${component.name}`,
                url: `https://pyup.io/vulnerabilities/${vuln.id}/`,
                publishedDate: new Date(),
                severity: 'UNKNOWN',
                description: vuln.advisory,
                vendor: 'PyUp.io Safety DB'
              }],
              workarounds: [],
              lastUpdated: new Date(),
              confidence: 85,
              sources: ['PyUp Safety DB'],
              severity: 'UNKNOWN'
            });
          }
        }
      }
      
      return cves;
    } catch (error) {
      this.emit('api_error', { source: 'PyUp Safety DB', error: error.message });
      return [];
    }
  }

  // Request queue management for rate limiting
  private async makeQueuedRequest(url: string, options: any = {}): Promise<Response> {
    return new Promise((resolve, reject) => {
      this.requestQueue.push(async () => {
        try {
          this.activeRequests++;
          const response = await fetch(url, {
            ...options,
            headers: {
              'User-Agent': this.userAgent,
              ...options.headers
            },
            timeout: 30000
          });
          this.activeRequests--;
          this.processQueue();
          resolve(response);
        } catch (error) {
          this.activeRequests--;
          this.processQueue();
          reject(error);
        }
      });
      
      this.processQueue();
    });
  }

  private processQueue(): void {
    if (this.activeRequests < this.maxConcurrentRequests && this.requestQueue.length > 0) {
      const nextRequest = this.requestQueue.shift();
      if (nextRequest) {
        nextRequest();
      }
    }
  }

  // Enhanced utility methods

  private async executeWithConcurrencyLimit<T>(tasks: Promise<T>[], limit: number): Promise<T[]> {
    const results: T[] = [];
    
    for (let i = 0; i < tasks.length; i += limit) {
      const batch = tasks.slice(i, i + limit);
      const batchResults = await Promise.allSettled(batch);
      
      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        }
      }
    }
    
    return results;
  }

  private consolidateAndDeduplicate(cves: CVEPatchMapping[]): CVEPatchMapping[] {
    const merged = new Map<string, CVEPatchMapping>();
    
    for (const cve of cves) {
      const existing = merged.get(cve.cveId);
      
      if (existing) {
        // Intelligent merging
        existing.sources.push(...cve.sources);
        existing.sources = [...new Set(existing.sources)];
        existing.confidence = Math.max(existing.confidence, cve.confidence);
        existing.patches.push(...cve.patches);
        existing.advisories.push(...cve.advisories);
        existing.affectedVersions.push(...cve.affectedVersions);
        existing.patchedVersions.push(...cve.patchedVersions);
        
        // Deduplicate arrays
        existing.patches = this.deduplicateByKey(existing.patches, 'version');
        existing.advisories = this.deduplicateByKey(existing.advisories, 'id');
        existing.affectedVersions = [...new Set(existing.affectedVersions)];
        existing.patchedVersions = [...new Set(existing.patchedVersions)];
      } else {
        merged.set(cve.cveId, { ...cve });
      }
    }
    
    return Array.from(merged.values()).sort((a, b) => {
      // Sort by severity, then confidence
      const severityWeight = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0 };
      const aSeverity = severityWeight[a.severity as keyof typeof severityWeight] || 0;
      const bSeverity = severityWeight[b.severity as keyof typeof severityWeight] || 0;
      
      if (aSeverity !== bSeverity) return bSeverity - aSeverity;
      return b.confidence - a.confidence;
    });
  }

  private generateCPE(component: InstalledComponent): string {
    const vendor = this.extractVendor(component) || '*';
    return `cpe:2.3:a:${vendor}:${component.name}:${component.version}:*:*:*:*:*:*:*`;
  }

  private extractVendor(component: InstalledComponent): string {
    if (component.vendor) return component.vendor.toLowerCase().replace(/[^a-z0-9]/g, '_');
    
    if (component.repository) {
      const match = component.repository.match(/github\.com\/([^\/]+)/);
      if (match) return match[1].toLowerCase();
    }
    
    const vendorMap: Record<string, string> = {
      'npm': 'npmjs',
      'pypi': 'python_software_foundation',
      'maven': 'apache',
      'nuget': 'microsoft'
    };
    
    return vendorMap[component.ecosystem] || '*';
  }

  private generateAlternativeNames(component: InstalledComponent): string[] {
    const alternatives = new Set<string>();
    const name = component.name.toLowerCase();
    
    // Ecosystem-specific patterns
    switch (component.ecosystem) {
      case 'npm':
        alternatives.add(`node-${name}`);
        alternatives.add(`${name}.js`);
        alternatives.add(`@types/${name}`);
        if (name.includes('-')) {
          alternatives.add(name.replace(/-/g, '_'));
        }
        break;
        
      case 'pypi':
        alternatives.add(`python-${name}`);
        alternatives.add(name.replace(/-/g, '_'));
        alternatives.add(name.replace(/_/g, '-'));
        break;
        
      case 'maven':
        const parts = name.split(':');
        if (parts.length > 1) {
          alternatives.add(parts[parts.length - 1]);
        }
        break;
    }
    
    return Array.from(alternatives);
  }

  private mapToOSVEcosystem(ecosystem: string): string {
    const mapping: Record<string, string> = {
      'npm': 'npm',
      'pypi': 'PyPI',
      'maven': 'Maven',
      'nuget': 'NuGet',
      'composer': 'Packagist',
      'rubygems': 'RubyGems',
      'go': 'Go',
      'cargo': 'crates.io'
    };
    
    return mapping[ecosystem] || ecosystem;
  }

  private generatePackageDownloadUrl(ecosystem: string, name: string, version: string): string {
    const urls: Record<string, string> = {
      'npm': `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
      'pypi': `https://pypi.org/project/${name}/${version}/#files`,
      'maven': `https://repo1.maven.org/maven2/${name.replace(/[:.]/g, '/')}/${version}/`,
      'nuget': `https://www.nuget.org/packages/${name}/${version}`,
      'rubygems': `https://rubygems.org/gems/${name}/versions/${version}`,
      'go': `https://pkg.go.dev/${name}@v${version}`,
      'cargo': `https://crates.io/crates/${name}/${version}`
    };
    
    return urls[ecosystem] || '';
  }

  private extractWorkaroundsFromText(text: string): WorkaroundInfo[] {
    if (!text) return [];
    
    const workaroundKeywords = ['workaround', 'mitigation', 'temporary fix', 'bypass'];
    const lowerText = text.toLowerCase();
    
    if (workaroundKeywords.some(keyword => lowerText.includes(keyword))) {
      return [{
        description: 'Workaround mentioned in advisory',
        steps: [text.substring(0, 200) + '...'],
        effectiveness: 'partial' as const,
        complexity: 'medium' as const,
        temporaryOnly: true
      }];
    }
    
    return [];
  }

  private mapCVSSToSeverity(score?: number): string {
    if (!score) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  }

  private extractSeverityFromOSV(vuln: any): string {
    if (vuln.database_specific?.severity) {
      return vuln.database_specific.severity.toUpperCase();
    }
    
    if (vuln.severity?.length > 0) {
      return vuln.severity[0].type?.toUpperCase() || 'UNKNOWN';
    }
    
    return 'UNKNOWN';
  }

  private calculateNVDConfidence(cve: any, component: InstalledComponent): number {
    let confidence = 70; // Base confidence
    
    // Increase confidence based on exact matches
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value?.toLowerCase() || '';
    if (description.includes(component.name.toLowerCase())) confidence += 20;
    
    // Increase confidence if CPE matches
    const configurations = cve.configurations?.nodes || [];
    for (const node of configurations) {
      for (const cpeMatch of node.cpeMatch || []) {
        if (cpeMatch.criteria?.includes(component.name)) {
          confidence += 15;
          break;
        }
      }
    }
    
    return Math.min(100, confidence);
  }

  private isComponentAffected(vuln: any, component: InstalledComponent): boolean {
    const product = vuln.product?.toLowerCase() || '';
    const vendor = vuln.vendorProject?.toLowerCase() || '';
    const componentName = component.name.toLowerCase();
    
    return product.includes(componentName) || 
           vendor.includes(componentName) ||
           vuln.vulnerabilityName?.toLowerCase().includes(componentName);
  }

  private deduplicateByKey<T>(array: T[], key: keyof T): T[] {
    const seen = new Set();
    return array.filter(item => {
      const value = item[key];
      if (seen.has(value)) return false;
      seen.add(value);
      return true;
    });
  }

  // Enhanced database routing
  private async searchDatabaseForCVEs(database: CVEDatabase, query: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    switch (database.name) {
      case 'NIST NVD':
        return await this.searchNISTNVD(query, component);
      case 'GitHub Security Advisories':
        return await this.searchGitHubAdvisories(query, component);
      case 'OSV Database':
        return await this.searchOSVDatabase(query, component);
      case 'CISA KEV':
        return await this.searchCISAKEV(query, component);
      case 'NPM Security Advisories':
        return await this.searchNPMAdvisories(component);
      case 'PyPI Safety DB':
        return await this.searchPyPISafetyDB(component);
      default:
        return [];
    }
  }

  private async enrichCVEFromDatabase(database: CVEDatabase, cve: CVEPatchMapping, component: InstalledComponent): Promise<Partial<CVEPatchMapping>> {
    // This would contain database-specific enrichment logic
    // For now, return empty enrichment
    return {
      patches: [],
      advisories: [],
      workarounds: [],
      sources: []
    };
  }

  private mergeEnrichmentData(originalCVE: CVEPatchMapping, enrichmentResults: Partial<CVEPatchMapping>[]): CVEPatchMapping {
    const merged = { ...originalCVE };
    
    for (const enrichment of enrichmentResults) {
      if (enrichment.patches) merged.patches.push(...enrichment.patches);
      if (enrichment.advisories) merged.advisories.push(...enrichment.advisories);
      if (enrichment.workarounds) merged.workarounds.push(...enrichment.workarounds);
      if (enrichment.sources) merged.sources.push(...enrichment.sources);
    }
    
    // Deduplicate
    merged.patches = this.deduplicateByKey(merged.patches, 'version');
    merged.advisories = this.deduplicateByKey(merged.advisories, 'id');
    merged.sources = [...new Set(merged.sources)];
    
    return merged;
  }

  private async validateAndScoreCVE(cve: CVEPatchMapping, component: InstalledComponent): Promise<CVEPatchMapping> {
    // Add validation logic and confidence scoring
    const validated = { ...cve };
    
    // Increase confidence based on number of sources
    validated.confidence += Math.min(20, cve.sources.length * 3);
    
    // Increase confidence if patches are available
    validated.confidence += Math.min(15, cve.patches.length * 5);
    
    validated.confidence = Math.min(100, validated.confidence);
    
    return validated;
  }

  private async crossReferenceAndValidate(vulnerabilities: Map<string, CVEPatchMapping[]>): Promise<void> {
    // Cross-reference CVEs across components for validation
    this.emit('cross_reference_started', { components: vulnerabilities.size });
    
    // Implementation would include cross-validation logic
    
    this.emit('cross_reference_completed');
  }

  private getEcosystemSpecificDatabases(ecosystem: string): string[] {
    const mapping: Record<string, string[]> = {
      'npm': ['NPM Security Advisories', 'GitHub Security Advisories'],
      'pypi': ['PyPI Safety DB', 'GitHub Security Advisories'],
      'maven': ['GitHub Security Advisories', 'OSV Database'],
      'nuget': ['GitHub Security Advisories', 'OSV Database'],
      'go': ['Go Vulnerability Database', 'GitHub Security Advisories'],
      'cargo': ['Rust Security Advisory Database', 'GitHub Security Advisories']
    };
    
    return mapping[ecosystem] || ['GitHub Security Advisories', 'OSV Database'];
  }

  private getVendorSpecificDatabases(vendor: string): string[] {
    const mapping: Record<string, string[]> = {
      'microsoft': ['Microsoft Security Response Center', 'NIST NVD'],
      'oracle': ['Oracle Security Alerts', 'NIST NVD'],
      'redhat': ['Red Hat Security Data', 'NIST NVD'],
      'canonical': ['Ubuntu Security Notices', 'NIST NVD']
    };
    
    return mapping[vendor.toLowerCase()] || ['NIST NVD'];
  }

  private extractAffectedVersionsFromNVD(cve: any, component: InstalledComponent): string[] {
    const versions = [];
    
    for (const node of cve.configurations?.nodes || []) {
      for (const cpeMatch of node.cpeMatch || []) {
        if (cpeMatch.criteria?.includes(component.name)) {
          if (cpeMatch.versionStartIncluding) versions.push(`>=${cpeMatch.versionStartIncluding}`);
          if (cpeMatch.versionEndExcluding) versions.push(`<${cpeMatch.versionEndExcluding}`);
          if (cpeMatch.versionEndIncluding) versions.push(`<=${cpeMatch.versionEndIncluding}`);
        }
      }
    }
    
    return versions;
  }

  private extractPatchedVersionsFromNVD(cve: any, component: InstalledComponent): string[] {
    // NVD doesn't typically contain patch version info directly
    return [];
  }

  private extractPatchesFromNVD(cve: any): PatchInfo[] {
    const patches = [];
    
    for (const ref of cve.references || []) {
      if (ref.tags?.includes('Patch') || ref.tags?.includes('Vendor Advisory')) {
        patches.push({
          type: 'security_patch' as const,
          downloadUrl: ref.url,
          description: `Patch reference: ${ref.url}`,
          releaseDate: new Date(),
          vendor: 'NVD Reference'
        });
      }
    }
    
    return patches;
  }

  private extractAdvisoriesFromNVD(cve: any): AdvisoryInfo[] {
    const advisories = [];
    
    for (const ref of cve.references || []) {
      if (ref.tags?.includes('Third Party Advisory')) {
        advisories.push({
          id: `NVD-${cve.id}-${ref.url.split('/').pop()}`,
          title: `Advisory for ${cve.id}`,
          url: ref.url,
          publishedDate: new Date(cve.published),
          severity: 'UNKNOWN',
          description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
          vendor: 'NVD Reference'
        });
      }
    }
    
    return advisories;
  }

  private async intelligentDelay(): Promise<void> {
    // Dynamic delay based on rate limit pressure
    const baseDelay = 100;
    const pressureMultiplier = Math.min(3, this.activeRequests / this.maxConcurrentRequests);
    const delay = baseDelay * (1 + pressureMultiplier);
    
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  private canMakeRequest(database: CVEDatabase): boolean {
    const now = Date.now();
    const requests = this.rateLimiters.get(database.name) || [];
    const recentRequests = requests.filter(time => now - time < 60000);
    this.rateLimiters.set(database.name, recentRequests);
    
    return recentRequests.length < database.rateLimitPerMinute;
  }

  private recordRequest(database: CVEDatabase): void {
    const now = Date.now();
    const requests = this.rateLimiters.get(database.name) || [];
    requests.push(now);
    this.rateLimiters.set(database.name, requests);
  }

  private getSourceUtilization(): Record<string, number> {
    const utilization: Record<string, number> = {};
    
    for (const [dbName, requests] of this.rateLimiters.entries()) {
      utilization[dbName] = requests.length;
    }
    
    return utilization;
  }

  // Public API methods
  public async getComprehensiveAnalytics(): Promise<{
    totalVulnerabilities: number;
    criticalVulnerabilities: number;
    patchesAvailable: number;
    activelyExploited: number;
    sourceReliability: Record<string, number>;
    ecosystemRisk: Record<string, number>;
    patchCoverage: number;
  }> {
    const allCVEs = Array.from(this.cveDatabase.values());
    
    return {
      totalVulnerabilities: allCVEs.length,
      criticalVulnerabilities: allCVEs.filter(cve => cve.severity === 'CRITICAL').length,
      patchesAvailable: allCVEs.filter(cve => cve.patches.length > 0).length,
      activelyExploited: allCVEs.filter(cve => cve.activelyExploited).length,
      sourceReliability: this.calculateSourceReliability(allCVEs),
      ecosystemRisk: this.calculateEcosystemRisk(allCVEs),
      patchCoverage: this.calculatePatchCoverage(allCVEs)
    };
  }

  private calculateSourceReliability(cves: CVEPatchMapping[]): Record<string, number> {
    const reliability: Record<string, number> = {};
    
    for (const source of this.databases.map(db => db.name)) {
      const sourceCVEs = cves.filter(cve => cve.sources.includes(source));
      const avgConfidence = sourceCVEs.reduce((sum, cve) => sum + cve.confidence, 0) / sourceCVEs.length || 0;
      reliability[source] = Math.round(avgConfidence);
    }
    
    return reliability;
  }

  private calculateEcosystemRisk(cves: CVEPatchMapping[]): Record<string, number> {
    const risk: Record<string, number> = {};
    
    for (const cve of cves) {
      const ecosystem = cve.component.split(':')[0];
      if (!risk[ecosystem]) risk[ecosystem] = 0;
      
      const severityWeight = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      risk[ecosystem] += severityWeight[cve.severity as keyof typeof severityWeight] || 0;
    }
    
    return risk;
  }

  private calculatePatchCoverage(cves: CVEPatchMapping[]): number {
    const cvesWithPatches = cves.filter(cve => cve.patches.length > 0).length;
    return Math.round((cvesWithPatches / cves.length) * 100) || 0;
  }

  public async exportIntelligenceReport(format: 'json' | 'csv' | 'xml' = 'json'): Promise<string> {
    const allCVEs = Array.from(this.cveDatabase.values());
    const analytics = await this.getComprehensiveAnalytics();
    
    const report = {
      metadata: {
        generatedAt: new Date().toISOString(),
        agentVersion: '4.0',
        totalComponents: this.cveDatabase.size,
        totalVulnerabilities: allCVEs.length,
        sourcesUtilized: Object.keys(this.getSourceUtilization()).length
      },
      analytics,
      vulnerabilities: allCVEs.map(cve => ({
        ...cve,
        lastUpdated: cve.lastUpdated.toISOString()
      }))
    };
    
    switch (format) {
      case 'json':
        return JSON.stringify(report, null, 2);
      case 'csv':
        return this.convertToCSV(allCVEs);
      case 'xml':
        return this.convertToXML(allCVEs);
      default:
        return JSON.stringify(report, null, 2);
    }
  }

  private convertToCSV(cves: CVEPatchMapping[]): string {
    const headers = [
      'CVE ID', 'Component', 'Severity', 'CVSS Score', 'Patches Available',
      'Actively Exploited', 'Sources', 'Confidence', 'Last Updated'
    ];
    
    const rows = cves.map(cve => [
      cve.cveId,
      cve.component,
      cve.severity || 'UNKNOWN',
      cve.cvssScore?.toString() || '',
      cve.patches.length.toString(),
      cve.activelyExploited ? 'Yes' : 'No',
      cve.sources.join('; '),
      cve.confidence.toString(),
      cve.lastUpdated.toISOString()
    ]);
    
    return [headers, ...rows]
      .map(row => row.map(cell => `"${cell.toString().replace(/"/g, '""')}"`).join(','))
      .join('\n');
  }

  private convertToXML(cves: CVEPatchMapping[]): string {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<vulnerability_report>\n';
    
    for (const cve of cves) {
      xml += `  <vulnerability>\n`;
      xml += `    <cve_id>${this.escapeXML(cve.cveId)}</cve_id>\n`;
      xml += `    <component>${this.escapeXML(cve.component)}</component>\n`;
      xml += `    <severity>${this.escapeXML(cve.severity || 'UNKNOWN')}</severity>\n`;
      xml += `    <patches_count>${cve.patches.length}</patches_count>\n`;
      xml += `    <confidence>${cve.confidence}</confidence>\n`;
      xml += `    <sources>${this.escapeXML(cve.sources.join(', '))}</sources>\n`;
      xml += `  </vulnerability>\n`;
    }
    
    xml += '</vulnerability_report>';
    return xml;
  }

  private escapeXML(str: string): string {
    return str.replace(/[<>&'"]/g, (c) => {
      const map: Record<string, string> = {
        '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;'
      };
      return map[c];
    });
  }
}