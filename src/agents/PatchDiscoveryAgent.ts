import { GoogleGenerativeAI, GenerateContentResult } from '@google/generative-ai';
import { EventEmitter } from 'events';

export interface PatchSearchResult {
  patches: PatchInfo[];
  advisories: AdvisoryInfo[];
  workarounds: WorkaroundInfo[];
  groundingSources: GroundingSource[];
  searchMetadata: SearchMetadata;
}

export interface PatchInfo {
  type: 'version_update' | 'security_patch' | 'hotfix' | 'configuration_change';
  version?: string;
  description: string;
  releaseDate?: Date;
  downloadUrl?: string;
  vendor?: string;
  platform?: string;
  instructions?: string;
  verified: boolean;
  confidence: number;
}

export interface AdvisoryInfo {
  id: string;
  title: string;
  url: string;
  source: string;
  publishedDate?: Date;
  severity?: string;
  description: string;
  affectedVersions?: string[];
  fixedVersions?: string[];
}

export interface WorkaroundInfo {
  description: string;
  steps: string[];
  effectiveness: 'full' | 'partial' | 'minimal';
  source?: string;
  limitations?: string[];
}

export interface GroundingSource {
  url: string;
  title: string;
  snippet: string;
  relevanceScore?: number;
}

export interface SearchMetadata {
  searchQuery: string;
  timestamp: Date;
  totalSourcesFound: number;
  processingTime: number;
  fallbackUsed: boolean;
}

export class EnhancedGeminiPatchService extends EventEmitter {
  private genAI: GoogleGenerativeAI;
  private model: any;

  constructor(apiKey: string) {
    super();
    this.genAI = new GoogleGenerativeAI(apiKey);
    this.model = this.genAI.getGenerativeModel({
      model: 'gemini-2.0-flash-exp',
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 8192,
      }
    });
  }

  /**
   * Search for patches and advisories for a specific CVE
   */
  async searchPatchesForCVE(
    cveId: string, 
    componentName?: string,
    version?: string
  ): Promise<PatchSearchResult> {
    const startTime = Date.now();
    
    this.emit('search_started', { cveId, componentName, version });

    try {
      // Try structured search first
      let result = await this.performStructuredSearch(cveId, componentName, version);
      
      // If no patches found, try alternative search strategies
      if (result.patches.length === 0 && result.advisories.length === 0) {
        this.emit('fallback_search', { cveId, reason: 'No results from structured search' });
        result = await this.performFallbackSearch(cveId, componentName, version);
      }

      // Enrich with heuristic detection if still limited results
      if (result.patches.length < 2) {
        this.emit('heuristic_enrichment', { cveId });
        result = await this.enrichWithHeuristics(result, cveId, componentName);
      }

      const processingTime = Date.now() - startTime;
      result.searchMetadata.processingTime = processingTime;

      this.emit('search_completed', { 
        cveId, 
        patchesFound: result.patches.length,
        advisoriesFound: result.advisories.length,
        processingTime 
      });

      return result;

    } catch (error) {
      this.emit('search_error', { cveId, error: error.message });
      throw error;
    }
  }

  /**
   * Perform structured search with specific prompt
   */
  private async performStructuredSearch(
    cveId: string,
    componentName?: string,
    version?: string
  ): Promise<PatchSearchResult> {
    const componentInfo = componentName ? ` for ${componentName}${version ? ` version ${version}` : ''}` : '';
    
    const prompt = `Search for patches, fixes, and security advisories for ${cveId}${componentInfo}.

IMPORTANT: Search these specific sources:
1. Official vendor security bulletins and patch releases
2. NIST NVD database entries with remediation information
3. GitHub Security Advisories database
4. Distribution-specific security updates (Ubuntu, Debian, Red Hat, etc.)
5. CISA advisories and mitigation guidance
6. Security mailing lists and forums

For each patch or fix found, extract:
- Exact version numbers that fix the vulnerability
- Download URLs for patches
- Release dates
- Installation instructions
- Platform/OS specific information

Return a JSON response with this EXACT structure:
{
  "patches": [
    {
      "type": "version_update|security_patch|hotfix",
      "version": "specific version number",
      "description": "clear description",
      "releaseDate": "YYYY-MM-DD",
      "downloadUrl": "direct download URL",
      "vendor": "vendor name",
      "platform": "platform/OS",
      "instructions": "installation steps",
      "verified": true/false
    }
  ],
  "advisories": [
    {
      "id": "advisory ID",
      "title": "advisory title",
      "url": "advisory URL",
      "source": "source name",
      "publishedDate": "YYYY-MM-DD",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "advisory description",
      "affectedVersions": ["list of affected versions"],
      "fixedVersions": ["list of fixed versions"]
    }
  ],
  "workarounds": [
    {
      "description": "workaround description",
      "steps": ["step 1", "step 2"],
      "effectiveness": "full|partial|minimal",
      "source": "source of workaround",
      "limitations": ["limitation 1", "limitation 2"]
    }
  ],
  "sources": [
    {
      "url": "source URL",
      "title": "source title",
      "snippet": "relevant excerpt"
    }
  ]
}

Include ALL patches and advisories found, not just the latest ones.`;

    try {
      const result = await this.model.generateContent(prompt);
      const response = await result.response;
      
      return this.parseStructuredResponse(response, cveId);
    } catch (error) {
      this.emit('structured_search_error', { cveId, error: error.message });
      return this.createEmptyResult(cveId);
    }
  }

  /**
   * Perform fallback search with different strategies
   */
  private async performFallbackSearch(
    cveId: string,
    componentName?: string,
    version?: string
  ): Promise<PatchSearchResult> {
    const searches = [
      this.searchVendorSpecific(cveId, componentName),
      this.searchByExploitStatus(cveId),
      this.searchSecurityBulletins(cveId, componentName)
    ];

    const results = await Promise.allSettled(searches);
    
    // Merge all successful results
    const mergedResult = this.createEmptyResult(cveId);
    mergedResult.searchMetadata.fallbackUsed = true;

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        mergedResult.patches.push(...result.value.patches);
        mergedResult.advisories.push(...result.value.advisories);
        mergedResult.workarounds.push(...result.value.workarounds);
        mergedResult.groundingSources.push(...result.value.groundingSources);
      }
    }

    // Deduplicate
    mergedResult.patches = this.deduplicatePatches(mergedResult.patches);
    mergedResult.advisories = this.deduplicateAdvisories(mergedResult.advisories);

    return mergedResult;
  }

  /**
   * Search vendor-specific patches
   */
  private async searchVendorSpecific(
    cveId: string,
    componentName?: string
  ): Promise<PatchSearchResult> {
    const prompt = `Find vendor-specific patches and security updates for ${cveId}.
${componentName ? `Focus on ${componentName} from its official vendor.` : ''}

Search for:
1. Official vendor patch announcements
2. Version-specific security updates
3. Hotfixes and emergency patches
4. Vendor security bulletins

Return JSON with patches and download links.`;

    try {
      const result = await this.model.generateContent(prompt);
      return this.parseStructuredResponse(await result.response, cveId);
    } catch {
      return this.createEmptyResult(cveId);
    }
  }

  /**
   * Search based on exploit status
   */
  private async searchByExploitStatus(cveId: string): Promise<PatchSearchResult> {
    const prompt = `Search CISA Known Exploited Vulnerabilities catalog and exploit databases for ${cveId}.

Find:
1. CISA required actions and due dates
2. Emergency patches for actively exploited vulnerabilities
3. Temporary mitigations until patches are available
4. Exploit prevention measures

Return JSON with patches, workarounds, and advisories.`;

    try {
      const result = await this.model.generateContent(prompt);
      return this.parseStructuredResponse(await result.response, cveId);
    } catch {
      return this.createEmptyResult(cveId);
    }
  }

  /**
   * Search security bulletins
   */
  private async searchSecurityBulletins(
    cveId: string,
    componentName?: string
  ): Promise<PatchSearchResult> {
    const prompt = `Search security bulletins and mailing lists for ${cveId}.

Check:
1. Full-disclosure mailing list
2. OSS-security mailing list  
3. Vendor security announcement lists
4. Distribution security teams
${componentName ? `5. ${componentName} security announcements` : ''}

Find patch information, fixed versions, and workarounds.
Return JSON response.`;

    try {
      const result = await this.model.generateContent(prompt);
      return this.parseStructuredResponse(await result.response, cveId);
    } catch {
      return this.createEmptyResult(cveId);
    }
  }

  /**
   * Parse Gemini's structured response
   */
  private parseStructuredResponse(
    response: any,
    cveId: string
  ): PatchSearchResult {
    const result = this.createEmptyResult(cveId);

    try {
      const text = response.text();
      
      // Try to extract JSON from the response
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        this.emit('parse_warning', { cveId, warning: 'No JSON found in response' });
        return this.parseUnstructuredResponse(text, cveId);
      }

      const data = JSON.parse(jsonMatch[0]);

      // Parse patches
      if (Array.isArray(data.patches)) {
        result.patches = data.patches.map((patch: any) => ({
          type: patch.type || 'security_patch',
          version: patch.version,
          description: patch.description || 'Security update',
          releaseDate: patch.releaseDate ? new Date(patch.releaseDate) : undefined,
          downloadUrl: patch.downloadUrl,
          vendor: patch.vendor,
          platform: patch.platform,
          instructions: patch.instructions,
          verified: patch.verified !== false,
          confidence: this.calculatePatchConfidence(patch)
        }));
      }

      // Parse advisories
      if (Array.isArray(data.advisories)) {
        result.advisories = data.advisories.map((advisory: any) => ({
          id: advisory.id || `ADV-${Date.now()}`,
          title: advisory.title || `Advisory for ${cveId}`,
          url: advisory.url || '',
          source: advisory.source || 'Unknown',
          publishedDate: advisory.publishedDate ? new Date(advisory.publishedDate) : undefined,
          severity: advisory.severity,
          description: advisory.description || '',
          affectedVersions: advisory.affectedVersions || [],
          fixedVersions: advisory.fixedVersions || []
        }));
      }

      // Parse workarounds
      if (Array.isArray(data.workarounds)) {
        result.workarounds = data.workarounds.map((workaround: any) => ({
          description: workaround.description || '',
          steps: Array.isArray(workaround.steps) ? workaround.steps : [],
          effectiveness: workaround.effectiveness || 'partial',
          source: workaround.source,
          limitations: workaround.limitations || []
        }));
      }

      // Parse sources
      if (Array.isArray(data.sources)) {
        result.groundingSources = data.sources.map((source: any) => ({
          url: source.url || '',
          title: source.title || '',
          snippet: source.snippet || '',
          relevanceScore: source.relevanceScore
        }));
      }

      // Handle grounding metadata if present
      if (response.candidates?.[0]?.groundingMetadata) {
        const groundingData = response.candidates[0].groundingMetadata;
        if (groundingData.webSearchQueries) {
          result.searchMetadata.searchQuery = groundingData.webSearchQueries.join('; ');
        }
        if (groundingData.groundingChunks) {
          for (const chunk of groundingData.groundingChunks) {
            if (chunk.web?.uri) {
              result.groundingSources.push({
                url: chunk.web.uri,
                title: chunk.web.title || '',
                snippet: '',
                relevanceScore: chunk.relevanceScore
              });
            }
          }
        }
      }

    } catch (error) {
      this.emit('parse_error', { cveId, error: error.message });
      // Fallback to unstructured parsing
      return this.parseUnstructuredResponse(response.text(), cveId);
    }

    return result;
  }

  /**
   * Parse unstructured text response
   */
  private parseUnstructuredResponse(text: string, cveId: string): PatchSearchResult {
    const result = this.createEmptyResult(cveId);
    
    // Extract version patterns
    const versionPattern = /(?:version|v|fix(?:ed)?\s+in)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9]+)?)/gi;
    const matches = text.matchAll(versionPattern);
    
    for (const match of matches) {
      result.patches.push({
        type: 'version_update',
        version: match[1],
        description: `Update to version ${match[1]}`,
        verified: false,
        confidence: 60
      });
    }

    // Extract URLs
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g;
    const urls = text.match(urlPattern) || [];
    
    for (const url of urls) {
      if (url.includes('advisory') || url.includes('security') || url.includes('bulletin')) {
        result.advisories.push({
          id: `ADV-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          title: `Security Advisory`,
          url: url,
          source: this.extractDomainFromUrl(url),
          description: 'Security advisory found in search results'
        });
      }
    }

    return result;
  }

  /**
   * Enrich results with heuristic detection
   */
  private async enrichWithHeuristics(
    currentResult: PatchSearchResult,
    cveId: string,
    componentName?: string
  ): Promise<PatchSearchResult> {
    const enrichedResult = { ...currentResult };

    // Add heuristic-based patches
    if (componentName) {
      // Common version increment patterns
      const heuristicPatches = this.generateHeuristicPatches(componentName, currentResult);
      enrichedResult.patches.push(...heuristicPatches);
    }

    // Add standard advisory sources
    const standardAdvisories = this.generateStandardAdvisories(cveId, componentName);
    enrichedResult.advisories.push(...standardAdvisories);

    // Deduplicate
    enrichedResult.patches = this.deduplicatePatches(enrichedResult.patches);
    enrichedResult.advisories = this.deduplicateAdvisories(enrichedResult.advisories);

    return enrichedResult;
  }

  /**
   * Generate heuristic patches based on patterns
   */
  private generateHeuristicPatches(
    componentName: string,
    currentResult: PatchSearchResult
  ): PatchInfo[] {
    const patches: PatchInfo[] = [];

    // If we found fixed versions in advisories, create patches for them
    for (const advisory of currentResult.advisories) {
      if (advisory.fixedVersions) {
        for (const version of advisory.fixedVersions) {
          patches.push({
            type: 'version_update',
            version: version,
            description: `Update to fixed version ${version}`,
            vendor: advisory.source,
            verified: false,
            confidence: 70
          });
        }
      }
    }

    return patches;
  }

  /**
   * Generate standard advisory links
   */
  private generateStandardAdvisories(
    cveId: string,
    componentName?: string
  ): AdvisoryInfo[] {
    const advisories: AdvisoryInfo[] = [];

    // NIST NVD
    advisories.push({
      id: `NVD-${cveId}`,
      title: `NIST NVD Entry for ${cveId}`,
      url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      source: 'NIST NVD',
      description: 'Official NIST National Vulnerability Database entry'
    });

    // MITRE
    advisories.push({
      id: `MITRE-${cveId}`,
      title: `MITRE CVE Entry for ${cveId}`,
      url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`,
      source: 'MITRE',
      description: 'Official CVE entry from MITRE'
    });

    // GitHub Advisory Database
    if (componentName) {
      advisories.push({
        id: `GITHUB-${cveId}`,
        title: `GitHub Advisory Database`,
        url: `https://github.com/advisories?query=${cveId}`,
        source: 'GitHub',
        description: 'Search GitHub Security Advisories'
      });
    }

    return advisories;
  }

  /**
   * Calculate patch confidence score
   */
  private calculatePatchConfidence(patch: any): number {
    let confidence = 50; // Base confidence

    if (patch.version) confidence += 20;
    if (patch.downloadUrl) confidence += 15;
    if (patch.vendor) confidence += 10;
    if (patch.releaseDate) confidence += 5;

    return Math.min(100, confidence);
  }

  /**
   * Deduplicate patches
   */
  private deduplicatePatches(patches: PatchInfo[]): PatchInfo[] {
    const seen = new Map<string, PatchInfo>();
    
    for (const patch of patches) {
      const key = `${patch.type}-${patch.version || patch.description}`;
      const existing = seen.get(key);
      
      if (!existing || patch.confidence > existing.confidence) {
        seen.set(key, patch);
      }
    }

    return Array.from(seen.values());
  }

  /**
   * Deduplicate advisories
   */
  private deduplicateAdvisories(advisories: AdvisoryInfo[]): AdvisoryInfo[] {
    const seen = new Map<string, AdvisoryInfo>();
    
    for (const advisory of advisories) {
      const key = advisory.url || advisory.id;
      if (!seen.has(key)) {
        seen.set(key, advisory);
      }
    }

    return Array.from(seen.values());
  }

  /**
   * Extract domain from URL
   */
  private extractDomainFromUrl(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.replace('www.', '');
    } catch {
      return 'Unknown';
    }
  }

  /**
   * Create empty result structure
   */
  private createEmptyResult(cveId: string): PatchSearchResult {
    return {
      patches: [],
      advisories: [],
      workarounds: [],
      groundingSources: [],
      searchMetadata: {
        searchQuery: cveId,
        timestamp: new Date(),
        totalSourcesFound: 0,
        processingTime: 0,
        fallbackUsed: false
      }
    };
  }

  /**
   * Get patch statistics
   */
  async getPatchStatistics(): Promise<{
    totalSearches: number;
    averageProcessingTime: number;
    fallbackUsageRate: number;
    averagePatchesFound: number;
  }> {
    // This would connect to your analytics system
    return {
      totalSearches: 0,
      averageProcessingTime: 0,
      fallbackUsageRate: 0,
      averagePatchesFound: 0
    };
  }
}

// Example usage
export async function example() {
  const service = new EnhancedGeminiPatchService(process.env.GEMINI_API_KEY!);

  // Listen to events
  service.on('search_started', (data) => {
    console.log('🔍 Starting patch search:', data);
  });

  service.on('fallback_search', (data) => {
    console.log('🔄 Using fallback search:', data);
  });

  service.on('search_completed', (data) => {
    console.log('✅ Search completed:', data);
  });

  // Search for patches
  const result = await service.searchPatchesForCVE(
    'CVE-2025-27920',
    'component-name',
    '1.0.0'
  );

  console.log('Patches found:', result.patches.length);
  console.log('Advisories found:', result.advisories.length);
  console.log('Workarounds found:', result.workarounds.length);
  
  // Display patches
  for (const patch of result.patches) {
    console.log(`\n📦 Patch: ${patch.type}`);
    console.log(`   Version: ${patch.version || 'N/A'}`);
    console.log(`   Description: ${patch.description}`);
    console.log(`   Confidence: ${patch.confidence}%`);
    if (patch.downloadUrl) {
      console.log(`   Download: ${patch.downloadUrl}`);
    }
  }
}