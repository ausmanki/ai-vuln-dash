// src/services/ValidationService.ts
import {
  CVEValidationData,
  BaseCVEInfo,
  PatchInfo, // Ensure this is correctly imported if defined in cveData.ts
  AdvisoryInfo, // Ensure this is correctly imported
  // Import other necessary types like AIThreatIntelData (actual name may vary), PatchData
  // For now, using 'any' for undefined complex types from other services.
} from '../types/cveData';
import { APIService } from './APIService'; // Assuming APIService might be needed for some sub-fetches, though ideally data is passed in.

// Placeholder for actual AI Intel and PatchData types
// These should be replaced with their actual definitions from other parts of the application
interface AIThreatIntelDataPlaceholder {
  summary?: string;
  technicalAnalysis?: { text?: string };
  searchResults?: Array<{ snippet?: string; title?: string; url?: string }>; // Example structure
  // Add other fields that might contain relevant text or structured info from AI
  vendorDisputes?: Array<{ source: string; detail: string }>; // Example if AI can structure this
  researcherOpinions?: Array<{ source: string; opinion: string; url: string }>; // Example
}

interface PatchDataPlaceholder {
  patches?: Array<PatchInfo & { vendor: string; product?: string; downloadUrl?: string; advisoryUrl?: string; description?: string }>;
  advisories?: Array<AdvisoryInfo & { source: string; url?: string; title?: string }>;
  searchSummary?: any;
}


export class ValidationService {
  public static async validateAIFindings(
    cveId: string,
    nvdData: BaseCVEInfo | null,
    aiIntel: AIThreatIntelDataPlaceholder | null, // Using placeholder
    patchAdvisoryData: PatchDataPlaceholder | null, // Using placeholder
  ): Promise<CVEValidationData> {

    const validationOutput: CVEValidationData = {
      cveId,
      vendorDispute: { hasDispute: false },
      falsePositive: { isFalsePositive: false },
      vendorConfirmation: { hasConfirmation: false, patches: [], advisories: [] },
      researcherValidation: { consensus: 'Unknown', evidence: [] },
      legitimacySummary: '',
      legitimacyScore: null,
      status: 'UNKNOWN',
      confidence: 'Low',
      validationSources: [],
      disputes: [],
      lastUpdated: new Date().toISOString(),
    };

    // --- Populate Vendor Confirmation ---
    if (patchAdvisoryData) {
      const { patches, advisories } = patchAdvisoryData;
      const collectedPatches: PatchInfo[] = [];
      const collectedAdvisories: AdvisoryInfo[] = [];

      if (patches && patches.length > 0) {
        validationOutput.vendorConfirmation!.hasConfirmation = true;
        patches.forEach(p => collectedPatches.push({
          vendor: p.vendor || 'N/A',
          product: p.product || 'N/A',
          patchVersion: p.patchVersion,
          downloadUrl: p.downloadUrl,
          advisoryUrl: p.advisoryUrl,
          releaseDate: p.releaseDate,
          description: p.description,
          source: p.source || 'Patch Data',
          citationUrl: p.citationUrl,
        }));
      }
      if (advisories && advisories.length > 0) {
        validationOutput.vendorConfirmation!.hasConfirmation = true;
        advisories.forEach(a => collectedAdvisories.push({
          source: a.source || 'Advisory Data',
          url: a.url,
          title: a.title,
          // Map other fields if AdvisoryInfo in CVEValidationData expects them
        }));
      }
      validationOutput.vendorConfirmation!.patches = collectedPatches;
      validationOutput.vendorConfirmation!.advisories = collectedAdvisories;

      if (validationOutput.vendorConfirmation!.hasConfirmation) {
        validationOutput.vendorConfirmation!.details = `Found ${collectedPatches.length} patch(es) and ${collectedAdvisories.length} advisory(ies).`;
        validationOutput.validationSources?.push('Vendor Patches/Advisories');
      }
    }

    // --- Populate False Positive and Dispute from NVD ---
    if (nvdData?.cve) {
      validationOutput.validationSources?.push('NVD');
      if (nvdData.cve.vulnStatus === 'Rejected' || nvdData.cve.vulnStatus === 'Withdrawn') { // Assuming 'Withdrawn' is a possible status
        validationOutput.falsePositive!.isFalsePositive = true;
        validationOutput.falsePositive!.reason = `NVD Status: ${nvdData.cve.vulnStatus}`;
        validationOutput.falsePositive!.source = 'NVD';
      }
      // NVD can also mark as DISPUTED. This often means a vendor disputes it.
      if (nvdData.cve.vulnStatus === 'Disputed') {
        validationOutput.vendorDispute!.hasDispute = true;
        validationOutput.vendorDispute!.details = nvdData.cve.descriptions?.find(d => d.lang === 'en')?.value || 'Marked as DISPUTED in NVD.';
        validationOutput.vendorDispute!.source = 'NVD';
        // Also add to the main 'disputes' array for compatibility/detail
        validationOutput.disputes?.push({
            source: 'NVD',
            reason: validationOutput.vendorDispute!.details || 'Disputed',
            date: nvdData.cve.lastModified // Or published date
        });
      }
    }

    // --- Process AI Intelligence (aiIntel) for Disputes, Researcher Validation, and further False Positive/Confirmation signals ---
    if (aiIntel) {
      validationOutput.validationSources?.push('AI Web Search Analysis');
      const aiTextContent = this.extractTextFromAIIntel(aiIntel);

      // Vendor Disputes from AI
      const disputeKeywords = [
        'vendor disputes this',
        'vendor does not consider this a vulnerability',
        'vendor rejected this claim',
        'will not fix this issue',
        'out of scope for vendor',
        'vendor denies',
        'vendor claims not exploitable'
      ];
      const disputeInfo = this.findKeywordsAndContext(aiTextContent, disputeKeywords, aiIntel.searchResults || []);
      if (disputeInfo.found && !validationOutput.vendorDispute?.hasDispute) { // Prioritize NVD if already set
        validationOutput.vendorDispute = {
          hasDispute: true,
          details: disputeInfo.context || 'AI analysis suggests vendor dispute.',
          source: disputeInfo.sourceURL || 'AI Web Search',
        };
      }

      // False Positives from AI
      const fpKeywords = ['cve withdrawn by reporter', 'incorrectly assigned cve', 'vulnerability does not exist', 'confirmed false positive'];
      const fpInfo = this.findKeywordsAndContext(aiTextContent, fpKeywords, aiIntel.searchResults || []);
      if (fpInfo.found && !validationOutput.falsePositive?.isFalsePositive) { // Prioritize NVD
        validationOutput.falsePositive = {
          isFalsePositive: true,
          reason: fpInfo.context || 'AI analysis suggests false positive.',
          source: fpInfo.sourceURL || 'AI Web Search',
        };
      }

      // Researcher Validation from AI
      const positiveResearcherKeywords = [
        'security researcher analysis of',
        'technical write-up for cve',
        'poc available for',
        'confirmed by security researchers',
        'public exploit for'
      ];
      const negativeResearcherKeywords = [
        'no public exploit',
        'no evidence of exploit',
        'vendor denies',
        'exploit not reproducible',
        'researchers question',
        'unconfirmed vulnerability'
      ];

      const positiveEvidence = this.findKeywordsAndContext(
        aiTextContent,
        positiveResearcherKeywords,
        aiIntel.searchResults || [],
        true
      ) as Array<{ context: string; sourceURL?: string; sourceTitle?: string }>;

      const negativeEvidence = this.findKeywordsAndContext(
        aiTextContent,
        negativeResearcherKeywords,
        aiIntel.searchResults || [],
        true
      ) as Array<{ context: string; sourceURL?: string; sourceTitle?: string }>;

      const evidenceCombined = [...positiveEvidence, ...negativeEvidence];
      let consensus: 'Positive' | 'Negative' | 'Mixed' | 'Unknown' = 'Unknown';
      if (positiveEvidence.length > 0 && negativeEvidence.length > 0) {
        consensus = 'Mixed';
      } else if (positiveEvidence.length > 0) {
        consensus = 'Positive';
      } else if (negativeEvidence.length > 0) {
        consensus = 'Negative';
      }

      if (consensus !== 'Unknown') {
        validationOutput.researcherValidation!.consensus = consensus;
        validationOutput.researcherValidation!.summary = `${positiveEvidence.length} positive and ${negativeEvidence.length} negative source(s) found.`;
        validationOutput.researcherValidation!.evidence = evidenceCombined.map(ev => ({
          text: ev.context,
          url: ev.sourceURL,
          source: ev.sourceTitle || 'AI Web Search'
        }));
      }
    }

    // --- Populate Legitimacy Summary and Score ---
    validationOutput.legitimacySummary = this.generateLegitimacySummary(validationOutput);
    validationOutput.legitimacyScore = this.calculateLegitimacyScore(validationOutput);

    // --- Determine overall status and confidence ---
    if (validationOutput.falsePositive?.isFalsePositive) {
        validationOutput.status = 'INVALID';
        validationOutput.recommendation = `Likely False Positive or Rejected. Reason: ${validationOutput.falsePositive.reason || 'Not specified'}`;
        validationOutput.confidence = 'High';
    } else if (validationOutput.vendorDispute?.hasDispute) {
        validationOutput.status = 'DISPUTED';
        validationOutput.recommendation = `Disputed by vendor. Details: ${validationOutput.vendorDispute.details || 'Not specified'}. Investigate carefully.`;
        validationOutput.confidence = 'High'; // Confidence in the "disputed" status
    } else if (validationOutput.vendorConfirmation?.hasConfirmation) {
        validationOutput.status = 'VALID';
        validationOutput.recommendation = 'Considered valid based on vendor confirmation (patches/advisories available).';
        validationOutput.confidence = 'High';
    } else if (validationOutput.researcherValidation?.consensus === 'Positive' && (validationOutput.researcherValidation.evidence?.length || 0) > 0) {
        validationOutput.status = 'VALID';
        validationOutput.recommendation = 'Likely valid based on researcher analysis/PoC.';
        validationOutput.confidence = 'Medium';
    } else {
        validationOutput.status = 'NEEDS_VERIFICATION';
        validationOutput.recommendation = 'Legitimacy is unclear based on available automated analysis. Further verification may be needed.';
        validationOutput.confidence = 'Low';
    }
    validationOutput.lastUpdated = new Date().toISOString();

    return validationOutput;
  }

  private static extractTextFromAIIntel(aiIntel: AIThreatIntelDataPlaceholder): string {
    let text = '';
    if (aiIntel?.summary) text += aiIntel.summary.toLowerCase() + ' ';
    if (aiIntel?.technicalAnalysis?.text) text += aiIntel.technicalAnalysis.text.toLowerCase() + ' ';
    if (aiIntel?.searchResults) {
        aiIntel.searchResults.forEach(res => {
            if (res.snippet) text += res.snippet.toLowerCase() + ' ';
            if (res.title) text += res.title.toLowerCase() + ' ';
        });
    }
    // Add other text sources from aiIntel if necessary
    return text;
  }

  private static findKeywordsAndContext(
    textToSearch: string,
    keywords: string[],
    searchResults: Array<{ snippet?: string; title?: string; url?: string }>,
    collectMultiple = false
  ): { found: boolean; context?: string; sourceURL?: string; sourceTitle?: string; } | Array<{context: string; sourceURL?: string; sourceTitle?: string;}> {

    const foundItems: Array<{context: string; sourceURL?: string; sourceTitle?: string;}> = [];

    // First, check direct textToSearch (e.g., overall summaries from AI)
    for (const keyword of keywords) {
      const kwLower = keyword.toLowerCase();
      let index = textToSearch.indexOf(kwLower);
      while (index !== -1) {
        const start = Math.max(0, index - 70); // Extend context window
        const end = Math.min(textToSearch.length, index + kwLower.length + 200); // Extend context window
        const contextSnippet = textToSearch.substring(start, end);
        const item = { context: `...${contextSnippet}...`, sourceURL: undefined, sourceTitle: "AI Summary/Analysis" };
        if (collectMultiple) {
          foundItems.push(item);
        } else {
          return { found: true, ...item };
        }
        index = textToSearch.indexOf(kwLower, index + 1);
      }
    }

    // Then, iterate through search results for more specific context and URLs
    if (searchResults) {
        for (const res of searchResults) {
            const resText = ((res.title || '') + ' ' + (res.snippet || '')).toLowerCase();
            for (const keyword of keywords) {
                const kwLower = keyword.toLowerCase();
                if (resText.includes(kwLower)) {
                    const item = { context: `${res.title || ''}: ${res.snippet || ''}`, sourceURL: res.url, sourceTitle: res.title || res.url};
                    if (collectMultiple) {
                        if (!foundItems.some(fi => fi.sourceURL === item.sourceURL && fi.context.includes(keyword))) { // Avoid duplicates for same keyword from same source
                           foundItems.push(item);
                        }
                    } else {
                        return { found: true, ...item };
                    }
                }
            }
        }
    }

    if (collectMultiple) return foundItems;
    return { found: false };
  }

  private static generateLegitimacySummary(validationData: CVEValidationData): string {
    let summaryParts: string[] = [];
    summaryParts.push(`Assessment for ${validationData.cveId}:`);

    if (validationData.falsePositive?.isFalsePositive) {
      summaryParts.push(`Status: LIKELY FALSE POSITIVE/REJECTED (Reason: ${validationData.falsePositive.reason || 'N/A'}, Source: ${validationData.falsePositive.source || 'N/A'}).`);
    } else if (validationData.vendorDispute?.hasDispute) {
      summaryParts.push(`Status: DISPUTED BY VENDOR (Details: ${validationData.vendorDispute.details || 'N/A'}, Source: ${validationData.vendorDispute.source || 'N/A'}).`);
    } else if (validationData.vendorConfirmation?.hasConfirmation) {
      summaryParts.push(`Status: VENDOR CONFIRMED (Patches/Advisories: ${validationData.vendorConfirmation.details || 'Available'}).`);
    } else if (validationData.researcherValidation?.consensus === 'Positive') {
      summaryParts.push(`Status: RESEARCHER VALIDATED (Evidence found: ${validationData.researcherValidation.summary || 'Positive signals from researchers'}).`);
    } else if (validationData.researcherValidation?.consensus === 'Negative') {
      summaryParts.push(`Status: RESEARCHERS DISPUTE VALIDITY (Evidence found: ${validationData.researcherValidation.summary || 'Negative assessments from researchers'}).`);
    } else if (validationData.researcherValidation?.consensus === 'Mixed') {
      summaryParts.push(`Status: MIXED RESEARCHER OPINIONS (Evidence found: ${validationData.researcherValidation.summary || 'Conflicting assessments from researchers'}).`);
    } else {
      summaryParts.push(`Status: UNCERTAIN/NEEDS VERIFICATION (No strong positive or negative legitimacy signals found).`);
    }

    if (validationData.legitimacyScore !== null) {
      summaryParts.push(`Calculated Legitimacy Score: ${validationData.legitimacyScore}/100.`);
    }
    return summaryParts.join(' ');
  }

  private static calculateLegitimacyScore(validationData: CVEValidationData): number {
    let score = 50;

    if (validationData.falsePositive?.isFalsePositive) return 5;
    if (validationData.vendorDispute?.hasDispute) return 20;

    if (validationData.vendorConfirmation?.hasConfirmation) {
      score += 40;
      if ((validationData.vendorConfirmation.patches?.length || 0) > 0) score +=5; // Extra for direct patches
    }

    if (validationData.researcherValidation?.consensus === 'Positive') {
      score += Math.min(25, 5 + (validationData.researcherValidation.evidence?.length || 0) * 5); // More evidence, higher score up to a cap
    } else if (validationData.researcherValidation?.consensus === 'Negative') {
      score -= 30;
    } else if (validationData.researcherValidation?.consensus === 'Mixed') {
      score -= 10;
    }

    // If NVD status is just "Analyzed" or similar without specific dispute/rejection, and no other signals.
    if (validationData.status === 'UNKNOWN' || validationData.status === 'NEEDS_VERIFICATION') {
        if (!validationData.vendorConfirmation?.hasConfirmation && validationData.researcherValidation?.consensus === 'Unknown') {
            score -= 20; // Less confidence if no positive signals
        }
    }

    return Math.max(0, Math.min(100, score));
  }
}
