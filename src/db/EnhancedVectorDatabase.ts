import { CONSTANTS } from '../utils/constants';
import patchPrompts from '../../docs/Patch_Discovery_RAG_System_Prompts.md?raw';

export class EnhancedVectorDatabase {
  constructor() {
    this.documents = [];
    this.initialized = false;
    this.useGemini = false;
    this.storagePath = 'rag_documents.json';
  }

  async loadConfig() {
    try {
      const res = await fetch('/api/ai-config');
      const cfg = await res.json();
      this.useGemini = cfg.hasGemini;
    } catch {
      this.useGemini = false;
    }
  }

  async createEmbedding(text) {
    if (this.useGemini) {
      try {
        return await this.createGeminiEmbedding(text);
      } catch (error) {
        console.warn('Gemini embedding failed, falling back to local embeddings:', error.message);
        this.useGemini = false;
      }
    }
    return this.createLocalEmbedding(text);
  }

  async createGeminiEmbedding(text) {
    const url = '/api/gemini?model=gemini-embedding-exp-03-07&action=embedContent';
    const requestBody = {
      model: "models/gemini-embedding-exp-03-07",
      content: {
        parts: [{ text: text.substring(0, 2048) }]
      }
    };

    try {
      let response;
      response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`Gemini Embedding API error: ${response.status}`);
      }

      const data = await response.json();
      if (!data.embedding?.values) {
        throw new Error('Invalid embedding response from Gemini API');
      }

      console.log(`🔗 Generated Gemini embedding (${data.embedding.values.length} dimensions) for text: "${text.substring(0, 50)}..."`);
      return data.embedding.values;
    } catch (error) {
      console.error('Gemini embedding error:', error);
      throw error;
    }
  }

  createLocalEmbedding(text) {
    const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 2);
    const tf = {};
    words.forEach(word => {
      tf[word] = (tf[word] || 0) + 1;
    });

    const idf = {};
    const D = this.documents.length;
    const securityTerms = [
      'vulnerability', 'exploit', 'cvss', 'epss', 'cisa', 'kev', 'critical', 'high', 'medium', 'low',
      'remote', 'local', 'authentication', 'authorization', 'injection', 'overflow', 'disclosure',
      'elevation', 'bypass', 'denial', 'service', 'code', 'execution', 'memory', 'corruption',
      'cross', 'site', 'scripting', 'sql', 'command', 'path', 'traversal', 'buffer', 'heap',
      'stack', 'format', 'string', 'integer', 'underflow', 'race', 'condition', 'symlink',
      'privilege', 'escalation', 'information', 'sensitive', 'exposure', 'leak', 'weak',
      'cryptography', 'certificate', 'validation', 'trust', 'boundary', 'sandbox', 'escape'
    ];
    const allTerms = [...new Set([...Object.keys(tf), ...securityTerms])];
    allTerms.forEach(term => {
      const docsWithTerm = this.documents.filter(doc => doc.content.toLowerCase().includes(term)).length;
      idf[term] = Math.log((D + 1) / (docsWithTerm + 1)) + 1;
    });

    const vector = allTerms.slice(0, 200).map(term => (tf[term] || 0) * (idf[term] || 1));
    const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
    return magnitude > 0 ? vector.map(val => val / magnitude) : vector;
  }

  cosineSimilarity(vec1, vec2) {
    if (vec1.length !== vec2.length) {
      const maxLength = Math.max(vec1.length, vec2.length);
      const paddedVec1 = [...vec1, ...new Array(maxLength - vec1.length).fill(0)];
      const paddedVec2 = [...vec2, ...new Array(maxLength - vec2.length).fill(0)];
      vec1 = paddedVec1;
      vec2 = paddedVec2;
    }
    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;
    for (let i = 0; i < vec1.length; i++) {
      dotProduct += vec1[i] * vec2[i];
      norm1 += vec1[i] * vec1[i];
      norm2 += vec2[i] * vec2[i];
    }
    const magnitude1 = Math.sqrt(norm1);
    const magnitude2 = Math.sqrt(norm2);
    if (magnitude1 === 0 || magnitude2 === 0) return 0;
    return dotProduct / (magnitude1 * magnitude2);
  }

  async saveDocuments(filePath = this.storagePath) {
    try {
      if (typeof window === 'undefined') {
        const fs = await import('fs/promises');
        await fs.writeFile(filePath, JSON.stringify(this.documents, null, 2), 'utf8');
      } else {
        localStorage.setItem('ragDatabase', JSON.stringify(this.documents));
      }
      console.log(`💾 Saved ${this.documents.length} RAG documents to ${filePath}`);
    } catch (error) {
      console.error('Failed to save RAG documents:', error);
    }
  }

  async loadDocuments(filePath = this.storagePath) {
    try {
      let data;
      if (typeof window === 'undefined') {
        const fs = await import('fs/promises');
        data = await fs.readFile(filePath, 'utf8');
      } else {
        data = localStorage.getItem('ragDatabase');
      }
      if (data) {
        this.documents = JSON.parse(data);
        this.initialized = this.documents.length > 0;
        console.log(`📂 Loaded ${this.documents.length} RAG documents from ${filePath}`);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error('Failed to load RAG documents:', error);
      } else {
        console.log('No existing RAG database found.');
      }
    }
  }

  async addDocument(content, metadata = {}) {
    const embedding = await this.createEmbedding(content);
    const doc = {
      id: Date.now() + Math.random(),
      content,
      metadata,
      embedding,
      timestamp: new Date().toISOString(),
      embeddingType: this.useGemini ? 'gemini' : 'local'
    };
    this.documents.push(doc);
    console.log(`📚 Added document to RAG database (${doc.embeddingType} embedding):`, metadata.title || 'Untitled');
    return doc.id;
  }

  async search(query, k = 8) {
    if (this.documents.length === 0) {
      console.warn('⚠️ RAG database is empty - initializing with default knowledge base');
      await this.initialize();
    }
    const queryEmbedding = await this.createEmbedding(query);
    const similarities = this.documents.map(doc => ({
      ...doc,
      similarity: this.cosineSimilarity(queryEmbedding, doc.embedding)
    }));
    const results = similarities
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, k)
      .filter(doc => doc.similarity > 0.05);
    const embeddingTypes = results.map(r => r.embeddingType).filter(Boolean);
    const hasGemini = embeddingTypes.includes('gemini');
    console.log(`🔍 RAG search for "${query}" found ${results.length} relevant documents from ${this.documents.length} total (${hasGemini ? 'Using Gemini embeddings' : 'Using local embeddings'})`);
    return results;
  }

  async initialize() {
    if (this.initialized) return;
    await this.loadConfig();
    await this.loadDocuments();
    if (this.initialized) {
      await this.ensureInitialized();
      return;
    }
    console.log(`🚀 Initializing Enhanced RAG Vector Database with ${this.useGemini ? 'Gemini' : 'local'} embeddings...`);
    await this.addComprehensiveSecurityKnowledgeBase();
    this.initialized = true;
    await this.saveDocuments();
    console.log(`✅ RAG database initialized with ${this.documents.length} security documents using ${this.useGemini ? 'Gemini' : 'local'} embeddings`);
  }

  async addComprehensiveSecurityKnowledgeBase() {
    const comprehensiveKnowledgeBase = [
      {
        title: "CVE Severity Classification Framework",
        content: "CVE severity classification uses CVSS (Common Vulnerability Scoring System) scores ranging from 0.0 to 10.0. Critical vulnerabilities (9.0-10.0) require immediate attention, especially when combined with high EPSS scores. High severity (7.0-8.9) vulnerabilities need urgent patching. Medium (4.0-6.9) and Low (0.1-3.9) require prioritization based on environmental factors and exploitability.",
        category: "severity",
        tags: ["cvss", "severity", "classification", "priority", "scoring"]
      },
      {
        title: "Threat Intelligence Concepts",
        content: "Threat intelligence involves the collection, analysis, and dissemination of information about current and potential attacks. Key concepts include Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), and threat actor profiling. High-quality threat intelligence is timely, accurate, and actionable.",
        category: "threat-intelligence",
        tags: ["threat-intel", "iocs", "ttps", "threat-actors"]
      },
      {
        title: "Patch Management Best Practices",
        content: "Effective patch management involves identifying, acquiring, testing, and installing patches in a timely manner. Prioritization should be based on a combination of factors, including CVSS score, EPSS score, and asset criticality. Automated patch management tools can help to streamline the process.",
        category: "patch-management",
        tags: ["patching", "remediation", "automation"]
      }
    ];
    for (const item of comprehensiveKnowledgeBase) {
      await this.addDocument(item.content, {
        title: item.title,
        category: item.category,
        tags: item.tags,
        source: 'comprehensive-knowledge-base'
      });
    }
    const cveExamples = [
      {
        title: "High-Impact CVE Characteristics",
        content: "High-impact CVEs typically affect widely-deployed software, require no authentication, allow remote code execution, and have public exploit code available. Examples include Heartbleed (CVE-2014-0160), WannaCry SMB vulnerability (CVE-2017-0144), and Log4Shell (CVE-2021-44228). These vulnerabilities cause widespread internet disruption.",
        category: "high-impact-cves",
        tags: ["heartbleed", "wannacry", "log4shell", "widespread-impact", "rce"]
      },
      {
        title: "Low-Impact CVE Characteristics",
        content: "Low-impact CVEs typically affect software that is not widely deployed, require local access, or have a high degree of complexity to exploit. For example, a vulnerability in a command-line tool that requires a specific set of flags to be passed to it would likely be considered low-impact.",
        category: "low-impact-cves",
        tags: ["low-impact", "local-access", "high-complexity"]
      }
    ];
    for (const item of cveExamples) {
      await this.addDocument(item.content, {
        title: item.title,
        category: item.category,
        tags: item.tags,
        source: 'cve-knowledge-base'
      });
    }

    if (patchPrompts) {
      await this.addDocument(patchPrompts, {
        title: 'Patch Discovery System Prompts',
        category: 'prompt-engineering',
        tags: ['patch', 'rag', 'prompt'],
        source: 'internal-docs'
      });
    }
  }

  async ensureInitialized() {
    if (!this.initialized) {
      await this.loadDocuments();
    }
    if (this.documents.length === 0) {
      console.log('🔄 RAG database empty, reinitializing...');
      await this.initialize();
    } else if (this.useGemini && this.documents.some(doc => doc.embeddingType !== 'gemini')) {
      console.log('🔄 Upgrading to Gemini embeddings...');
      const localEmbeddedDocs = this.documents.filter(doc => doc.embeddingType !== 'gemini');
      if (localEmbeddedDocs.length > 0) {
        console.log(`🔄 Re-embedding ${localEmbeddedDocs.length} documents with Gemini embeddings...`);
        const batchSize = 5;
        for (let i = 0; i < localEmbeddedDocs.length; i += batchSize) {
          const batch = localEmbeddedDocs.slice(i, i + batchSize);
          await Promise.all(batch.map(async (doc) => {
            try {
              const newEmbedding = await this.createGeminiEmbedding(doc.content);
              doc.embedding = newEmbedding;
              doc.embeddingType = 'gemini';
            } catch (error) {
              console.warn(`Failed to re-embed document:`, error.message);
            }
          }));
          if (i + batchSize < localEmbeddedDocs.length) {
            await new Promise(resolve => setTimeout(resolve, 1000));
          }
        }
      }
      await this.saveDocuments();
    }
  }
}

export const ragDatabase = new EnhancedVectorDatabase();
