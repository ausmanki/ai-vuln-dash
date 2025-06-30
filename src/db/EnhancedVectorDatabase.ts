import { CONSTANTS } from '../utils/constants';

export class EnhancedVectorDatabase {
  constructor() {
    this.documents = [];
    this.initialized = false;
    this.geminiApiKey = null;
  }

  setApiKey(apiKey) {
    this.geminiApiKey = apiKey;
  }

  async createEmbedding(text) {
    if (this.geminiApiKey) {
      try {
        return await this.createGeminiEmbedding(text);
      } catch (error) {
        console.warn('Gemini embedding failed, falling back to local embeddings:', error.message);
        return this.createLocalEmbedding(text);
      }
    }
    return this.createLocalEmbedding(text);
  }

  async createGeminiEmbedding(text) {
    const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-exp-03-07:embedContent';
    const requestBody = {
      model: "models/gemini-embedding-exp-03-07",
      content: {
        parts: [{ text: text.substring(0, 2048) }]
      }
    };

    try {
      let response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: {
            'x-goog-api-key': this.geminiApiKey,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        });
      } catch (corsError) {
        console.log('Direct Gemini embedding blocked by CORS, trying proxy...');
        const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
        response = await fetch(proxyUrl, {
          method: 'POST',
          headers: {
            'x-goog-api-key': this.geminiApiKey,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        });
      }

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
    const wordFreq = {};
    words.forEach(word => {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    });
    const securityTerms = [
      'vulnerability', 'exploit', 'cvss', 'epss', 'cisa', 'kev', 'critical', 'high', 'medium', 'low',
      'remote', 'local', 'authentication', 'authorization', 'injection', 'overflow', 'disclosure',
      'elevation', 'bypass', 'denial', 'service', 'code', 'execution', 'memory', 'corruption',
      'cross', 'site', 'scripting', 'sql', 'command', 'path', 'traversal', 'buffer', 'heap',
      'stack', 'format', 'string', 'integer', 'underflow', 'race', 'condition', 'symlink',
      'privilege', 'escalation', 'information', 'sensitive', 'exposure', 'leak', 'weak',
      'cryptography', 'certificate', 'validation', 'trust', 'boundary', 'sandbox', 'escape'
    ];
    const allTerms = [...new Set([...Object.keys(wordFreq), ...securityTerms])];
    const vector = allTerms.slice(0, 200).map(term => wordFreq[term] || 0);
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

  async addDocument(content, metadata = {}) {
    const embedding = await this.createEmbedding(content);
    const doc = {
      id: Date.now() + Math.random(),
      content,
      metadata,
      embedding,
      timestamp: new Date().toISOString(),
      embeddingType: this.geminiApiKey ? 'gemini' : 'local'
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

  async initialize(geminiApiKey = null) {
    if (this.initialized) return;
    if (geminiApiKey) {
      this.setApiKey(geminiApiKey);
    }
    console.log(`🚀 Initializing Enhanced RAG Vector Database with ${this.geminiApiKey ? 'Gemini' : 'local'} embeddings...`);
    await this.addComprehensiveSecurityKnowledgeBase();
    this.initialized = true;
    console.log(`✅ RAG database initialized with ${this.documents.length} security documents using ${this.geminiApiKey ? 'Gemini' : 'local'} embeddings`);
  }

  async addComprehensiveSecurityKnowledgeBase() {
    const comprehensiveKnowledgeBase = [
      {
        title: "CVE Severity Classification Framework",
        content: "CVE severity classification uses CVSS (Common Vulnerability Scoring System) scores ranging from 0.0 to 10.0. Critical vulnerabilities (9.0-10.0) require immediate attention, especially when combined with high EPSS scores. High severity (7.0-8.9) vulnerabilities need urgent patching. Medium (4.0-6.9) and Low (0.1-3.9) require prioritization based on environmental factors and exploitability.",
        category: "severity",
        tags: ["cvss", "severity", "classification", "priority", "scoring"]
      },
      // ... (rest of the knowledge base items)
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
      // ... (rest of the cve examples)
    ];
    for (const item of cveExamples) {
      await this.addDocument(item.content, {
        title: item.title,
        category: item.category,
        tags: item.tags,
        source: 'cve-knowledge-base'
      });
    }
  }

  async ensureInitialized(geminiApiKey = null) {
    if (this.documents.length === 0) {
      console.log('🔄 RAG database empty, reinitializing...');
      await this.initialize(geminiApiKey);
    } else if (geminiApiKey && !this.geminiApiKey) {
      console.log('🔄 Upgrading to Gemini embeddings...');
      this.setApiKey(geminiApiKey);
      const localEmbeddedDocs = this.documents.filter(doc => doc.embeddingType !== 'gemini');
      if (localEmbeddedDocs.length > 0) {
        console.log(`🔄 Re-embedding ${localEmbeddedDocs.length} documents with Gemini embeddings...`);
        for (let i = 0; i < Math.min(localEmbeddedDocs.length, 5); i++) {
          try {
            const doc = localEmbeddedDocs[i];
            const newEmbedding = await this.createGeminiEmbedding(doc.content);
            doc.embedding = newEmbedding;
            doc.embeddingType = 'gemini';
            if (i < 4) await new Promise(resolve => setTimeout(resolve, 1000));
          } catch (error) {
            console.warn(`Failed to re-embed document ${i}:`, error.message);
          }
        }
      }
    }
  }
}

export const ragDatabase = new EnhancedVectorDatabase();
