import { logger } from '../utils/logger';
// GeminiRateLimiter.ts - Add this to handle Gemini rate limits better

class GeminiRateLimiter {
  private requestQueue: Array<() => Promise<any>> = [];
  private isProcessing = false;
  private lastRequestTime = 0;
  private minDelayBetweenRequests = 1000; // 1 second minimum between requests
  private maxConcurrentRequests = 1;
  
  async addRequest<T>(requestFn: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      this.requestQueue.push(async () => {
        try {
          const result = await requestFn();
          resolve(result);
        } catch (error) {
          reject(error);
        }
      });
      
      this.processQueue();
    });
  }
  
  private async processQueue() {
    if (this.isProcessing || this.requestQueue.length === 0) {
      return;
    }
    
    this.isProcessing = true;
    
    while (this.requestQueue.length > 0) {
      // Ensure minimum delay between requests
      const now = Date.now();
      const timeSinceLastRequest = now - this.lastRequestTime;
      
      if (timeSinceLastRequest < this.minDelayBetweenRequests) {
        const delay = this.minDelayBetweenRequests - timeSinceLastRequest;
        logger.debug(`⏱️ Rate limiting: waiting ${delay}ms before next request`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
      
      const request = this.requestQueue.shift();
      if (request) {
        this.lastRequestTime = Date.now();
        
        try {
          await request();
        } catch (error) {
          logger.error('Request failed:', error);
        }
      }
    }
    
    this.isProcessing = false;
  }
  
  // Increase delay after 503 errors
  increaseDelay() {
    this.minDelayBetweenRequests = Math.min(this.minDelayBetweenRequests * 2, 10000); // Max 10 seconds
    logger.debug(`📈 Increased rate limit delay to ${this.minDelayBetweenRequests}ms`);
  }
  
  // Reset delay after successful requests
  resetDelay() {
    this.minDelayBetweenRequests = 1000;
  }
}

// Create a singleton instance
export const geminiRateLimiter = new GeminiRateLimiter();

// Enhanced fetch function with rate limiting
export async function fetchWithGeminiRateLimit(
  apiUrl: string,
  requestBody: any,
  apiKey: string,
  maxRetries: number = 3
): Promise<any> {
  return geminiRateLimiter.addRequest(async () => {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        logger.debug(`🌐 Gemini API request (attempt ${attempt}/${maxRetries})`);
        
        const response = await fetch(apiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        });
        
        if (response.ok) {
          geminiRateLimiter.resetDelay();
          return await response.json();
        }
        
        const errorText = await response.text();
        const errorData = JSON.parse(errorText);
        
        if (response.status === 503) {
          logger.debug(`⚠️ Gemini model overloaded (attempt ${attempt}/${maxRetries})`);
          geminiRateLimiter.increaseDelay();
          
          if (attempt < maxRetries) {
            // Wait with exponential backoff
            const backoffDelay = Math.min(1000 * Math.pow(2, attempt), 30000);
            logger.debug(`⏳ Waiting ${backoffDelay}ms before retry...`);
            await new Promise(resolve => setTimeout(resolve, backoffDelay));
            continue;
          }
        }
        
        throw new Error(`Gemini API error: ${response.status} - ${errorData.error?.message || 'Unknown error'}`);
        
      } catch (error) {
        lastError = error;
        
        if (attempt === maxRetries) {
          throw error;
        }
      }
    }
    
    throw lastError;
  });
}

// Update your fetchWithAIWebSearch to use the rate limiter
export async function fetchWithAIWebSearchEnhanced(
  url: string,
  prompt: string,
  settings: any
): Promise<any> {
  const useGemini = !!settings.geminiApiKey && !settings.openAiApiKey;
  
  if (useGemini) {
    const model = settings.geminiModel || 'gemini-2.5-flash';
    const requestBody = {
      contents: [{
        parts: [{
          text: prompt
        }]
      }],
      generationConfig: {
        temperature: 0.3,
        topK: 1,
        topP: 0.8,
        maxOutputTokens: 2048,
        candidateCount: 1
      },
      tools: [{
        google_search: {}
      }]
    };
    
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${settings.geminiApiKey}`;
    
    try {
      const data = await fetchWithGeminiRateLimit(apiUrl, requestBody, settings.geminiApiKey);
      
      // Process the response
      if (data.candidates?.[0]?.content?.parts?.[0]?.text) {
        return {
          answer: data.candidates[0].content.parts[0].text,
          groundingMetadata: data.candidates[0].groundingMetadata
        };
      }
      
      throw new Error('Invalid response from Gemini API');
      
    } catch (error) {
      logger.error('Gemini API error:', error);
      throw error;
    }
  }
  
  // Handle OpenAI case...
  // (keep your existing OpenAI logic)
