// Regex to identify CVE patterns (e.g., CVE-YYYY-NNNN or CVE-YYYY-NNNNN...)
import { CVE_REGEX } from '../utils/cveRegex';
import { logger } from '../utils/logger';

/**
 * Reads a CSV file and extracts all valid CVE ID patterns from its content.
 * It assumes CVEs can be anywhere in the CSV data.
 *
 * @param file The CSV file object to parse.
 * @returns A Promise that resolves to a deduplicated array of found CVE ID strings.
 */
export async function extractCVEsFromCSV(file: File): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = (event) => {
      try {
        const csvContent = event.target?.result as string;
        if (!csvContent) {
          resolve([]);
          return;
        }

        // Use the regex to find all matches in the entire CSV content.
        // This is a simple approach; more robust CSV parsing might involve
        // processing row by row, cell by cell if specific columns are targeted.
        // For now, just scan the whole text content.
        const matches = csvContent.matchAll(CVE_REGEX);
        const cveIds = new Set<string>();

        for (const match of matches) {
          cveIds.add(match[0].toUpperCase());
        }

        resolve(Array.from(cveIds));
      } catch (error) {
        logger.error("Error parsing CSV content:", error);
        reject(new Error("Failed to parse CSV file. Ensure it's a valid text-based CSV."));
      }
    };

    reader.onerror = (error) => {
      logger.error("Error reading file:", error);
      reject(new Error("Failed to read the file."));
    };

    reader.readAsText(file); // Read the file as plain text
  });
}

import * as pdfjsLib from 'pdfjs-dist/build/pdf';
import { PDFTextItem } from '../types/pdf';
// You might need to configure the worker path depending on your bundler.
// For Vite, often it can resolve this, or you might need:
// import pdfjsWorker from 'pdfjs-dist/build/pdf.worker.entry';
// if (typeof window !== 'undefined') { // Check if running in browser
//   pdfjsLib.GlobalWorkerOptions.workerSrc = pdfjsWorker;
// }
// A simpler approach for Vite if the above doesn't work out of the box or causes issues:
if (typeof window !== 'undefined' && !pdfjsLib.GlobalWorkerOptions.workerSrc) {
    // Construct a URL to the worker based on how pdfjs-dist is installed and served.
    // This often means copying the worker file to your public directory and referencing it,
    // or if Vite includes it in node_modules assets, a relative path might work.
    // A common pattern is to set it up from a CDN or a local copy in `public`.
    // For Vite, you might need to ensure the worker file is copied to `dist/` and then use a relative path.
    // Let's try a common approach that often works with module bundlers:
    // pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;
    // For local serving with Vite, it's often:
    // Assuming pdf.worker.min.js is available at this path after build or via node_modules.
    // The exact path might need adjustment based on your project structure and Vite config.
    // This can be tricky. A common solution is to host pdf.worker.js in your public folder.
    // For now, let's assume a setup where it might be found relative to the pdf.js module itself.
    // This often needs to be: `pdfjsLib.GlobalWorkerOptions.workerSrc = new URL('pdfjs-dist/build/pdf.worker.min.js', import.meta.url).toString();`
    // However, `import.meta.url` can be problematic in some contexts or if not using ES modules for workers.
    // A more direct approach for Vite if you copy the worker to public:
    // pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.js'; // if pdf.worker.min.js is in public/

    // Let's try to set a path that Vite might handle by default if the worker is part of the pdfjs-dist package assets
    // This is often the trickiest part of pdfjs-dist setup.
    // We'll assume for now Vite's default handling or a CDN path is a fallback.
    // If this fails, the user might see errors about workerSrc.
    try {
        // Try to create a URL for the worker that Vite can handle.
        // This assumes that 'pdfjs-dist/build/pdf.worker.js' can be resolved by Vite's dev server and build process.
        const workerUrl = new URL('pdfjs-dist/build/pdf.worker.js', import.meta.url);
        pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl.href;
    } catch (e) {
        logger.warn("Could not set pdf.js workerSrc automatically. PDF processing might be slow or fail. Consider hosting pdf.worker.js in your public folder and setting pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.js'; or use a CDN.", e);
        // Fallback to a CDN - requires internet access
        pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;
    }
}


/**
 * Reads a PDF file and extracts all valid CVE ID patterns from its text content.
 *
 * @param file The PDF file object to parse.
 * @returns A Promise that resolves to a deduplicated array of found CVE ID strings.
 */
export async function extractCVEsFromPDF(file: File): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = async (event) => {
      try {
        const arrayBuffer = event.target?.result as ArrayBuffer;
        if (!arrayBuffer) {
          resolve([]);
          return;
        }

        const loadingTask = pdfjsLib.getDocument({ data: arrayBuffer });
        const pdf = await loadingTask.promise;
        let allTextContent = "";

        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const textContent = await page.getTextContent();
          const pageText = textContent.items.map(item => (item as PDFTextItem).str).join(' ');
          allTextContent += pageText + "\n";
        }

        const matches = allTextContent.matchAll(CVE_REGEX);
        const cveIds = new Set<string>();
        for (const match of matches) {
          cveIds.add(match[0].toUpperCase());
        }
        resolve(Array.from(cveIds));

      } catch (error) {
        logger.error("Error parsing PDF content:", error);
        reject(new Error("Failed to parse PDF file. Ensure it's a valid PDF."));
      }
    };

    reader.onerror = (error) => {
      logger.error("Error reading file for PDF parsing:", error);
      reject(new Error("Failed to read the file for PDF processing."));
    };

    reader.readAsArrayBuffer(file); // Read PDF as ArrayBuffer
  });
}

import * as XLSX from 'xlsx';

// Placeholder for XLSX parsing (more complex)
export async function extractCVEsFromXLSX(file: File): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = async (event) => {
      try {
        const arrayBuffer = event.target?.result as ArrayBuffer;
        if (!arrayBuffer) {
          resolve([]);
          return;
        }

        const workbook = XLSX.read(arrayBuffer, { type: 'array' });
        let allTextContent = "";

        workbook.SheetNames.forEach(sheetName => {
          const worksheet = workbook.Sheets[sheetName];
          // Convert sheet to an array of arrays (rows) of cell values
          // XLSX.utils.sheet_to_json with header:1 converts to array of arrays
          const sheetData: unknown[][] = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "" });

          sheetData.forEach(row => {
            row.forEach(cell => {
              if (cell !== null && cell !== undefined) {
                allTextContent += String(cell) + " "; // Add space to separate cell contents
              }
            });
            allTextContent += "\n"; // Add newline after each row
          });
        });

        const matches = allTextContent.matchAll(CVE_REGEX);
        const cveIds = new Set<string>();
        for (const match of matches) {
          cveIds.add(match[0].toUpperCase());
        }
        resolve(Array.from(cveIds));

      } catch (error) {
        logger.error("Error parsing XLSX content:", error);
        reject(new Error("Failed to parse XLSX file. Ensure it's a valid XLSX."));
      }
    };

    reader.onerror = (error) => {
      logger.error("Error reading file for XLSX parsing:", error);
      reject(new Error("Failed to read the file for XLSX processing."));
    };

    reader.readAsArrayBuffer(file); // Read XLSX as ArrayBuffer
  });
}
