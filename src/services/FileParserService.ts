// Regex to identify CVE patterns (e.g., CVE-YYYY-NNNN or CVE-YYYY-NNNNN...)
// This should be kept consistent with the one in UserAssistantAgent.ts or centralized if used in many places.
const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi; // Added 'g' flag for global match

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
        console.error("Error parsing CSV content:", error);
        reject(new Error("Failed to parse CSV file. Ensure it's a valid text-based CSV."));
      }
    };

    reader.onerror = (error) => {
      console.error("Error reading file:", error);
      reject(new Error("Failed to read the file."));
    };

    reader.readAsText(file); // Read the file as plain text
  });
}

// Placeholder for PDF parsing (more complex)
// export async function extractCVEsFromPDF(file: File): Promise<string[]> {
//   // Requires a library like PDF.js
//   // 1. Load the PDF file.
//   // 2. Extract text content from each page.
//   // 3. Concatenate text.
//   // 4. Use CVE_REGEX.matchAll(textContent) to find CVEs.
//   console.warn("PDF parsing is not fully implemented yet.");
//   return [];
// }

// Placeholder for XLSX parsing (more complex)
// export async function extractCVEsFromXLSX(file: File): Promise<string[]> {
//   // Requires a library like SheetJS (xlsx)
//   // 1. Read the XLSX file.
//   // 2. Iterate through sheets and rows/cells.
//   // 3. Concatenate all string cell values.
//   // 4. Use CVE_REGEX.matchAll(allCellText) to find CVEs.
//   console.warn("XLSX parsing is not fully implemented yet.");
//   return [];
// }
