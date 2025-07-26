// Centralized regex for matching CVE identifiers like "CVE-YYYY-NNNN" or "CVE-YYYY-NNNNN...".
// The regex is case-insensitive and global to allow multiple matches.
// Matches CVE identifiers like "CVE-YYYY-NNNN" or "CVE-YYYY-NNNNN".
// Case-insensitive with word boundaries to avoid partial matches.
export const CVE_REGEX = /\bCVE-\d{4}-\d{4,7}\b/gi;
