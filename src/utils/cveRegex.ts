// Centralized regex for matching CVE identifiers like "CVE-YYYY-NNNN" or "CVE-YYYY-NNNNN...".
// The regex is case-insensitive and global to allow multiple matches.
export const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi;
