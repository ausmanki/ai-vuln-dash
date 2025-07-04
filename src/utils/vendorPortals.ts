import type { VendorPortalMap } from '../types/vendorPortal';

export const vendorPortalMap: VendorPortalMap = {
  'apache': {
    name: 'Apache Software Foundation',
    securityUrl: 'https://httpd.apache.org/security/',
    downloadUrl: 'https://httpd.apache.org/download.cgi',
    description: 'Official Apache HTTP Server security advisories and patches',
    searchTips: 'Look for security reports and vulnerability announcements',
    updateGuidance: 'Download latest stable version with security fixes'
  },
  'java': {
    name: 'Oracle Java SE',
    securityUrl: 'https://www.oracle.com/security-alerts',
    downloadUrl: 'https://www.oracle.com/java/technologies/downloads/',
    description: 'Oracle Java security alerts and Critical Patch Updates',
    searchTips: 'Check quarterly CPU releases and security alerts',
    updateGuidance: 'Download latest JDK/JRE version or apply security patches'
  },
  'nodejs': {
    name: 'Node.js Foundation',
    securityUrl: 'https://nodejs.org/en/security/',
    downloadUrl: 'https://nodejs.org/en/download/',
    description: 'Node.js security releases and advisories',
    searchTips: 'Review security releases and update to latest LTS version',
    updateGuidance: 'Update to latest Node.js version using official installer or package manager'
  },
  'wordpress': {
    name: 'WordPress.org',
    securityUrl: 'https://wordpress.org/news/category/security/',
    downloadUrl: 'https://wordpress.org/download/',
    description: 'WordPress security releases and core updates',
    searchTips: 'Check for core updates and security releases',
    updateGuidance: 'Update WordPress core through admin dashboard or download latest version'
  },
  'redhat': {
    name: 'Red Hat Customer Portal',
    securityUrl: 'https://access.redhat.com/security/',
    downloadUrl: 'https://access.redhat.com/downloads/',
    description: 'Red Hat security advisories and errata packages',
    searchTips: 'Search by CVE ID or product name in security center',
    updateGuidance: 'Apply security updates through yum/dnf or download RPM packages'
  },
  'ubuntu': {
    name: 'Ubuntu Security',
    securityUrl: 'https://ubuntu.com/security/notices',
    downloadUrl: 'https://ubuntu.com/download',
    description: 'Ubuntu Security Notices (USN) and package updates',
    searchTips: 'Filter by CVE ID or package name in security notices',
    updateGuidance: 'Apply security updates using apt package manager'
  },
  'debian': {
    name: 'Debian Security',
    securityUrl: 'https://www.debian.org/security/',
    downloadUrl: 'https://www.debian.org/distrib/',
    description: 'Debian Security Advisories (DSA) and package fixes',
    searchTips: 'Check DSA releases and security announcements',
    updateGuidance: 'Update packages using apt-get or download fixed packages'
  },
  'microsoft': {
    name: 'Microsoft Security Response Center',
    securityUrl: 'https://msrc.microsoft.com/',
    downloadUrl: 'https://www.microsoft.com/en-us/download/',
    description: 'Microsoft security updates and advisories',
    searchTips: 'Use Security Update Guide to find relevant patches',
    updateGuidance: 'Install updates through Windows Update or download specific patches'
  },
  'windows': {
    name: 'Microsoft Windows Update',
    securityUrl: 'https://msrc.microsoft.com/update-guide/',
    downloadUrl: 'https://www.microsoft.com/en-us/download/windows.aspx',
    description: 'Windows security updates and cumulative updates',
    searchTips: 'Search by CVE ID in Security Update Guide',
    updateGuidance: 'Apply updates through Windows Update or download standalone packages'
  },
  'dotnet': {
    name: 'Microsoft .NET',
    securityUrl: 'https://github.com/dotnet/announcements/issues?q=is%3Aissue+label%3ASecurity',
    downloadUrl: 'https://dotnet.microsoft.com/download',
    description: '.NET Framework and .NET Core security announcements',
    searchTips: 'Check GitHub security announcements and releases',
    updateGuidance: 'Update .NET runtime/SDK or apply security patches'
  },
  'python': {
    name: 'Python Software Foundation',
    securityUrl: 'https://www.python.org/news/security/',
    downloadUrl: 'https://www.python.org/downloads/',
    description: 'Python security releases and vulnerability fixes',
    searchTips: 'Review security announcements and release notes',
    updateGuidance: 'Update to latest Python version or apply security patches'
  },
  'php': {
    name: 'PHP.net',
    securityUrl: 'https://www.php.net/security/',
    downloadUrl: 'https://www.php.net/downloads.php',
    description: 'PHP security advisories and release information',
    searchTips: 'Check security section and changelog for vulnerability fixes',
    updateGuidance: 'Update to latest PHP version with security fixes'
  },
  'mysql': {
    name: 'Oracle MySQL',
    securityUrl: 'https://www.oracle.com/security-alerts/cpuapr2024.html#AppendixMSQL',
    downloadUrl: 'https://dev.mysql.com/downloads/',
    description: 'MySQL security fixes in Critical Patch Updates',
    searchTips: 'Check quarterly CPU releases for MySQL security fixes',
    updateGuidance: 'Update MySQL server to latest version or apply security patches'
  },
  'postgresql': {
    name: 'PostgreSQL Global Development Group',
    securityUrl: 'https://www.postgresql.org/support/security/',
    downloadUrl: 'https://www.postgresql.org/download/',
    description: 'PostgreSQL security information and release notes',
    searchTips: 'Review security announcements and minor release notes',
    updateGuidance: 'Update PostgreSQL to latest minor version with security fixes'
  },
  'docker': {
    name: 'Docker Inc.',
    securityUrl: 'https://docs.docker.com/engine/security/',
    downloadUrl: 'https://docs.docker.com/get-docker/',
    description: 'Docker Engine security best practices and updates',
    searchTips: 'Check Docker release notes and security documentation',
    updateGuidance: 'Update Docker Engine and review container security practices'
  },
  'kubernetes': {
    name: 'Kubernetes (CNCF)',
    securityUrl: 'https://kubernetes.io/docs/reference/issues-security/',
    downloadUrl: 'https://kubernetes.io/releases/',
    description: 'Kubernetes security announcements and patches',
    searchTips: 'Monitor security announcements and release notes',
    updateGuidance: 'Update Kubernetes cluster to latest patched version'
  },
  'nginx': {
    name: 'NGINX Inc.',
    securityUrl: 'http://nginx.org/en/security_advisories.html',
    downloadUrl: 'http://nginx.org/en/download.html',
    description: 'NGINX security advisories and stable releases',
    searchTips: 'Check security advisories page for vulnerability information',
    updateGuidance: 'Update to latest stable NGINX version'
  },
  'linux': {
    name: 'Linux Kernel Organization',
    securityUrl: 'https://docs.kernel.org/process/security-bugs.html',
    downloadUrl: 'https://www.kernel.org/',
    description: 'Linux kernel security announcements and releases',
    searchTips: 'Check kernel.org security category and CVE database',
    updateGuidance: 'Update kernel through distribution package manager or compile from source'
  }
};

export function getVendorPortal(ecosystem: string) {
  return vendorPortalMap[ecosystem];
}
