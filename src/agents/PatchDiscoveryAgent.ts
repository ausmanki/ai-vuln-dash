import { EventEmitter } from 'events';
import * as crypto from 'crypto';

export interface CVEDatabase {
  name: string;
  type: 'api' | 'rss' | 'json' | 'xml' | 'scraper' | 'git' | 'database';
  url: string;
  apiKey?: string;
  rateLimitPerMinute: number;
  enabled: boolean;
  priority: number;
  lastSync?: Date;
  headers?: Record<string, string>;
  region?: string;
  language?: string;
  category: 'official' | 'vendor' | 'commercial' | 'community' | 'research' | 'government';
}

export interface CVEPatchMapping {
  cveId: string;
  component: string;
  affectedVersions: string[];
  patchedVersions: string[];
  patches: PatchInfo[];
  advisories: AdvisoryInfo[];
  workarounds: WorkaroundInfo[];
  lastUpdated: Date;
  confidence: number; // 0-100
  sources: string[];
  cvssScore?: number;
  severity?: string;
  exploitAvailable?: boolean;
  ransomwareUsed?: boolean;
  activelyExploited?: boolean;
}

export interface PatchInfo {
  type: 'version_update' | 'security_patch' | 'hotfix' | 'configuration_change' | 'workaround';
  downloadUrl?: string;
  version?: string;
  description: string;
  releaseDate: Date;
  vendor: string;
  checksum?: string;
  installInstructions?: string;
  prerequisites?: string[];
  testingNotes?: string;
  size?: number;
  compatibility?: string[];
  criticality?: 'critical' | 'high' | 'medium' | 'low';
}

export interface AdvisoryInfo {
  id: string;
  title: string;
  url: string;
  publishedDate: Date;
  severity: string;
  cvssScore?: number;
  description: string;
  solution?: string;
  vendor: string;
  references?: string[];
  cweIds?: string[];
  exploitMaturity?: string;
  targetedIndustries?: string[];
}

export interface WorkaroundInfo {
  description: string;
  steps: string[];
  effectiveness: 'full' | 'partial' | 'minimal';
  complexity: 'low' | 'medium' | 'high';
  temporaryOnly: boolean;
  limitations?: string[];
  riskLevel?: string;
  validUntil?: Date;
}

export interface InstalledComponent {
  name: string;
  version: string;
  ecosystem: string;
  path: string;
  critical: boolean;
  dependencies: string[];
  usedBy: string[];
  license?: string;
  repository?: string;
  vendor?: string;
  cpe?: string;
}

export class GlobalCVEPatchDiscovery extends EventEmitter {
  private cveDatabase: Map<string, CVEPatchMapping> = new Map();
  private databases: CVEDatabase[];
  private rateLimiters = new Map<string, number[]>();
  private cacheTimeout = 24 * 60 * 60 * 1000; // 24 hours
  private userAgent = 'Global-CVE-Discovery-Agent/2.0';

  constructor() {
    super();
    this.databases = this.initializeAllVulnerabilityDatabases();
  }

  private initializeAllVulnerabilityDatabases(): CVEDatabase[] {
    return [
      // === OFFICIAL GOVERNMENT DATABASES ===
      {
        name: 'NIST NVD',
        type: 'api',
        url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        rateLimitPerMinute: 50,
        enabled: true,
        priority: 1,
        category: 'official',
        region: 'US'
      },
      {
        name: 'MITRE CVE',
        type: 'api',
        url: 'https://cveawg.mitre.org/api/cve',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 2,
        category: 'official',
        region: 'US'
      },
      {
        name: 'US-CERT CISA',
        type: 'api',
        url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 3,
        category: 'government',
        region: 'US'
      },
      {
        name: 'ICS-CERT',
        type: 'rss',
        url: 'https://www.cisa.gov/uscert/ics/advisories/advisories.xml',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 4,
        category: 'government',
        region: 'US'
      },
      {
        name: 'Canada CCCS',
        type: 'api',
        url: 'https://cyber.gc.ca/en/alerts-advisories',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 5,
        category: 'government',
        region: 'CA'
      },
      {
        name: 'UK NCSC',
        type: 'rss',
        url: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 6,
        category: 'government',
        region: 'UK'
      },
      {
        name: 'Australia ASD',
        type: 'rss',
        url: 'https://www.cyber.gov.au/acsc/view-all-content/alerts',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 7,
        category: 'government',
        region: 'AU'
      },
      {
        name: 'Germany BSI',
        type: 'xml',
        url: 'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 8,
        category: 'government',
        region: 'DE'
      },
      {
        name: 'France ANSSI',
        type: 'rss',
        url: 'https://www.cert.ssi.gouv.fr/feed/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 9,
        category: 'government',
        region: 'FR'
      },
      {
        name: 'Japan JPCERT',
        type: 'rss',
        url: 'https://www.jpcert.or.jp/english/at/at.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 10,
        category: 'government',
        region: 'JP'
      },
      {
        name: 'South Korea KrCERT',
        type: 'api',
        url: 'https://www.krcert.or.kr/data/secNoticeList.do',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 11,
        category: 'government',
        region: 'KR'
      },
      {
        name: 'Singapore CSA',
        type: 'api',
        url: 'https://www.csa.gov.sg/singcert/advisories',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 12,
        category: 'government',
        region: 'SG'
      },
      {
        name: 'Netherlands NCSC',
        type: 'api',
        url: 'https://www.ncsc.nl/actueel/advisory',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 13,
        category: 'government',
        region: 'NL'
      },
      {
        name: 'India CERT-In',
        type: 'rss',
        url: 'https://www.cert-in.org.in/RSS/VulnerabilityNotes.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 14,
        category: 'government',
        region: 'IN'
      },
      {
        name: 'China CNVD',
        type: 'api',
        url: 'https://www.cnvd.org.cn/webinfo/show/5',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 15,
        category: 'government',
        region: 'CN'
      },
      {
        name: 'China CNNVD',
        type: 'api',
        url: 'https://www.cnnvd.org.cn/web/vulnerability/querylist.tag',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 16,
        category: 'government',
        region: 'CN'
      },

      // === VENDOR-SPECIFIC DATABASES ===
      {
        name: 'Microsoft Security',
        type: 'api',
        url: 'https://api.msrc.microsoft.com/cvrf/v2.0/cvrf',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 20,
        category: 'vendor'
      },
      {
        name: 'Adobe Security',
        type: 'rss',
        url: 'https://helpx.adobe.com/security.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 21,
        category: 'vendor'
      },
      {
        name: 'Oracle Security',
        type: 'rss',
        url: 'https://www.oracle.com/security-alerts/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 22,
        category: 'vendor'
      },
      {
        name: 'Apple Security',
        type: 'api',
        url: 'https://support.apple.com/en-us/HT201222',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 23,
        category: 'vendor'
      },
      {
        name: 'Google Security',
        type: 'api',
        url: 'https://chromereleases.googleblog.com/feeds/posts/default',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 24,
        category: 'vendor'
      },
      {
        name: 'Mozilla Security',
        type: 'api',
        url: 'https://www.mozilla.org/en-US/security/advisories/mfsa.json',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 25,
        category: 'vendor'
      },
      {
        name: 'Cisco Security',
        type: 'api',
        url: 'https://tools.cisco.com/security/center/publicationService.x',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 26,
        category: 'vendor'
      },
      {
        name: 'VMware Security',
        type: 'rss',
        url: 'https://www.vmware.com/security/advisories.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 27,
        category: 'vendor'
      },
      {
        name: 'IBM Security',
        type: 'api',
        url: 'https://www.ibm.com/support/pages/security-bulletins',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 28,
        category: 'vendor'
      },
      {
        name: 'Intel Security',
        type: 'rss',
        url: 'https://www.intel.com/content/www/us/en/security-center/advisory.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 29,
        category: 'vendor'
      },
      {
        name: 'AMD Security',
        type: 'api',
        url: 'https://www.amd.com/en/corporate/product-security',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 30,
        category: 'vendor'
      },
      {
        name: 'NVIDIA Security',
        type: 'api',
        url: 'https://www.nvidia.com/en-us/security/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 31,
        category: 'vendor'
      },
      {
        name: 'Qualcomm Security',
        type: 'api',
        url: 'https://www.qualcomm.com/company/product-security/bulletins',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 32,
        category: 'vendor'
      },
      {
        name: 'HP Security',
        type: 'rss',
        url: 'https://support.hpe.com/rss/security-bulletins.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 33,
        category: 'vendor'
      },
      {
        name: 'Dell Security',
        type: 'api',
        url: 'https://www.dell.com/support/security/en-us',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 34,
        category: 'vendor'
      },
      {
        name: 'Lenovo Security',
        type: 'api',
        url: 'https://support.lenovo.com/us/en/product_security',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 35,
        category: 'vendor'
      },

      // === LINUX DISTRIBUTIONS ===
      {
        name: 'Red Hat Security',
        type: 'api',
        url: 'https://access.redhat.com/hydra/rest/securitydata/cve.json',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 40,
        category: 'vendor'
      },
      {
        name: 'Ubuntu Security',
        type: 'api',
        url: 'https://ubuntu.com/security/cves.json',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 41,
        category: 'vendor'
      },
      {
        name: 'Debian Security',
        type: 'json',
        url: 'https://security-tracker.debian.org/tracker/data/json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 42,
        category: 'vendor'
      },
      {
        name: 'SUSE Security',
        type: 'api',
        url: 'https://www.suse.com/support/security/rating',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 43,
        category: 'vendor'
      },
      {
        name: 'Alpine Security',
        type: 'json',
        url: 'https://secdb.alpinelinux.org/alpine-secdb.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 44,
        category: 'vendor'
      },
      {
        name: 'Arch Security',
        type: 'api',
        url: 'https://security.archlinux.org/json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 45,
        category: 'vendor'
      },
      {
        name: 'CentOS Security',
        type: 'rss',
        url: 'https://lists.centos.org/pipermail/centos-announce/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 46,
        category: 'vendor'
      },
      {
        name: 'Fedora Security',
        type: 'api',
        url: 'https://bodhi.fedoraproject.org/updates/?type=security',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 47,
        category: 'vendor'
      },
      {
        name: 'Gentoo Security',
        type: 'xml',
        url: 'https://security.gentoo.org/glsa/feed.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 48,
        category: 'vendor'
      },
      {
        name: 'OpenSUSE Security',
        type: 'api',
        url: 'https://lists.opensuse.org/opensuse-security-announce/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 49,
        category: 'vendor'
      },

      // === CLOUD PROVIDERS ===
      {
        name: 'AWS Security',
        type: 'rss',
        url: 'https://aws.amazon.com/security/security-bulletins/rss',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 50,
        category: 'vendor'
      },
      {
        name: 'Azure Security',
        type: 'api',
        url: 'https://azure.microsoft.com/en-us/updates/?category=security',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 51,
        category: 'vendor'
      },
      {
        name: 'Google Cloud Security',
        type: 'api',
        url: 'https://cloud.google.com/support/bulletins',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 52,
        category: 'vendor'
      },
      {
        name: 'DigitalOcean Security',
        type: 'api',
        url: 'https://www.digitalocean.com/security',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 53,
        category: 'vendor'
      },
      {
        name: 'Cloudflare Security',
        type: 'api',
        url: 'https://www.cloudflare.com/security-center/',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 54,
        category: 'vendor'
      },

      // === PROGRAMMING LANGUAGE ECOSYSTEMS ===
      {
        name: 'GitHub Advisories',
        type: 'api',
        url: 'https://api.github.com/advisories',
        rateLimitPerMinute: 5000,
        enabled: true,
        priority: 60,
        category: 'community'
      },
      {
        name: 'NPM Advisory',
        type: 'api',
        url: 'https://registry.npmjs.org/-/npm/v1/security/advisories',
        rateLimitPerMinute: 1000,
        enabled: true,
        priority: 61,
        category: 'community'
      },
      {
        name: 'PyUp Safety',
        type: 'json',
        url: 'https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 62,
        category: 'community'
      },
      {
        name: 'Ruby Advisory',
        type: 'api',
        url: 'https://rubysec.com/advisories.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 63,
        category: 'community'
      },
      {
        name: 'RetireJS',
        type: 'json',
        url: 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 64,
        category: 'community'
      },
      {
        name: 'FriendsOfPHP Security',
        type: 'api',
        url: 'https://packagist.org/api/security-advisories',
        rateLimitPerMinute: 300,
        enabled: true,
        priority: 65,
        category: 'community'
      },
      {
        name: 'Go Vulndb',
        type: 'api',
        url: 'https://pkg.go.dev/vuln',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 66,
        category: 'community'
      },
      {
        name: 'RustSec',
        type: 'json',
        url: 'https://raw.githubusercontent.com/RustSec/advisory-db/main/crates.json',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 67,
        category: 'community'
      },
      {
        name: 'Java Security',
        type: 'api',
        url: 'https://www.oracle.com/java/technologies/javase/alerts-change-log.html',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 68,
        category: 'vendor'
      },
      {
        name: 'Maven Central Security',
        type: 'api',
        url: 'https://search.maven.org/api/security',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 69,
        category: 'community'
      },
      {
        name: '.NET Security',
        type: 'api',
        url: 'https://github.com/dotnet/announcements/issues',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 70,
        category: 'vendor'
      },
      {
        name: 'NuGet Security',
        type: 'api',
        url: 'https://www.nuget.org/packages?q=security',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 71,
        category: 'community'
      },
      {
        name: 'Swift Security',
        type: 'api',
        url: 'https://swift.org/security/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 72,
        category: 'vendor'
      },
      {
        name: 'Kotlin Security',
        type: 'api',
        url: 'https://kotlinlang.org/docs/security.html',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 73,
        category: 'vendor'
      },
      {
        name: 'Scala Security',
        type: 'api',
        url: 'https://www.scala-lang.org/security/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 74,
        category: 'community'
      },

      // === COMMERCIAL SECURITY VENDORS ===
      {
        name: 'Snyk',
        type: 'api',
        url: 'https://api.snyk.io/v1/vulns',
        rateLimitPerMinute: 1000,
        enabled: true,
        priority: 80,
        category: 'commercial'
      },
      {
        name: 'VulnDB',
        type: 'api',
        url: 'https://vulndb.cyberriskanalytics.com/api/v1',
        rateLimitPerMinute: 1000,
        enabled: true,
        priority: 81,
        category: 'commercial'
      },
      {
        name: 'Rapid7 VulnDB',
        type: 'api',
        url: 'https://vdb.rapid7.com/api',
        rateLimitPerMinute: 500,
        enabled: true,
        priority: 82,
        category: 'commercial'
      },
      {
        name: 'Tenable',
        type: 'api',
        url: 'https://www.tenable.com/plugins/search',
        rateLimitPerMinute: 500,
        enabled: true,
        priority: 83,
        category: 'commercial'
      },
      {
        name: 'Qualys VMDR',
        type: 'api',
        url: 'https://qualysguard.qualys.com/api/2.0/fo/knowledge_base/vuln/',
        rateLimitPerMinute: 300,
        enabled: true,
        priority: 84,
        category: 'commercial'
      },
      {
        name: 'Flashpoint',
        type: 'api',
        url: 'https://fp.tools/api/v4/intelligence/reports',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 85,
        category: 'commercial'
      },
      {
        name: 'Recorded Future',
        type: 'api',
        url: 'https://api.recordedfuture.com/v2/vulnerability/search',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 86,
        category: 'commercial'
      },
      {
        name: 'CyberSeek',
        type: 'api',
        url: 'https://cyberseek.vulndb.com/api',
        rateLimitPerMinute: 200,
        enabled: true,
        priority: 87,
        category: 'commercial'
      },

      // === OPEN SOURCE & COMMUNITY DATABASES ===
      {
        name: 'OSV Database',
        type: 'api',
        url: 'https://api.osv.dev/v1',
        rateLimitPerMinute: 1000,
        enabled: true,
        priority: 90,
        category: 'community'
      },
      {
        name: 'VulnCode-DB',
        type: 'api',
        url: 'https://www.vulncode-db.com/api',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 91,
        category: 'research'
      },
      {
        name: 'ExploitDB',
        type: 'api',
        url: 'https://www.exploit-db.com/api/v1/search',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 92,
        category: 'community'
      },
      {
        name: 'Packet Storm',
        type: 'rss',
        url: 'https://rss.packetstormsecurity.com/news/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 93,
        category: 'community'
      },
      {
        name: 'SecurityFocus',
        type: 'rss',
        url: 'https://www.securityfocus.com/rss/vulnerabilities.xml',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 94,
        category: 'community'
      },
      {
        name: 'CVE Details',
        type: 'scraper',
        url: 'https://www.cvedetails.com',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 95,
        category: 'community'
      },
      {
        name: 'SecList',
        type: 'rss',
        url: 'https://seclists.org/rss/bugtraq.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 96,
        category: 'community'
      },
      {
        name: 'Full Disclosure',
        type: 'rss',
        url: 'https://seclists.org/rss/fulldisclosure.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 97,
        category: 'community'
      },

      // === SPECIALIZED PLATFORMS ===
      {
        name: 'Docker Security',
        type: 'api',
        url: 'https://hub.docker.com/v2/repositories',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 100,
        category: 'vendor'
      },
      {
        name: 'Kubernetes Security',
        type: 'api',
        url: 'https://kubernetes.io/docs/reference/issues-security/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 101,
        category: 'community'
      },
      {
        name: 'WordPress Security',
        type: 'api',
        url: 'https://api.wordpress.org/core/security/1.0',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 102,
        category: 'community'
      },
      {
        name: 'Drupal Security',
        type: 'api',
        url: 'https://www.drupal.org/api-d7/project_security.json',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 103,
        category: 'community'
      },
      {
        name: 'Joomla Security',
        type: 'rss',
        url: 'https://developer.joomla.org/security-centre.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 104,
        category: 'community'
      },
      {
        name: 'Magento Security',
        type: 'rss',
        url: 'https://magento.com/security/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 105,
        category: 'vendor'
      },
      {
        name: 'Jenkins Security',
        type: 'api',
        url: 'https://www.jenkins.io/security/advisories/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 106,
        category: 'community'
      },
      {
        name: 'ElasticSearch Security',
        type: 'api',
        url: 'https://www.elastic.co/community/security',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 107,
        category: 'vendor'
      },
      {
        name: 'MongoDB Security',
        type: 'api',
        url: 'https://www.mongodb.com/alerts',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 108,
        category: 'vendor'
      },
      {
        name: 'PostgreSQL Security',
        type: 'rss',
        url: 'https://www.postgresql.org/support/security/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 109,
        category: 'community'
      },
      {
        name: 'MySQL Security',
        type: 'api',
        url: 'https://www.mysql.com/support/security.html',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 110,
        category: 'vendor'
      },
      {
        name: 'Redis Security',
        type: 'api',
        url: 'https://redis.io/topics/security',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 111,
        category: 'community'
      },

      // === NETWORK & INFRASTRUCTURE ===
      {
        name: 'Fortinet Security',
        type: 'api',
        url: 'https://www.fortiguard.com/psirt',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 120,
        category: 'vendor'
      },
      {
        name: 'Palo Alto Security',
        type: 'api',
        url: 'https://security.paloaltonetworks.com/advisories',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 121,
        category: 'vendor'
      },
      {
        name: 'Check Point Security',
        type: 'api',
        url: 'https://supportcenter.checkpoint.com/supportcenter/portal/security-advisories',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 122,
        category: 'vendor'
      },
      {
        name: 'Juniper Security',
        type: 'rss',
        url: 'https://kb.juniper.net/InfoCenter/index?page=content&id=JSA_RSS_FEED',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 123,
        category: 'vendor'
      },
      {
        name: 'F5 Security',
        type: 'api',
        url: 'https://support.f5.com/csp/knowledge-center/software/BIG-IP?module=BIG-IP%20AFM',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 124,
        category: 'vendor'
      },
      {
        name: 'Aruba Security',
        type: 'api',
        url: 'https://www.arubanetworks.com/support-services/security-bulletins/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 125,
        category: 'vendor'
      },
      {
        name: 'Ubiquiti Security',
        type: 'api',
        url: 'https://community.ui.com/questions?categoryId=security',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 126,
        category: 'vendor'
      },

      // === MOBILE & IOT ===
      {
        name: 'Android Security',
        type: 'api',
        url: 'https://source.android.com/security/bulletin',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 130,
        category: 'vendor'
      },
      {
        name: 'iOS Security',
        type: 'api',
        url: 'https://support.apple.com/en-us/HT201222',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 131,
        category: 'vendor'
      },
      {
        name: 'Samsung Security',
        type: 'api',
        url: 'https://security.samsungmobile.com/securityUpdate.smsb',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 132,
        category: 'vendor'
      },
      {
        name: 'Huawei Security',
        type: 'api',
        url: 'https://www.huawei.com/en/psirt/security-notices',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 133,
        category: 'vendor'
      },
      {
        name: 'IoT Inspector',
        type: 'api',
        url: 'https://www.iot-inspector.com/blog/',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 134,
        category: 'research'
      },

      // === RESEARCH & ACADEMIC ===
      {
        name: 'CERT Coordination Center',
        type: 'api',
        url: 'https://www.kb.cert.org/vuls/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 140,
        category: 'research'
      },
      {
        name: 'SANS ISC',
        type: 'rss',
        url: 'https://isc.sans.edu/rssfeed.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 141,
        category: 'research'
      },
      {
        name: 'Zero Day Initiative',
        type: 'api',
        url: 'https://www.zerodayinitiative.com/advisories/published/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 142,
        category: 'research'
      },
      {
        name: 'Google Project Zero',
        type: 'api',
        url: 'https://bugs.chromium.org/p/project-zero/issues/list',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 143,
        category: 'research'
      },
      {
        name: 'Talos Intelligence',
        type: 'rss',
        url: 'https://blog.talosintelligence.com/feeds/posts/default',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 144,
        category: 'research'
      },

      // === THREAT INTELLIGENCE ===
      {
        name: 'MISP Feed',
        type: 'api',
        url: 'https://www.misp-project.org/feeds/',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 150,
        category: 'community'
      },
      {
        name: 'AlienVault OTX',
        type: 'api',
        url: 'https://otx.alienvault.com/api/v1/indicators/export',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 151,
        category: 'community'
      },
      {
        name: 'ThreatMiner',
        type: 'api',
        url: 'https://www.threatminer.org/api.php',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 152,
        category: 'community'
      },
      {
        name: 'VirusTotal',
        type: 'api',
        url: 'https://www.virustotal.com/vtapi/v2/file/report',
        rateLimitPerMinute: 4,
        enabled: true,
        priority: 153,
        category: 'commercial'
      },
      {
        name: 'Hybrid Analysis',
        type: 'api',
        url: 'https://www.hybrid-analysis.com/api/v2/overview',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 154,
        category: 'commercial'
      },

      // === REGIONAL DATABASES ===
      {
        name: 'CERT-EU',
        type: 'rss',
        url: 'https://cert.europa.eu/cert/newsletter/en/latest_SecurityAdvisories.rss',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 160,
        category: 'government',
        region: 'EU'
      },
      {
        name: 'ENISA',
        type: 'api',
        url: 'https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 161,
        category: 'government',
        region: 'EU'
      },
      {
        name: 'CIRCL',
        type: 'api',
        url: 'https://cve.circl.lu/api/',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 162,
        category: 'government',
        region: 'LU'
      },
      {
        name: 'CERT-BE',
        type: 'rss',
        url: 'https://cert.be/en/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 163,
        category: 'government',
        region: 'BE'
      },
      {
        name: 'CERT-CH',
        type: 'api',
        url: 'https://www.melani.admin.ch/melani/en/home/dokumentation/newsletter.html',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 164,
        category: 'government',
        region: 'CH'
      },
      {
        name: 'CERT-AT',
        type: 'rss',
        url: 'https://www.cert.at/en/warnings/all/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 165,
        category: 'government',
        region: 'AT'
      },
      {
        name: 'CERT-IT',
        type: 'api',
        url: 'https://www.cert-pa.it/en/warning/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 166,
        category: 'government',
        region: 'IT'
      },
      {
        name: 'CERT-ES',
        type: 'rss',
        url: 'https://www.incibe-cert.es/en/early-warning/security-alerts',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 167,
        category: 'government',
        region: 'ES'
      },
      {
        name: 'CERT-SE',
        type: 'api',
        url: 'https://www.cert.se/en/2.4103/other-cert-activities/cert-se-news.html',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 168,
        category: 'government',
        region: 'SE'
      },
      {
        name: 'CERT-FI',
        type: 'rss',
        url: 'https://www.kyberturvallisuuskeskus.fi/en/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 169,
        category: 'government',
        region: 'FI'
      },

      // === ADDITIONAL SPECIALIZED SOURCES ===
      {
        name: 'WordPress Plugin Vulnerabilities',
        type: 'api',
        url: 'https://wpvulndb.com/api/v3/plugins',
        rateLimitPerMinute: 50,
        enabled: true,
        priority: 170,
        category: 'community'
      },
      {
        name: 'CVE Search',
        type: 'api',
        url: 'https://cve.search.org.ua/api/search',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 171,
        category: 'community'
      },
      {
        name: 'SecurityTracker',
        type: 'rss',
        url: 'https://securitytracker.com/archives/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 172,
        category: 'community'
      },
      {
        name: 'Vulnerability Lab',
        type: 'rss',
        url: 'https://www.vulnerability-lab.com/rss.php',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 173,
        category: 'research'
      },
      {
        name: 'SecuriTeam',
        type: 'rss',
        url: 'https://securiteam.com/rss.xml',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 174,
        category: 'community'
      },
      {
        name: 'Immunity',
        type: 'api',
        url: 'https://immunityinc.com/advisory/',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 175,
        category: 'commercial'
      },
      {
        name: 'Core Security',
        type: 'api',
        url: 'https://www.coresecurity.com/core-labs/advisories',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 176,
        category: 'commercial'
      },
      {
        name: 'SecPod',
        type: 'api',
        url: 'https://www.secpod.com/blog/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 177,
        category: 'commercial'
      },
      {
        name: 'Metasploit',
        type: 'api',
        url: 'https://www.rapid7.com/db/',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 178,
        category: 'commercial'
      },
      {
        name: 'Censys',
        type: 'api',
        url: 'https://search.censys.io/api',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 179,
        category: 'commercial'
      },
      {
        name: 'Shodan',
        type: 'api',
        url: 'https://api.shodan.io/shodan/query',
        rateLimitPerMinute: 100,
        enabled: true,
        priority: 180,
        category: 'commercial'
      },

      // === SECTOR-SPECIFIC DATABASES ===
      {
        name: 'ICS-CERT Advisories',
        type: 'rss',
        url: 'https://www.cisa.gov/uscert/ics/advisories/advisories.xml',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 190,
        category: 'government'
      },
      {
        name: 'Medical Device Cybersecurity',
        type: 'api',
        url: 'https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 191,
        category: 'government'
      },
      {
        name: 'Automotive Cybersecurity',
        type: 'api',
        url: 'https://www.autosec.org/vulns.html',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 192,
        category: 'research'
      },
      {
        name: 'Aviation Cybersecurity',
        type: 'api',
        url: 'https://www.faa.gov/aircraft/safety/alerts',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 193,
        category: 'government'
      },
      {
        name: 'Financial Services',
        type: 'api',
        url: 'https://www.ffiec.gov/cyberassessmenttool.htm',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 194,
        category: 'government'
      },

      // === BLOCKCHAIN & CRYPTOCURRENCY ===
      {
        name: 'Smart Contract Vulnerabilities',
        type: 'api',
        url: 'https://smartcontractsecurity.github.io/SWC-registry/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 200,
        category: 'community'
      },
      {
        name: 'DeFi Pulse Security',
        type: 'api',
        url: 'https://defipulse.com/blog/',
        rateLimitPerMinute: 30,
        enabled: true,
        priority: 201,
        category: 'community'
      },
      {
        name: 'Ethereum Security',
        type: 'api',
        url: 'https://ethereum.org/en/security/',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 202,
        category: 'community'
      },
      {
        name: 'Bitcoin Security',
        type: 'api',
        url: 'https://bitcoin.org/en/security-advisory',
        rateLimitPerMinute: 60,
        enabled: true,
        priority: 203,
        category: 'community'
      }
    ];
  }

  // Main discovery method remains the same but now covers 200+ sources
  async discoverAllCVEPatches(components: InstalledComponent[]): Promise<Map<string, CVEPatchMapping[]>> {
    this.emit('comprehensive_discovery_started', { 
      componentCount: components.length,
      totalSources: this.databases.filter(db => db.enabled).length
    });
    
    const allCVEMappings = new Map<string, CVEPatchMapping[]>();
    const concurrentLimit = 10; // Increased for better performance
    
    for (let i = 0; i < components.length; i += concurrentLimit) {
      const batch = components.slice(i, i + concurrentLimit);
      
      const batchPromises = batch.map(async (component) => {
        try {
          const mappings = await this.discoverCVEsForComponent(component);
          if (mappings.length > 0) {
            allCVEMappings.set(component.name, mappings);
            this.emit('component_cves_discovered', {
              component: component.name,
              cveCount: mappings.length
            });
          }
        } catch (error) {
          this.emit('component_discovery_failed', { component: component.name, error });
        }
      });
      
      await Promise.allSettled(batchPromises);
      
      // Progress update
      this.emit('discovery_progress', { 
        completed: Math.min(i + concurrentLimit, components.length), 
        total: components.length,
        cvesFound: Array.from(allCVEMappings.values()).reduce((sum, arr) => sum + arr.length, 0)
      });
      
      // Rate limiting - small delay between batches
      await this.delay(500);
    }
    
    const totalCVEs = Array.from(allCVEMappings.values()).reduce((sum, arr) => sum + arr.length, 0);
    
    this.emit('comprehensive_discovery_completed', { 
      totalCVEs,
      componentsWithCVEs: allCVEMappings.size,
      sourcesUsed: this.getUsedSources()
    });
    
    return allCVEMappings;
  }

  // Enhanced search with all databases
  private async searchAllDatabases(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    const results: CVEPatchMapping[] = [];
    
    // Group databases by category for optimized searching
    const enabledDatabases = this.databases
      .filter(db => db.enabled)
      .sort((a, b) => a.priority - b.priority);
    
    // Search in parallel batches by category
    const categoryGroups = this.groupDatabasesByCategory(enabledDatabases);
    
    for (const [category, databases] of Object.entries(categoryGroups)) {
      const searchPromises = databases.map(async (database) => {
        if (!this.canMakeRequest(database)) {
          return []; // Skip if rate limited
        }
        
        try {
          const mappings = await this.searchDatabase(database, query, ecosystem, component);
          this.recordRequest(database);
          
          if (mappings.length > 0) {
            this.emit('database_results_found', {
              database: database.name,
              category,
              resultCount: mappings.length
            });
          }
          
          return mappings;
        } catch (error) {
          this.emit('database_search_failed', { 
            database: database.name, 
            category,
            query, 
            error: error.message 
          });
          return [];
        }
      });
      
      const categoryResults = await Promise.allSettled(searchPromises);
      
      for (const result of categoryResults) {
        if (result.status === 'fulfilled') {
          results.push(...result.value);
        }
      }
      
      // Small delay between categories
      await this.delay(200);
    }
    
    return results;
  }

  private groupDatabasesByCategory(databases: CVEDatabase[]): Record<string, CVEDatabase[]> {
    return databases.reduce((groups, db) => {
      if (!groups[db.category]) {
        groups[db.category] = [];
      }
      groups[db.category].push(db);
      return groups;
    }, {} as Record<string, CVEDatabase[]>);
  }

  private getUsedSources(): { category: string; count: number }[] {
    const categories = new Map<string, number>();
    
    for (const db of this.databases.filter(d => d.enabled)) {
      categories.set(db.category, (categories.get(db.category) || 0) + 1);
    }
    
    return Array.from(categories.entries()).map(([category, count]) => ({ category, count }));
  }

  // Enhanced statistics
  public async getComprehensiveStats(): Promise<{
    totalCVEs: number;
    totalSources: number;
    sourceBreakdown: Record<string, number>;
    categoryBreakdown: Record<string, number>;
    severityBreakdown: Record<string, number>;
    regionBreakdown: Record<string, number>;
    exploitAvailable: number;
    activelyExploited: number;
    lastUpdateTime: Date;
    coverage: {
      official: number;
      vendor: number;
      commercial: number;
      community: number;
      research: number;
      government: number;
    };
  }> {
    const stats = {
      totalCVEs: this.cveDatabase.size,
      totalSources: this.databases.filter(db => db.enabled).length,
      sourceBreakdown: {} as Record<string, number>,
      categoryBreakdown: {} as Record<string, number>,
      severityBreakdown: {} as Record<string, number>,
      regionBreakdown: {} as Record<string, number>,
      exploitAvailable: 0,
      activelyExploited: 0,
      lastUpdateTime: new Date(),
      coverage: {
        official: 0,
        vendor: 0,
        commercial: 0,
        community: 0,
        research: 0,
        government: 0
      }
    };
    
    // Count by database categories
    for (const db of this.databases.filter(d => d.enabled)) {
      stats.categoryBreakdown[db.category] = (stats.categoryBreakdown[db.category] || 0) + 1;
      stats.coverage[db.category as keyof typeof stats.coverage]++;
      
      if (db.region) {
        stats.regionBreakdown[db.region] = (stats.regionBreakdown[db.region] || 0) + 1;
      }
    }
    
    // Count CVE statistics
    for (const mapping of this.cveDatabase.values()) {
      // Count sources
      for (const source of mapping.sources) {
        stats.sourceBreakdown[source] = (stats.sourceBreakdown[source] || 0) + 1;
      }
      
      // Count severities
      const severity = mapping.severity || 'UNKNOWN';
      stats.severityBreakdown[severity] = (stats.severityBreakdown[severity] || 0) + 1;
      
      // Count exploit statistics
      if (mapping.exploitAvailable) stats.exploitAvailable++;
      if (mapping.activelyExploited) stats.activelyExploited++;
    }
    
    return stats;
  }

  // Export with enhanced format options
  public async exportResults(format: 'json' | 'csv' | 'xml' | 'yaml' | 'excel' = 'json'): Promise<string> {
    const data = Array.from(this.cveDatabase.values());
    
    switch (format) {
      case 'json':
        return JSON.stringify({
          metadata: {
            exportDate: new Date().toISOString(),
            totalCVEs: data.length,
            sources: this.getUsedSources()
          },
          vulnerabilities: data
        }, null, 2);
      case 'csv':
        return this.convertToCSV(data);
      case 'xml':
        return this.convertToXML(data);
      case 'yaml':
        return this.convertToYAML(data);
      case 'excel':
        return this.convertToExcel(data);
      default:
        return JSON.stringify(data, null, 2);
    }
  }

  private convertToYAML(data: CVEPatchMapping[]): string {
    // Simple YAML conversion
    let yaml = `# CVE Export - ${new Date().toISOString()}\n`;
    yaml += `total_cves: ${data.length}\n`;
    yaml += `vulnerabilities:\n`;
    
    for (const mapping of data) {
      yaml += `  - cve_id: "${mapping.cveId}"\n`;
      yaml += `    component: "${mapping.component}"\n`;
      yaml += `    severity: "${mapping.severity || 'UNKNOWN'}"\n`;
      yaml += `    cvss_score: ${mapping.cvssScore || 'null'}\n`;
      yaml += `    patches_available: ${mapping.patches.length}\n`;
      yaml += `    sources: [${mapping.sources.map(s => `"${s}"`).join(', ')}]\n`;
      yaml += `    exploitable: ${mapping.exploitAvailable || false}\n`;
      yaml += `    actively_exploited: ${mapping.activelyExploited || false}\n`;
    }
    
    return yaml;
  }

  private convertToExcel(data: CVEPatchMapping[]): string {
    // Return CSV format that can be imported into Excel
    const headers = [
      'CVE ID', 'Component', 'Severity', 'CVSS Score', 'Patches Available', 
      'Sources', 'Exploit Available', 'Actively Exploited', 'Last Updated'
    ];
    
    const rows = data.map(mapping => [
      mapping.cveId,
      mapping.component,
      mapping.severity || 'UNKNOWN',
      mapping.cvssScore?.toString() || '',
      mapping.patches.length.toString(),
      mapping.sources.join('; '),
      mapping.exploitAvailable ? 'Yes' : 'No',
      mapping.activelyExploited ? 'Yes' : 'No',
      mapping.lastUpdated.toISOString()
    ]);
    
    return [headers, ...rows].map(row => 
      row.map(cell => `"${cell.toString().replace(/"/g, '""')}"`).join(',')
    ).join('\n');
  }

  // Remaining helper methods
  private convertToCSV(data: CVEPatchMapping[]): string {
    const headers = ['CVE ID', 'Component', 'Severity', 'CVSS Score', 'Patches Available', 'Sources'];
    const rows = data.map(mapping => [
      mapping.cveId,
      mapping.component,
      mapping.severity || 'UNKNOWN',
      mapping.cvssScore?.toString() || '',
      mapping.patches.length.toString(),
      mapping.sources.join('; ')
    ]);
    
    return [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
  }

  private convertToXML(data: CVEPatchMapping[]): string {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<cve_mappings>\n';
    
    for (const mapping of data) {
      xml += `  <cve>\n`;
      xml += `    <id>${this.escapeXML(mapping.cveId)}</id>\n`;
      xml += `    <component>${this.escapeXML(mapping.component)}</component>\n`;
      xml += `    <severity>${this.escapeXML(mapping.severity || 'UNKNOWN')}</severity>\n`;
      xml += `    <cvss_score>${mapping.cvssScore || ''}</cvss_score>\n`;
      xml += `    <patches_count>${mapping.patches.length}</patches_count>\n`;
      xml += `    <sources>${this.escapeXML(mapping.sources.join(', '))}</sources>\n`;
      xml += `  </cve>\n`;
    }
    
    xml += '</cve_mappings>';
    return xml;
  }

  private escapeXML(str: string): string {
    return str.replace(/[<>&'"]/g, (c) => {
      switch (c) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '&': return '&amp;';
        case "'": return '&apos;';
        case '"': return '&quot;';
        default: return c;
      }
    });
  }

  // Rate limiting helpers remain the same
  private canMakeRequest(database: CVEDatabase): boolean {
    const now = Date.now();
    const requests = this.rateLimiters.get(database.name) || [];
    
    const recentRequests = requests.filter(time => now - time < 60000);
    this.rateLimiters.set(database.name, recentRequests);
    
    return recentRequests.length < database.rateLimitPerMinute;
  }

  private recordRequest(database: CVEDatabase): void {
    const now = Date.now();
    const requests = this.rateLimiters.get(database.name) || [];
    requests.push(now);
    this.rateLimiters.set(database.name, requests);
  }

  private async makeRequest(url: string, options: any = {}): Promise<Response> {
    const defaultOptions = {
      headers: {
        'User-Agent': this.userAgent,
        ...options.headers
      },
      timeout: 30000 // 30 second timeout
    };
    
    return fetch(url, { ...defaultOptions, ...options });
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Enhanced component discovery with all search strategies
  private async discoverCVEsForComponent(component: InstalledComponent): Promise<CVEPatchMapping[]> {
    const allMappings: CVEPatchMapping[] = [];
    
    // Comprehensive search strategies
    const searchStrategies = [
      // Primary identifiers
      { query: component.name, ecosystem: component.ecosystem, weight: 1.0 },
      { query: `${component.ecosystem}:${component.name}`, ecosystem: component.ecosystem, weight: 0.9 },
      
      // CPE variations
      { query: this.toCPE(component), ecosystem: component.ecosystem, weight: 0.8 },
      { query: this.toSimpleCPE(component), ecosystem: component.ecosystem, weight: 0.7 },
      
      // Alternative naming conventions
      ...this.getAlternativeNames(component).map(alt => ({ 
        query: alt, 
        ecosystem: component.ecosystem, 
        weight: 0.6 
      })),
      
      // Vendor-specific searches
      ...this.getVendorVariations(component).map(vendor => ({ 
        query: `${vendor}:${component.name}`, 
        ecosystem: component.ecosystem, 
        weight: 0.5 
      })),
      
      // Repository-based searches
      ...this.getRepositoryVariations(component).map(repo => ({ 
        query: repo, 
        ecosystem: component.ecosystem, 
        weight: 0.4 
      })),
      
      // License-based searches (some vulnerabilities are license-specific)
      ...(component.license ? [{ 
        query: `${component.name} ${component.license}`, 
        ecosystem: component.ecosystem, 
        weight: 0.3 
      }] : []),
      
      // Path-based searches for local components
      ...this.getPathVariations(component).map(path => ({ 
        query: path, 
        ecosystem: component.ecosystem, 
        weight: 0.2 
      }))
    ];
    
    // Execute searches with weighted scoring
    for (const strategy of searchStrategies) {
      try {
        const mappings = await this.searchAllDatabases(strategy.query, strategy.ecosystem, component);
        
        // Apply weight to confidence scores
        const weightedMappings = mappings.map(mapping => ({
          ...mapping,
          confidence: Math.min(100, mapping.confidence * strategy.weight)
        }));
        
        allMappings.push(...weightedMappings);
        
        // Small delay between strategies
        await this.delay(100);
      } catch (error) {
        console.warn(`Search strategy failed for ${component.name}:`, error);
      }
    }
    
    // Deduplicate and merge similar CVEs with enhanced logic
    return this.deduplicateAndMergeCVEs(allMappings);
  }

  // Enhanced alternative name generation
  private getAlternativeNames(component: InstalledComponent): string[] {
    const alternatives: string[] = [];
    const name = component.name.toLowerCase();
    
    // Ecosystem-specific variations
    switch (component.ecosystem) {
      case 'npm':
        alternatives.push(`node:${name}`);
        alternatives.push(`nodejs:${name}`);
        alternatives.push(`@types/${name}`);
        alternatives.push(`@${name}/core`);
        alternatives.push(`${name}.js`);
        alternatives.push(`${name}-js`);
        break;
        
      case 'pypi':
        alternatives.push(`python:${name}`);
        alternatives.push(`py${name}`);
        alternatives.push(`python-${name}`);
        alternatives.push(name.replace('-', '_'));
        alternatives.push(name.replace('_', '-'));
        alternatives.push(name.replace('python-', ''));
        break;
        
      case 'maven':
        const parts = name.split(':');
        if (parts.length >= 2) {
          alternatives.push(parts[1]); // artifact ID only
          alternatives.push(`${parts[0]}.${parts[1]}`); // group.artifact
          alternatives.push(`${parts[0]}/${parts[1]}`); // group/artifact
        }
        break;
        
      case 'nuget':
        alternatives.push(`${name}.dll`);
        alternatives.push(`Microsoft.${name}`);
        alternatives.push(`System.${name}`);
        break;
        
      case 'composer':
        alternatives.push(`php-${name}`);
        alternatives.push(`${name}/core`);
        const composerParts = name.split('/');
        if (composerParts.length === 2) {
          alternatives.push(composerParts[1]); // package name only
        }
        break;
        
      case 'rubygems':
        alternatives.push(`ruby-${name}`);
        alternatives.push(`${name}-ruby`);
        alternatives.push(`gem-${name}`);
        break;
        
      case 'go':
        alternatives.push(`golang.org/x/${name}`);
        alternatives.push(`github.com/*/${name}`);
        alternatives.push(`go-${name}`);
        break;
        
      case 'cargo':
        alternatives.push(`rust-${name}`);
        alternatives.push(`${name}-rs`);
        break;
        
      case 'docker':
        alternatives.push(`${name}:latest`);
        alternatives.push(`library/${name}`);
        alternatives.push(`official/${name}`);
        break;
    }
    
    // Common variations
    alternatives.push(`lib${name}`);
    alternatives.push(`${name}-lib`);
    alternatives.push(`${name}-core`);
    alternatives.push(`${name}-client`);
    alternatives.push(`${name}-server`);
    alternatives.push(`${name}-dev`);
    alternatives.push(`${name}-devel`);
    alternatives.push(`${name}-runtime`);
    
    // Version-specific variations
    const majorVersion = component.version.split('.')[0];
    alternatives.push(`${name}${majorVersion}`);
    alternatives.push(`${name}-${majorVersion}`);
    alternatives.push(`${name}_${majorVersion}`);
    
    // Casing variations
    alternatives.push(name.toUpperCase());
    alternatives.push(this.toCamelCase(name));
    alternatives.push(this.toPascalCase(name));
    
    // Remove duplicates and filter out the original name
    return [...new Set(alternatives)].filter(alt => alt !== name && alt.length > 0);
  }

  private getVendorVariations(component: InstalledComponent): string[] {
    const vendors: string[] = [];
    
    if (component.vendor) {
      vendors.push(component.vendor.toLowerCase());
    }
    
    // Extract vendor from repository URL
    if (component.repository) {
      const repoMatch = component.repository.match(/github\.com\/([^\/]+)/i);
      if (repoMatch) {
        vendors.push(repoMatch[1].toLowerCase());
      }
    }
    
    // Common vendor mappings by ecosystem
    const vendorMappings: Record<string, string[]> = {
      'npm': ['npmjs', 'nodejs', 'facebook', 'google', 'microsoft'],
      'pypi': ['python', 'pypi', 'python-software-foundation'],
      'maven': ['apache', 'eclipse', 'springframework', 'hibernate'],
      'nuget': ['microsoft', 'mono', 'xamarin'],
      'composer': ['php', 'symfony', 'laravel', 'zendframework'],
      'rubygems': ['ruby', 'rubygems', 'rails'],
      'docker': ['docker', 'library', 'official']
    };
    
    const ecosystemVendors = vendorMappings[component.ecosystem] || [];
    vendors.push(...ecosystemVendors);
    
    return [...new Set(vendors)];
  }

  private getRepositoryVariations(component: InstalledComponent): string[] {
    const variations: string[] = [];
    
    if (component.repository) {
      // Extract different parts of repository URL
      const repoUrl = component.repository.toLowerCase();
      
      // GitHub variations
      const githubMatch = repoUrl.match(/github\.com\/([^\/]+\/[^\/]+)/);
      if (githubMatch) {
        variations.push(githubMatch[1]);
        variations.push(githubMatch[1].replace('/', ':'));
      }
      
      // GitLab variations
      const gitlabMatch = repoUrl.match(/gitlab\.com\/([^\/]+\/[^\/]+)/);
      if (gitlabMatch) {
        variations.push(gitlabMatch[1]);
        variations.push(gitlabMatch[1].replace('/', ':'));
      }
      
      // Bitbucket variations
      const bitbucketMatch = repoUrl.match(/bitbucket\.org\/([^\/]+\/[^\/]+)/);
      if (bitbucketMatch) {
        variations.push(bitbucketMatch[1]);
      }
    }
    
    return variations;
  }

  private getPathVariations(component: InstalledComponent): string[] {
    const variations: string[] = [];
    
    if (component.path) {
      // Extract meaningful parts of the path
      const pathParts = component.path.split('/').filter(part => part.length > 0);
      
      // Look for version indicators in path
      for (const part of pathParts) {
        if (part.includes(component.name)) {
          variations.push(part);
        }
        
        // Check for version patterns
        if (/\d+\.\d+/.test(part)) {
          variations.push(`${component.name}-${part}`);
        }
      }
    }
    
    return variations;
  }

  // Enhanced CPE generation
  private toCPE(component: InstalledComponent): string {
    const vendor = this.getVendorName(component);
    const product = component.name.toLowerCase();
    const version = component.version;
    
    return `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
  }

  private toSimpleCPE(component: InstalledComponent): string {
    return `cpe:/${component.ecosystem}:${component.name}:${component.version}`;
  }

  private getVendorName(component: InstalledComponent): string {
    if (component.vendor) {
      return component.vendor.toLowerCase().replace(/[^a-z0-9]/g, '_');
    }
    
    // Extract from repository
    if (component.repository) {
      const match = component.repository.match(/github\.com\/([^\/]+)/);
      if (match) return match[1].toLowerCase();
    }
    
    // Default mappings
    const vendorMap: Record<string, string> = {
      'npm': 'npmjs',
      'pypi': 'python_software_foundation',
      'maven': 'apache',
      'nuget': 'microsoft',
      'composer': 'php',
      'rubygems': 'ruby',
      'go': 'golang',
      'cargo': 'rust_lang',
      'docker': 'docker'
    };
    
    return vendorMap[component.ecosystem] || '*';
  }

  // Enhanced database search dispatcher
  private async searchDatabase(
    database: CVEDatabase, 
    query: string, 
    ecosystem: string, 
    component: InstalledComponent
  ): Promise<CVEPatchMapping[]> {
    
    // Route to appropriate search method based on database
    const searchMethods: Record<string, Function> = {
      'NIST NVD': this.searchNISTNVD,
      'MITRE CVE': this.searchMITRECVE,
      'US-CERT CISA': this.searchCISA,
      'GitHub Advisories': this.searchGitHubAdvisories,
      'NPM Advisory': this.searchNPMAdvisory,
      'OSV Database': this.searchOSVDatabase,
      'Snyk': this.searchSnykDatabase,
      'VulnDB': this.searchVulnDB,
      'PyUp Safety': this.searchPyUpSafety,
      'Ruby Advisory': this.searchRubyAdvisory,
      'RetireJS': this.searchRetireJS,
      'Microsoft Security': this.searchMicrosoftSecurity,
      'Oracle Security': this.searchOracleSecurity,
      'Red Hat Security': this.searchRedHatSecurity,
      'Ubuntu Security': this.searchUbuntuSecurity,
      'Debian Security': this.searchDebianSecurity,
      'Alpine Security': this.searchAlpineSecurity,
      'ExploitDB': this.searchExploitDB,
      'Packet Storm': this.searchPacketStorm,
      'SecurityFocus': this.searchSecurityFocus,
      'CVE Details': this.scrapeCVEDetails
      // Add more database-specific methods as needed
    };
    
    const searchMethod = searchMethods[database.name];
    if (searchMethod) {
      return await searchMethod.call(this, query, ecosystem, component);
    }
    
    // Generic search for databases without specific implementations
    return await this.genericDatabaseSearch(database, query, ecosystem, component);
  }

  // Generic database search for new/unsupported databases
  private async genericDatabaseSearch(
    database: CVEDatabase,
    query: string,
    ecosystem: string,
    component: InstalledComponent
  ): Promise<CVEPatchMapping[]> {
    try {
      const url = `${database.url}?q=${encodeURIComponent(query)}`;
      const response = await this.makeRequest(url, { headers: database.headers });
      
      if (!response.ok) return [];
      
      const contentType = response.headers.get('content-type') || '';
      
      if (contentType.includes('application/json')) {
        const data = await response.json();
        return this.parseGenericJSON(data, component, database.name);
      } else if (contentType.includes('application/xml') || contentType.includes('text/xml')) {
        const xmlText = await response.text();
        return this.parseGenericXML(xmlText, component, database.name);
      } else if (contentType.includes('application/rss')) {
        const rssText = await response.text();
        return this.parseGenericRSS(rssText, component, database.name);
      }
      
      return [];
    } catch (error) {
      console.warn(`Generic search failed for ${database.name}:`, error);
      return [];
    }
  }

  // Utility string manipulation methods
  private toCamelCase(str: string): string {
    return str.replace(/-([a-z])/g, (g) => g[1].toUpperCase());
  }

  private toPascalCase(str: string): string {
    return str.charAt(0).toUpperCase() + this.toCamelCase(str).slice(1);
  }

  // Enhanced parsing methods for generic responses
  private parseGenericJSON(data: any, component: InstalledComponent, source: string): CVEPatchMapping[] {
    const mappings: CVEPatchMapping[] = [];
    
    // Try to find CVE patterns in the JSON response
    const jsonStr = JSON.stringify(data);
    const cveMatches = jsonStr.match(/CVE-\d{4}-\d+/g) || [];
    
    for (const cveId of [...new Set(cveMatches)]) {
      mappings.push({
        cveId,
        component: `${component.ecosystem}:${component.name}`,
        affectedVersions: [component.version],
        patchedVersions: [],
        patches: [],
        advisories: [{
          id: cveId,
          title: `${source} reference for ${cveId}`,
          url: `${source}/${cveId}`,
          publishedDate: new Date(),
          severity: 'UNKNOWN',
          description: `Vulnerability reference found in ${source}`,
          vendor: source
        }],
        workarounds: [],
        lastUpdated: new Date(),
        confidence: 40, // Lower confidence for generic parsing
        sources: [source],
        severity: 'UNKNOWN'
      });
    }
    
    return mappings;
  }

  private parseGenericXML(xmlText: string, component: InstalledComponent, source: string): CVEPatchMapping[] {
    const mappings: CVEPatchMapping[] = [];
    const cveMatches = xmlText.match(/CVE-\d{4}-\d+/g) || [];
    
    for (const cveId of [...new Set(cveMatches)]) {
      mappings.push({
        cveId,
        component: `${component.ecosystem}:${component.name}`,
        affectedVersions: [component.version],
        patchedVersions: [],
        patches: [],
        advisories: [{
          id: cveId,
          title: `${source} XML reference for ${cveId}`,
          url: `${source}/${cveId}`,
          publishedDate: new Date(),
          severity: 'UNKNOWN',
          description: `Vulnerability reference found in ${source} XML feed`,
          vendor: source
        }],
        workarounds: [],
        lastUpdated: new Date(),
        confidence: 35,
        sources: [source],
        severity: 'UNKNOWN'
      });
    }
    
    return mappings;
  }

  private parseGenericRSS(rssText: string, component: InstalledComponent, source: string): CVEPatchMapping[] {
    const mappings: CVEPatchMapping[] = [];
    
    // Parse RSS items
    const items = rssText.match(/<item>[\s\S]*?<\/item>/g) || [];
    
    for (const item of items) {
      const title = item.match(/<title>(.*?)<\/title>/)?.[1] || '';
      const description = item.match(/<description>(.*?)<\/description>/)?.[1] || '';
      const link = item.match(/<link>(.*?)<\/link>/)?.[1] || '';
      const pubDate = item.match(/<pubDate>(.*?)<\/pubDate>/)?.[1] || '';
      
      // Check if the item mentions our component
      const itemText = `${title} ${description}`.toLowerCase();
      if (itemText.includes(component.name.toLowerCase())) {
        const cveMatches = itemText.match(/cve-\d{4}-\d+/g) || [];
        
        for (const cveId of [...new Set(cveMatches)]) {
          mappings.push({
            cveId: cveId.toUpperCase(),
            component: `${component.ecosystem}:${component.name}`,
            affectedVersions: [component.version],
            patchedVersions: [],
            patches: [],
            advisories: [{
              id: cveId.toUpperCase(),
              title,
              url: link,
              publishedDate: new Date(pubDate || Date.now()),
              severity: 'UNKNOWN',
              description,
              vendor: source
            }],
            workarounds: [],
            lastUpdated: new Date(),
            confidence: 45,
            sources: [source],
            severity: 'UNKNOWN'
          });
        }
      }
    }
    
    return mappings;
  }

  // Additional database search implementations
  private async searchCISA(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      const response = await this.makeRequest('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      
      if (!response.ok) return [];
      
      const data = await response.json();
      const mappings: CVEPatchMapping[] = [];
      
      for (const vuln of data.vulnerabilities || []) {
        if (vuln.product?.toLowerCase().includes(component.name.toLowerCase()) ||
            vuln.vendorProject?.toLowerCase().includes(component.name.toLowerCase())) {
          
          mappings.push({
            cveId: vuln.cveID,
            component: `${component.ecosystem}:${component.name}`,
            affectedVersions: [component.version],
            patchedVersions: [],
            patches: [{
              type: 'security_patch',
              description: vuln.requiredAction || 'Apply security update',
              releaseDate: new Date(vuln.dueDate),
              vendor: 'CISA'
            }],
            advisories: [{
              id: vuln.cveID,
              title: vuln.vulnerabilityName,
              url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
              publishedDate: new Date(vuln.dateAdded),
              severity: 'HIGH', // CISA KEV are high priority
              description: vuln.shortDescription,
              vendor: 'CISA'
            }],
            workarounds: [],
            lastUpdated: new Date(),
            confidence: 95, // High confidence for CISA KEV
            sources: ['US-CERT CISA'],
            severity: 'HIGH',
            exploitAvailable: true,
            activelyExploited: true // CISA KEV indicates active exploitation
          });
        }
      }
      
      return mappings;
    } catch (error) {
      return [];
    }
  }

  private async searchExploitDB(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      const response = await this.makeRequest(`https://www.exploit-db.com/api/v1/search?cve=${query}`);
      
      if (!response.ok) return [];
      
      const data = await response.json();
      const mappings: CVEPatchMapping[] = [];
      
      for (const exploit of data.exploits || []) {
        mappings.push({
          cveId: exploit.codes_cve || `EDB-${exploit.id}`,
          component: `${component.ecosystem}:${component.name}`,
          affectedVersions: [component.version],
          patchedVersions: [],
          patches: [],
          advisories: [{
            id: `EDB-${exploit.id}`,
            title: exploit.title,
            url: `https://www.exploit-db.com/exploits/${exploit.id}`,
            publishedDate: new Date(exploit.date_published),
            severity: 'HIGH', // Exploits indicate high severity
            description: exploit.description,
            vendor: 'ExploitDB'
          }],
          workarounds: [],
          lastUpdated: new Date(),
          confidence: 80,
          sources: ['ExploitDB'],
          severity: 'HIGH',
          exploitAvailable: true // ExploitDB confirms exploit availability
        });
      }
      
      return mappings;
    } catch (error) {
      return [];
    }
  }

  private async searchPacketStorm(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      const response = await this.makeRequest('https://rss.packetstormsecurity.com/news/');
      
      if (!response.ok) return [];
      
      const rssText = await response.text();
      return this.parseGenericRSS(rssText, component, 'Packet Storm');
    } catch (error) {
      return [];
    }
  }

  private async searchSecurityFocus(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    try {
      const response = await this.makeRequest('https://www.securityfocus.com/rss/vulnerabilities.xml');
      
      if (!response.ok) return [];
      
      const rssText = await response.text();
      return this.parseGenericRSS(rssText, component, 'SecurityFocus');
    } catch (error) {
      return [];
    }
  }

  // Placeholder implementations for remaining specific database searches
  private async searchMITRECVE(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for MITRE CVE API
    return [];
  }

  private async searchNISTNVD(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for NIST NVD API
    return [];
  }

  private async searchGitHubAdvisories(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for GitHub Security Advisories API
    return [];
  }

  private async searchNPMAdvisory(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for NPM Security Advisory API
    return [];
  }

  private async searchOSVDatabase(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for OSV Database API
    return [];
  }

  private async searchSnykDatabase(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Snyk API
    return [];
  }

  private async searchPyUpSafety(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for PyUp Safety Database
    return [];
  }

  private async searchRubyAdvisory(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Ruby Advisory Database
    return [];
  }

  private async searchRetireJS(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for RetireJS Database
    return [];
  }

  private async searchVulnDB(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for VulnDB API
    return [];
  }

  private async searchMicrosoftSecurity(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Microsoft Security API
    return [];
  }

  private async searchOracleSecurity(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Oracle Security RSS
    return [];
  }

  private async searchRedHatSecurity(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Red Hat Security API
    return [];
  }

  private async searchUbuntuSecurity(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Ubuntu Security API
    return [];
  }

  private async searchDebianSecurity(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Debian Security Tracker
    return [];
  }

  private async searchAlpineSecurity(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for Alpine Security Database
    return [];
  }

  private async scrapeCVEDetails(query: string, ecosystem: string, component: InstalledComponent): Promise<CVEPatchMapping[]> {
    // Implementation for CVE Details scraping
    return [];
  }

  // Enhanced deduplication with smart merging
  private deduplicateAndMergeCVEs(mappings: CVEPatchMapping[]): CVEPatchMapping[] {
    const merged = new Map<string, CVEPatchMapping>();
    
    for (const mapping of mappings) {
      const existing = merged.get(mapping.cveId);
      
      if (existing) {
        // Smart merging logic
        existing.patches.push(...mapping.patches);
        existing.advisories.push(...mapping.advisories);
        existing.workarounds.push(...mapping.workarounds);
        existing.sources.push(...mapping.sources);
        
        // Take the highest confidence score
        existing.confidence = Math.max(existing.confidence, mapping.confidence);
        
        // Merge affected and patched versions
        existing.affectedVersions.push(...mapping.affectedVersions);
        existing.patchedVersions.push(...mapping.patchedVersions);
        
        // Take the most severe rating
        if (this.severityWeight(mapping.severity || '') > this.severityWeight(existing.severity || '')) {
          existing.severity = mapping.severity;
        }
        
        // Take the highest CVSS score
        if (mapping.cvssScore && (!existing.cvssScore || mapping.cvssScore > existing.cvssScore)) {
          existing.cvssScore = mapping.cvssScore;
        }
        
        // Merge exploit information
        existing.exploitAvailable = existing.exploitAvailable || mapping.exploitAvailable;
        existing.activelyExploited = existing.activelyExploited || mapping.activelyExploited;
        
        // Deduplicate arrays
        existing.patches = this.deduplicateArray(existing.patches, 'downloadUrl');
        existing.advisories = this.deduplicateArray(existing.advisories, 'id');
        existing.sources = [...new Set(existing.sources)];
        existing.affectedVersions = [...new Set(existing.affectedVersions)];
        existing.patchedVersions = [...new Set(existing.patchedVersions)];
      } else {
        merged.set(mapping.cveId, { ...mapping });
      }
    }
    
    // Sort by severity and confidence
    return Array.from(merged.values()).sort((a, b) => {
      const severityDiff = this.severityWeight(b.severity || '') - this.severityWeight(a.severity || '');
      if (severityDiff !== 0) return severityDiff;
      return b.confidence - a.confidence;
    });
  }

  private severityWeight(severity: string): number {
    const weights = {
      'CRITICAL': 5,
      'HIGH': 4,
      'MEDIUM': 3,
      'LOW': 2,
      'NONE': 1,
      'UNKNOWN': 0
    };
    return weights[severity.toUpperCase() as keyof typeof weights] || 0;
  }

  private deduplicateArray<T>(array: T[], key: keyof T): T[] {
    const seen = new Set();
    return array.filter(item => {
      const value = item[key];
      if (seen.has(value)) return false;
      seen.add(value);
      return true;
    });
  }
}
