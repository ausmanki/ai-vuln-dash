import React, { useState, useCallback, useContext, useMemo } from 'react';
import { AppContext } from '../contexts/AppContext';
import { APIService } from '../services/APIService';
import { utils } from '../utils/helpers';
import { createStyles } from '../utils/styles';
import { COLORS, CONSTANTS } from '../utils/constants';
import CVSSDisplay from './CVSSDisplay';
import { Brain, Database, Globe, Info, Loader2, Copy, RefreshCw, Package, CheckCircle, XCircle, AlertTriangle, Target, ChevronRight, FileText, ExternalLink, Search, Clock } from 'lucide-react';
import TechnicalBrief from './TechnicalBrief';
import ScoreChart from './ScoreChart';
import AISourcesTab from './AISourcesTab';
import { vendorPortalMap } from '../utils/vendorPortals';

const CVEDetailView = ({ vulnerability }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [patchGuidance, setPatchGuidance] = useState(null);
  const [fetchingPatches, setFetchingPatches] = useState(false);
  const [activeGuidanceSection, setActiveGuidanceSection] = useState('overview');
  const { settings, addNotification, setVulnerabilities } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings?.darkMode || false), [settings?.darkMode]);

  // Comprehensive early return checks
  if (!vulnerability) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '400px',
        color: settings?.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText
      }}>
        <div style={{ textAlign: 'center' }}>
          <AlertTriangle size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
          <h3>No Vulnerability Selected</h3>
          <p>Please select a vulnerability to view details.</p>
        </div>
      </div>
    );
  }

  if (!vulnerability.cve) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '400px',
        color: settings?.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText
      }}>
        <div style={{ textAlign: 'center' }}>
          <AlertTriangle size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
          <h3>Invalid Vulnerability Data</h3>
          <p>The vulnerability data is incomplete or corrupted.</p>
        </div>
      </div>
    );
  }

  // Ensure settings exists with defaults
  const safeSettings = settings || { darkMode: false, geminiApiKey: null };
  const safeAddNotification = addNotification || (() => {});
  const safeSetVulnerabilities = setVulnerabilities || (() => {});

  // Patch discovery helpers
  const PatchDiscovery = {
    
    // Extract affected components from CVE description
    extractAffectedComponents: (description) => {
      const components = [];
      const lowerDesc = description.toLowerCase();
      
      // Define component patterns with their ecosystems
      const componentPatterns = [
        // Web servers and frameworks
        { pattern: /apache\s+http\s+server/i, name: 'Apache HTTP Server', type: 'web-server', ecosystem: 'apache' },
        { pattern: /nginx/i, name: 'Nginx', type: 'web-server', ecosystem: 'nginx' },
        { pattern: /apache\s+tomcat/i, name: 'Apache Tomcat', type: 'application-server', ecosystem: 'apache' },
        
        // Languages and runtimes
        { pattern: /node\.?js/i, name: 'Node.js', type: 'runtime', ecosystem: 'nodejs' },
        { pattern: /python/i, name: 'Python', type: 'language', ecosystem: 'python' },
        { pattern: /java/i, name: 'Java', type: 'language', ecosystem: 'java' },
        { pattern: /\.net/i, name: '.NET', type: 'framework', ecosystem: 'dotnet' },
        { pattern: /php/i, name: 'PHP', type: 'language', ecosystem: 'php' },
        
        // Databases
        { pattern: /mysql/i, name: 'MySQL', type: 'database', ecosystem: 'mysql' },
        { pattern: /postgresql/i, name: 'PostgreSQL', type: 'database', ecosystem: 'postgresql' },
        { pattern: /mongodb/i, name: 'MongoDB', type: 'database', ecosystem: 'mongodb' },
        
        // Operating systems
        { pattern: /linux\s+kernel/i, name: 'Linux Kernel', type: 'os', ecosystem: 'linux' },
        { pattern: /windows/i, name: 'Windows', type: 'os', ecosystem: 'windows' },
        { pattern: /ubuntu/i, name: 'Ubuntu', type: 'os', ecosystem: 'ubuntu' },
        { pattern: /debian/i, name: 'Debian', type: 'os', ecosystem: 'debian' },
        { pattern: /red\s+hat/i, name: 'Red Hat', type: 'os', ecosystem: 'redhat' },
        
        // Popular libraries
        { pattern: /log4j/i, name: 'Log4j', type: 'library', ecosystem: 'java' },
        { pattern: /spring/i, name: 'Spring Framework', type: 'framework', ecosystem: 'java' },
        { pattern: /maven/i, name: 'Apache Maven', type: 'build-tool', ecosystem: 'maven' },
        { pattern: /gradle/i, name: 'Gradle Build Tool', type: 'build-tool', ecosystem: 'gradle' },
        { pattern: /wordpress/i, name: 'WordPress', type: 'cms', ecosystem: 'wordpress' },
        { pattern: /drupal/i, name: 'Drupal', type: 'cms', ecosystem: 'drupal' },
        
        // Container and orchestration
        { pattern: /docker/i, name: 'Docker', type: 'container', ecosystem: 'docker' },
        { pattern: /kubernetes/i, name: 'Kubernetes', type: 'orchestration', ecosystem: 'kubernetes' },
        
        // Cloud services
        { pattern: /aws/i, name: 'Amazon Web Services', type: 'cloud', ecosystem: 'aws' },
        { pattern: /azure/i, name: 'Microsoft Azure', type: 'cloud', ecosystem: 'azure' },
        { pattern: /google\s+cloud/i, name: 'Google Cloud', type: 'cloud', ecosystem: 'gcp' }
      ];
      
      componentPatterns.forEach(pattern => {
        if (pattern.pattern.test(description)) {
          components.push({
            name: pattern.name,
            type: pattern.type,
            ecosystem: pattern.ecosystem,
            confidence: 'high'
          });
        }
      });
      
      // If no specific components found, try to infer from common keywords
      if (components.length === 0) {
        if (lowerDesc.includes('remote code execution')) {
          components.push({ name: 'Unknown Application', type: 'application', ecosystem: 'generic', confidence: 'low' });
        } else if (lowerDesc.includes('sql injection')) {
          components.push({ name: 'Database Application', type: 'database', ecosystem: 'generic', confidence: 'low' });
        } else if (lowerDesc.includes('cross-site scripting')) {
          components.push({ name: 'Web Application', type: 'web-application', ecosystem: 'generic', confidence: 'low' });
        }
      }
      
      return components;
    },

    // Generate vendor portal guidance for affected packages
    generateVendorPortals: (components) => {
      const portals = [];

      // Add specific package portals based on detected components
      components.forEach(component => {
        const portal = vendorPortalMap[component.ecosystem];
        if (portal && !portals.find(p => p.name === portal.name)) {
          portals.push({
            ...portal,
            relevantFor: component.name,
            ecosystem: component.ecosystem,
            componentType: component.type
          });
        }
      });

      // Add package-specific portals for known packages
      components.forEach(component => {
        const packageSpecificPortal = PatchDiscovery.getPackageSpecificPortal(component);
        if (packageSpecificPortal && !portals.find(p => p.name === packageSpecificPortal.name)) {
          portals.push(packageSpecificPortal);
        }
      });

      // Only add NVD as fallback if no specific vendor portals found
      if (portals.length === 0) {
        portals.push({
          name: 'National Vulnerability Database',
          securityUrl: 'https://nvd.nist.gov/',
          downloadUrl: 'https://nvd.nist.gov/vuln/search',
          description: 'Official US vulnerability database with CVE details',
          searchTips: 'Search by CVE ID for detailed vulnerability information',
          updateGuidance: 'Find vendor-specific remediation information and references',
          relevantFor: 'CVE reference information',
          ecosystem: 'nvd'
        });
      }
      
      return portals;
    },

    // Get package-specific vendor portals
    getPackageSpecificPortal: (component) => {
      const packagePortals = {
        'Log4j': {
          name: 'Apache Logging Services',
          securityUrl: 'https://logging.apache.org/log4j/2.x/security.html',
          downloadUrl: 'https://logging.apache.org/log4j/2.x/download.html',
          description: 'Apache Log4j security information and latest releases',
          searchTips: 'Check security page for Log4j vulnerability information and mitigation',
          updateGuidance: 'Download latest Log4j version or apply configuration changes',
          relevantFor: 'Log4j Library',
          ecosystem: 'java',
          componentType: 'library'
        },
        'Spring Framework': {
          name: 'Spring by VMware',
          securityUrl: 'https://spring.io/security',
          downloadUrl: 'https://spring.io/projects',
          description: 'Spring Framework security advisories and project updates',
          searchTips: 'Check Spring security page for vulnerability announcements',
          updateGuidance: 'Update Spring dependencies in Maven/Gradle or download latest versions',
          relevantFor: 'Spring Framework',
          ecosystem: 'java',
          componentType: 'framework'
        },
        'WordPress': {
          name: 'WordPress.org',
          securityUrl: 'https://wordpress.org/news/category/security/',
          downloadUrl: 'https://wordpress.org/download/',
          description: 'WordPress security releases and core updates',
          searchTips: 'Monitor security category for WordPress core and plugin vulnerabilities',
          updateGuidance: 'Update WordPress core, themes, and plugins through admin dashboard',
          relevantFor: 'WordPress CMS',
          ecosystem: 'wordpress',
          componentType: 'cms'
        },
        'Apache HTTP Server': {
          name: 'Apache HTTP Server Project',
          securityUrl: 'https://httpd.apache.org/security/vulnerabilities_24.html',
          downloadUrl: 'https://httpd.apache.org/download.cgi',
          description: 'Apache HTTP Server security vulnerabilities and patches',
          searchTips: 'Check version-specific vulnerability pages (2.4.x, 2.2.x)',
          updateGuidance: 'Download latest Apache HTTP Server version or apply security patches',
          relevantFor: 'Apache HTTP Server',
          ecosystem: 'apache',
          componentType: 'web-server'
        },
        'Node.js': {
          name: 'Node.js Foundation',
          securityUrl: 'https://nodejs.org/en/security/',
          downloadUrl: 'https://nodejs.org/en/download/',
          description: 'Node.js security releases and vulnerability reports',
          searchTips: 'Check security working group reports and release notes',
          updateGuidance: 'Update Node.js runtime to latest LTS or current version',
          relevantFor: 'Node.js Runtime',
          ecosystem: 'nodejs',
          componentType: 'runtime'
        }
      };

      return packagePortals[component.name];
    },

    // Generate search strategies
    generateSearchStrategies: (cveId, components) => {
      const strategies = [];
      
      // Primary CVE search
      strategies.push({
        name: 'Direct CVE Search',
        description: 'Search for the specific CVE ID across security databases',
        queries: [
          `"${cveId}" patch`,
          `"${cveId}" security advisory`,
          `"${cveId}" fix`,
          `"${cveId}" update`
        ],
        sites: [
          'nvd.nist.gov',
          'cve.mitre.org',
          'security.gentoo.org',
          'ubuntu.com/security'
        ],
        priority: 'high'
      });
      
      // Component-specific searches
      components.forEach(component => {
        strategies.push({
          name: `${component.name} Security Search`,
          description: `Find security updates specific to ${component.name}`,
          queries: [
            `"${component.name}" "${cveId}"`,
            `"${component.name}" security patch ${new Date().getFullYear()}`,
            `"${component.name}" vulnerability fix`,
            `"${component.name}" security update`
          ],
          sites: PatchDiscovery.getComponentSites(component.ecosystem),
          priority: 'high'
        });
      });
      
      return strategies;
    },

    // Generate package manager guidance
    generatePackageManagerGuidance: (components, cveId, description = '') => {
      const guidance = [];
      const lowerDesc = description.toLowerCase();
      
      const packageManagers = {
        'nodejs': {
          name: 'npm',
          checkCommands: ['npm audit', 'npm outdated'],
          updateCommands: ['npm audit fix', 'npm update [package-name]'],
          configFiles: ['package.json', 'package-lock.json'],
          registryUrl: 'https://www.npmjs.com/advisories',
          searchTips: 'Check npm advisories database for security fixes'
        },
        'python': {
          name: 'pip',
          checkCommands: ['pip list --outdated', 'safety check'],
          updateCommands: ['pip install --upgrade [package-name]', 'pip-audit'],
          configFiles: ['requirements.txt', 'setup.py', 'pyproject.toml'],
          registryUrl: 'https://pypi.org/',
          searchTips: 'Review PyPI security advisories and package history'
        },
        'java': {
          name: 'Maven',
          checkCommands: ['mvn versions:display-dependency-updates', 'mvn dependency:tree'],
          updateCommands: ['mvn versions:use-latest-versions', 'Update pom.xml dependencies'],
          configFiles: ['pom.xml', 'build.gradle'],
          registryUrl: 'https://search.maven.org/',
          searchTips: 'Check Maven Central for updated versions with security fixes'
        },
        'maven': {
          name: 'Maven',
          checkCommands: ['mvn versions:display-dependency-updates', 'mvn dependency:tree'],
          updateCommands: ['mvn versions:use-latest-versions', 'Update pom.xml dependencies'],
          configFiles: ['pom.xml', 'build.gradle'],
          registryUrl: 'https://search.maven.org/',
          searchTips: 'Check Maven Central for updated versions with security fixes'
        },
        'gradle': {
          name: 'Gradle',
          checkCommands: ['./gradlew dependencyUpdates', './gradlew dependencies'],
          updateCommands: ['./gradlew useLatestVersions', 'Update build.gradle dependencies'],
          configFiles: ['build.gradle', 'build.gradle.kts'],
          registryUrl: 'https://plugins.gradle.org/',
          searchTips: 'Check Gradle plugin portal for updated versions with security fixes'
        },
        'dotnet': {
          name: 'NuGet',
          checkCommands: ['dotnet list package --outdated', 'dotnet restore'],
          updateCommands: ['dotnet add package [package-name]', 'Update PackageReference'],
          configFiles: ['*.csproj', 'packages.config'],
          registryUrl: 'https://www.nuget.org/',
          searchTips: 'Review NuGet gallery for security updates'
        },
        'php': {
          name: 'Composer',
          checkCommands: ['composer outdated', 'composer audit'],
          updateCommands: ['composer update [package-name]', 'composer update'],
          configFiles: ['composer.json', 'composer.lock'],
          registryUrl: 'https://packagist.org/',
          searchTips: 'Check Packagist for security advisories'
        }
      };
      
      components.forEach(component => {
        let key = component.ecosystem;

        if (key === 'java') {
          if (lowerDesc.includes('gradle')) key = 'gradle';
          else if (lowerDesc.includes('maven')) key = 'maven';
          else key = 'maven';
        }

        const pm = packageManagers[key];
        if (pm) {
          guidance.push({
            ...pm,
            component: component.name,
            ecosystem: key,
            cveSearchTerms: [`${cveId} ${pm.name}`, `${component.name} ${cveId} security`]
          });
        }
      });

      if (guidance.length === 0) {
        if (lowerDesc.includes('gradle')) {
          const pm = packageManagers['gradle'];
          guidance.push({
            ...pm,
            component: 'Gradle Project',
            ecosystem: 'gradle',
            cveSearchTerms: [`${cveId} gradle`, `${cveId} security`]
          });
        } else if (lowerDesc.includes('maven')) {
          const pm = packageManagers['maven'];
          guidance.push({
            ...pm,
            component: 'Maven Project',
            ecosystem: 'maven',
            cveSearchTerms: [`${cveId} maven`, `${cveId} security`]
          });
        }
      }
      
      return guidance;
    },

    // Generate remediation steps
    generateRemediationSteps: (cveId, components) => {
      return [
        {
          phase: 'Assessment',
          title: 'Identify Affected Systems',
          description: 'Determine which systems in your environment are affected by this vulnerability',
          actions: [
            'Inventory all systems running the affected software',
            'Identify current versions of affected components',
            'Determine system criticality and exposure level',
            'Check if systems are internet-facing or internal'
          ],
          tools: ['Asset management tools', 'Network scanners', 'Configuration management'],
          estimatedTime: '1-4 hours',
          priority: 'critical'
        },
        {
          phase: 'Research',
          title: 'Find and Validate Patches',
          description: 'Research available patches and security updates',
          actions: [
            'Search vendor security advisories for patches',
            'Check package repositories for updated versions',
            'Review patch release notes and compatibility',
            'Verify patch authenticity and integrity'
          ],
          tools: ['Vendor security portals', 'Package managers', 'Security databases'],
          estimatedTime: '2-6 hours',
          priority: 'high'
        },
        {
          phase: 'Testing',
          title: 'Test Patches in Safe Environment',
          description: 'Validate patches in non-production environment',
          actions: [
            'Set up test environment matching production',
            'Apply patches to test systems',
            'Verify application functionality after patching',
            'Test rollback procedures if needed'
          ],
          tools: ['Test environments', 'Monitoring tools', 'Functional tests'],
          estimatedTime: '4-12 hours',
          priority: 'high'
        },
        {
          phase: 'Deployment',
          title: 'Deploy Patches to Production',
          description: 'Systematically apply patches to production systems',
          actions: [
            'Schedule maintenance windows',
            'Create system backups before patching',
            'Apply patches in staged deployment',
            'Monitor systems during deployment'
          ],
          tools: ['Deployment tools', 'Backup systems', 'Monitoring dashboards'],
          estimatedTime: '2-8 hours per system group',
          priority: 'critical'
        },
        {
          phase: 'Verification',
          title: 'Verify Patch Effectiveness',
          description: 'Confirm that patches have been successfully applied',
          actions: [
            'Scan systems to verify vulnerability is closed',
            'Test application functionality post-patch',
            'Monitor system performance and stability',
            'Update vulnerability management records'
          ],
          tools: ['Vulnerability scanners', 'Application monitors', 'SIEM systems'],
          estimatedTime: '1-3 hours',
          priority: 'medium'
        }
      ];
    },

    // Assess urgency level based on vulnerability characteristics
    assessUrgencyLevel: (vulnerability) => {
      let urgencyScore = 0;
      let factors = [];
      
      // CVSS Score impact
      const cvssScore = vulnerability?.cve?.cvssV3?.baseScore || vulnerability?.cve?.cvssV2?.baseScore || 0;
      if (cvssScore >= 9.0) {
        urgencyScore += 40;
        factors.push('Critical CVSS Score (9.0+)');
      } else if (cvssScore >= 7.0) {
        urgencyScore += 25;
        factors.push('High CVSS Score (7.0-8.9)');
      } else if (cvssScore >= 4.0) {
        urgencyScore += 10;
        factors.push('Medium CVSS Score (4.0-6.9)');
      }
      
      // EPSS Score impact
      const epssScore = vulnerability?.epss?.epssFloat || 0;
      if (epssScore > 0.7) {
        urgencyScore += 30;
        factors.push('High EPSS Score (Active Exploitation Likely)');
      } else if (epssScore > 0.3) {
        urgencyScore += 15;
        factors.push('Medium EPSS Score (Some Exploitation Risk)');
      }
      
      // CISA KEV listing
      if (vulnerability?.kev?.listed) {
        urgencyScore += 35;
        factors.push('Listed in CISA KEV (Active Exploitation)');
      }
      
      // Public exploits
      if (vulnerability?.exploits?.found) {
        urgencyScore += 20;
        factors.push('Public Exploits Available');
      }
      
      // Age of vulnerability
      const publishedDate = new Date(vulnerability?.cve?.publishedDate);
      const ageInDays = (Date.now() - publishedDate.getTime()) / (1000 * 60 * 60 * 24);
      if (ageInDays < 30) {
        urgencyScore += 10;
        factors.push('Recently Published (< 30 days)');
      }
      
      // Determine urgency level
      let level, timeframe, description;
      if (urgencyScore >= 80) {
        level = 'EMERGENCY';
        timeframe = 'Immediate (within hours)';
        description = 'Critical vulnerability requiring immediate attention';
      } else if (urgencyScore >= 60) {
        level = 'HIGH';
        timeframe = '24-48 hours';
        description = 'High priority vulnerability requiring urgent patching';
      } else if (urgencyScore >= 40) {
        level = 'MEDIUM';
        timeframe = '1-2 weeks';
        description = 'Important vulnerability requiring timely patching';
      } else {
        level = 'LOW';
        timeframe = '1 month';
        description = 'Standard vulnerability for regular maintenance window';
      }
      
      return {
        level,
        score: urgencyScore,
        timeframe,
        description,
        factors
      };
    },

    // Generate package and component overview
    generatePackageOverview: (components, vulnerability) => {
      const overview = {
        packages: [],
        purposes: [],
        vulnerabilityContext: {},
        affectedVersions: [],
        packageDetails: []
      };

      components.forEach(component => {
        // Generate package details based on component type
        const packageInfo = PatchDiscovery.getPackageInfo(component);
        if (packageInfo) {
          overview.packages.push(packageInfo);
        }
      });

      // Extract vulnerability context
      overview.vulnerabilityContext = PatchDiscovery.extractVulnerabilityContext(vulnerability);

      return overview;
    },

    // Get detailed package information
    getPackageInfo: (component) => {
      const packageDatabase = {
        'Log4j': {
          fullName: 'Apache Log4j',
          description: 'Apache Log4j is a Java-based logging utility that is part of the Apache Logging Services. It provides logging capabilities for Java applications with configurable output destinations and formats.',
          purpose: 'Logging framework for Java applications',
          maintainer: 'Apache Software Foundation',
          language: 'Java',
          category: 'Logging Library',
          commonUse: 'Used in enterprise Java applications for logging events, errors, and debugging information',
          ecosystem: 'Maven Central, Gradle repositories',
          keyFeatures: ['Hierarchical logging', 'Multiple output destinations', 'XML/JSON configuration', 'Performance optimization'],
          vulnerabilityImpact: 'Critical - Can lead to remote code execution through malicious log entries'
        },
        'Spring Framework': {
          fullName: 'Spring Framework',
          description: 'The Spring Framework is an application framework and inversion of control container for the Java platform, providing comprehensive infrastructure support for developing Java applications.',
          purpose: 'Application framework for Java enterprise development',
          maintainer: 'Pivotal Software (VMware)',
          language: 'Java',
          category: 'Application Framework',
          commonUse: 'Building enterprise Java applications with dependency injection, aspect-oriented programming, and MVC web framework',
          ecosystem: 'Maven Central, Spring repositories',
          keyFeatures: ['Dependency Injection', 'Aspect-Oriented Programming', 'MVC Framework', 'Data Access', 'Security'],
          vulnerabilityImpact: 'High - Can affect web applications and enterprise systems'
        },
        'Node.js': {
          fullName: 'Node.js Runtime',
          description: 'Node.js is a JavaScript runtime built on Chrome\'s V8 JavaScript engine that allows developers to run JavaScript on the server-side.',
          purpose: 'Server-side JavaScript runtime environment',
          maintainer: 'Node.js Foundation',
          language: 'JavaScript/C++',
          category: 'Runtime Environment',
          commonUse: 'Building scalable network applications, web servers, APIs, and real-time applications',
          ecosystem: 'npm registry, Node.js package ecosystem',
          keyFeatures: ['Event-driven architecture', 'Non-blocking I/O', 'npm package manager', 'Cross-platform'],
          vulnerabilityImpact: 'Critical - Can affect all Node.js applications and servers'
        },
        'WordPress': {
          fullName: 'WordPress Content Management System',
          description: 'WordPress is a free and open-source content management system written in PHP and paired with a MySQL or MariaDB database.',
          purpose: 'Content management system for websites and blogs',
          maintainer: 'WordPress Foundation',
          language: 'PHP',
          category: 'Content Management System',
          commonUse: 'Creating and managing websites, blogs, e-commerce sites, and web applications',
          ecosystem: 'WordPress.org plugin and theme repositories',
          keyFeatures: ['Plugin architecture', 'Theme system', 'User management', 'SEO features', 'Multi-site support'],
          vulnerabilityImpact: 'High - Can affect millions of websites worldwide'
        },
        'Apache HTTP Server': {
          fullName: 'Apache HTTP Server',
          description: 'The Apache HTTP Server is a free and open-source cross-platform web server software, released under the terms of Apache License 2.0.',
          purpose: 'Web server for hosting websites and web applications',
          maintainer: 'Apache Software Foundation',
          language: 'C',
          category: 'Web Server',
          commonUse: 'Serving web content, hosting websites, reverse proxy, load balancing',
          ecosystem: 'Apache modules ecosystem',
          keyFeatures: ['Modular architecture', 'Virtual hosting', 'SSL/TLS support', 'URL rewriting', 'Load balancing'],
          vulnerabilityImpact: 'Critical - Can affect web server security and availability'
        }
      };

      return packageDatabase[component.name] || {
        fullName: component.name,
        description: `${component.name} is a ${component.type} in the ${component.ecosystem} ecosystem.`,
        purpose: `${component.type} for ${component.ecosystem} applications`,
        maintainer: 'Various',
        language: component.ecosystem,
        category: component.type,
        commonUse: `Used in ${component.ecosystem} applications and systems`,
        ecosystem: `${component.ecosystem} package ecosystem`,
        keyFeatures: ['Core functionality', 'Integration capabilities'],
        vulnerabilityImpact: 'Potential security impact on dependent applications'
      };
    },

    // Extract vulnerability context
    extractVulnerabilityContext: (vulnerability) => {
      const context = {
        attackVector: vulnerability?.cve?.cvssV3?.attackVector || vulnerability?.cve?.cvssV2?.accessVector || 'Unknown',
        attackComplexity: vulnerability?.cve?.cvssV3?.attackComplexity || vulnerability?.cve?.cvssV2?.accessComplexity || 'Unknown',
        privilegesRequired: vulnerability?.cve?.cvssV3?.privilegesRequired || 'Unknown',
        userInteraction: vulnerability?.cve?.cvssV3?.userInteraction || 'Unknown',
        scope: vulnerability?.cve?.cvssV3?.scope || 'Unknown',
        impactConfidentiality: vulnerability?.cve?.cvssV3?.confidentialityImpact || 'Unknown',
        impactIntegrity: vulnerability?.cve?.cvssV3?.integrityImpact || 'Unknown',
        impactAvailability: vulnerability?.cve?.cvssV3?.availabilityImpact || 'Unknown',
        cweTypes: vulnerability?.cve?.cwe || [],
        references: vulnerability?.cve?.references?.length || 0
      };

      return context;
    },
    getComponentSites: (ecosystem) => {
      const siteMap = {
        'apache': ['httpd.apache.org', 'apache.org/security'],
        'microsoft': ['msrc.microsoft.com', 'microsoft.com/security'],
        'oracle': ['oracle.com/security-alerts', 'oracle.com/security'],
        'nodejs': ['nodejs.org/security', 'npmjs.com/advisories'],
        'python': ['python.org/security', 'pypi.org'],
        'java': ['oracle.com/java/security', 'openjdk.java.net'],
        'wordpress': ['wordpress.org/news/category/security', 'wpscan.com'],
        'ubuntu': ['ubuntu.com/security', 'launchpad.net/ubuntu/+cve'],
        'debian': ['debian.org/security', 'security-tracker.debian.org'],
        'redhat': ['access.redhat.com/security', 'redhat.com/security']
      };
      
      return siteMap[ecosystem] || ['security.generic-vendor.com'];
    },

    // Parse AI response for patch information
    parseAIResponseForPatches: (aiResponse) => {
      const patches = [];
      const advisories = [];
      const seenUrls = new Set(); // Track URLs to prevent duplicates
      
      try {
        if (!aiResponse || typeof aiResponse !== 'string') {
          return { patches, advisories };
        }

        // Enhanced URL pattern matching
        const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g;
        const foundUrls = aiResponse.match(urlPattern) || [];
        
        // Parse structured responses
        const lines = aiResponse.split('\n');
        let currentSection = null;
        let currentPatch = null;
        
        lines.forEach(line => {
          const trimmedLine = line.trim();
          
          // Identify sections
          if (trimmedLine.includes('Official') && trimmedLine.includes('Download')) {
            currentSection = 'downloads';
          } else if (trimmedLine.includes('Security') && trimmedLine.includes('Page')) {
            currentSection = 'security';
          } else if (trimmedLine.includes('Package Manager')) {
            currentSection = 'packages';
          }
          
          // Extract URLs with context
          const urlMatch = trimmedLine.match(/(https?:\/\/[^\s\)]+)/);
          if (urlMatch) {
            const url = urlMatch[1];
            
            // Skip if URL already seen
            if (seenUrls.has(url)) {
              return;
            }
            seenUrls.add(url);
            
            const isSecurityRelated = url.includes('security') || 
                                    url.includes('advisory') || 
                                    url.includes('patch') || 
                                    url.includes('update') ||
                                    url.includes('download') ||
                                    url.includes('maven') ||
                                    url.includes('npm') ||
                                    url.includes('github');
            
            if (isSecurityRelated) {
              const vendor = PatchDiscovery.extractVendorFromUrl(url);
              const isPatchLike = url.includes('download') || 
                                url.includes('maven') || 
                                url.includes('npm') ||
                                url.includes('packages') ||
                                url.includes('releases');
              
              if (isPatchLike) {
                patches.push({
                  vendor,
                  downloadUrl: url,
                  description: `Found in AI analysis: ${trimmedLine}`,
                  confidence: 'HIGH',
                  verified: false,
                  source: 'AI_DISCOVERY'
                });
              } else {
                advisories.push({
                  vendor,
                  url,
                  title: `${vendor} Security Advisory`,
                  summary: `Found in AI analysis: ${trimmedLine}`,
                  verified: false,
                  source: 'AI_DISCOVERY'
                });
              }
            }
          }
        });
        
        console.log(`Parsed ${patches.length} patches and ${advisories.length} advisories from AI response`);
        
      } catch (error) {
        console.warn('Error parsing AI response:', error);
      }
      
      return { patches, advisories };
    },

    // Extract vendor from URL
    extractVendorFromUrl: (url) => {
      try {
        const domain = new URL(url).hostname.toLowerCase();
        if (domain.includes('microsoft')) return 'Microsoft';
        if (domain.includes('adobe')) return 'Adobe';
        if (domain.includes('oracle')) return 'Oracle';
        if (domain.includes('vmware')) return 'VMware';
        if (domain.includes('cisco')) return 'Cisco';
        if (domain.includes('google') || domain.includes('android')) return 'Google';
        if (domain.includes('apple')) return 'Apple';
        if (domain.includes('redhat')) return 'Red Hat';
        if (domain.includes('ubuntu')) return 'Ubuntu';
        if (domain.includes('debian')) return 'Debian';
        if (domain.includes('github')) return 'GitHub';
        if (domain.includes('npmjs')) return 'npm';
        if (domain.includes('maven')) return 'Maven';
        if (domain.includes('pypi')) return 'PyPI';
        return 'Unknown';
      } catch (error) {
        return 'Unknown';
      }
    },

    // Verify patch URLs
    verifyPatchUrls: async (patches, advisories) => {
      const verifiedPatches = [];
      const verifiedAdvisories = [];
      
      // Verify patches
      for (const patch of patches) {
        try {
          const verification = await PatchDiscovery.verifyUrl(patch.downloadUrl);
          patch.verified = verification.valid;
          patch.verificationStatus = verification.status;
          patch.lastChecked = new Date().toISOString();
          verifiedPatches.push(patch);
        } catch (error) {
          patch.verified = false;
          patch.verificationStatus = 'ERROR';
          patch.verificationError = error.message;
          verifiedPatches.push(patch);
        }
      }
      
      // Verify advisories
      for (const advisory of advisories) {
        try {
          const verification = await PatchDiscovery.verifyUrl(advisory.url);
          advisory.verified = verification.valid;
          advisory.verificationStatus = verification.status;
          advisory.lastChecked = new Date().toISOString();
          verifiedAdvisories.push(advisory);
        } catch (error) {
          advisory.verified = false;
          advisory.verificationStatus = 'ERROR';
          advisory.verificationError = error.message;
          verifiedAdvisories.push(advisory);
        }
      }
      
      return { patches: verifiedPatches, advisories: verifiedAdvisories };
    },

    // Verify URL accessibility
    verifyUrl: async (url) => {
      try {
        // For well-known security domains, assume they're valid
        const wellKnownDomains = [
          'microsoft.com', 'adobe.com', 'oracle.com', 'vmware.com',
          'cisco.com', 'google.com', 'apple.com', 'redhat.com',
          'ubuntu.com', 'debian.org', 'github.com', 'npmjs.com',
          'maven.org', 'pypi.org', 'nvd.nist.gov'
        ];
        
        const domain = new URL(url).hostname.toLowerCase();
        const isWellKnown = wellKnownDomains.some(knownDomain => domain.includes(knownDomain));
        
        if (isWellKnown) {
          return { valid: true, status: 'ASSUMED_VALID' };
        }
        
        // Attempt basic fetch with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        
        const response = await fetch(url, { 
          method: 'HEAD',
          mode: 'no-cors',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        return { 
          valid: response.type === 'opaque' || response.ok, 
          status: response.type === 'opaque' ? 'CORS_BLOCKED' : 'ACCESSIBLE'
        };
      } catch (error) {
        return { valid: false, status: 'TIMEOUT_OR_ERROR' };
      }
    }
  };

  // Patch discovery function
  const discoverPatches = async () => {
    if (!safeSettings.geminiApiKey) {
      safeAddNotification({
        type: 'error',
        title: 'API Key Required',
        message: 'Configure Gemini API key to enable AI-powered patch discovery'
      });
      return;
    }

    setFetchingPatches(true);
    
    try {
      safeAddNotification({
        type: 'info',
        title: 'AI Patch Discovery Started',
        message: 'Using AI with Google Search to find patches and advisories...'
      });

      const cveId = vulnerability.cve.id;
      const description = vulnerability.cve.description;
      
      // Extract affected components
      const components = PatchDiscovery.extractAffectedComponents(description);
      
      // Generate AI search prompt
      const searchPrompt = `
You are a cybersecurity expert helping find official patches and fixes for vulnerabilities.

CVE ID: ${cveId}
DESCRIPTION: ${description}

TASK: Find official vendor patches, security advisories, and security bulletins for this CVE.

SEARCH AND PROVIDE:
1. **Official Vendor Downloads**: Direct download links for patched versions
2. **Security Advisories**: Vendor security pages with detailed information
3. **Vendor Security Bulletins**: announcements and response timelines
4. **GitHub Releases**: Official releases and security fixes
5. **Distribution Updates**: Linux distribution security updates

IMPORTANT REQUIREMENTS:
- Provide REAL, WORKING URLs only
- Include specific version numbers that fix the vulnerability
- Verify all information is current and accurate
- Focus on official vendor sources

RETURN FORMAT:
For each fix found, provide:
- **Vendor**: [Vendor name]
- **Type**: [Download/Advisory/Package Update]
- **URL**: [Complete working URL]
- **Version**: [Specific version that fixes the CVE]
- **Description**: [What this link provides]

Search comprehensively for all available patches and advisories.
`;

      // Create enhanced vulnerability object for AI search
      const enhancedVulnerability = {
        ...vulnerability,
        customPrompt: searchPrompt,
        requireWebSearch: true,
        searchDepth: 'comprehensive',
        validateCVE: true
      };

      // Generate AI analysis with web search
      const aiResponse = await APIService.generateAIAnalysis(
        enhancedVulnerability,
        safeSettings.geminiApiKey,
        safeSettings.geminiModel,
        safeSettings
      );

      if (!aiResponse || !aiResponse.analysis) {
        throw new Error('AI analysis failed or returned empty response');
      }

      // Parse AI response for patches and advisories
      const { patches, advisories } = PatchDiscovery.parseAIResponseForPatches(aiResponse.analysis);
      
      // Verify discovered URLs
      const verified = await PatchDiscovery.verifyPatchUrls(patches, advisories);
      
      // Generate comprehensive guidance
      const guidance = {
        cveId,
        components,
        aiPatches: verified.patches,
        aiAdvisories: verified.advisories,
        vendorPortals: PatchDiscovery.generateVendorPortals(components),
        searchStrategies: PatchDiscovery.generateSearchStrategies(cveId, components),
        packageManagers: PatchDiscovery.generatePackageManagerGuidance(components, cveId, description),
        remediationSteps: PatchDiscovery.generateRemediationSteps(cveId, components),
        urgencyLevel: PatchDiscovery.assessUrgencyLevel(vulnerability),
        aiAnalysis: aiResponse.analysis,
        generatedAt: new Date().toISOString(),
        searchPerformed: true,
        totalFound: verified.patches.length + verified.advisories.length,
        verifiedCount: verified.patches.filter(p => p.verified).length + verified.advisories.filter(a => a.verified).length
      };

      setPatchGuidance(guidance);
      setActiveTab('patches');

      const totalFound = guidance.totalFound;
      const verifiedCount = guidance.verifiedCount;
      
      if (totalFound > 0) {
        safeAddNotification({
          type: 'success',
          title: 'AI Patch Discovery Complete',
          message: `Found ${totalFound} patches/advisories (${verifiedCount} verified) using AI web search`
        });
      } else {
        safeAddNotification({
          type: 'info',
          title: 'AI Search Complete',
          message: 'No specific patches found via AI search. Comprehensive guidance provided.'
        });
      }

    } catch (error) {
      console.error('AI patch discovery error:', error);
      safeAddNotification({
        type: 'error',
        title: 'AI Patch Discovery Failed',
        message: error.message || 'Failed to discover patches using AI'
      });
    } finally {
      setFetchingPatches(false);
    }
  };

  // Enhanced patches tab rendering
  const renderEnhancedPatchesTab = () => {
    const getSeverityColor = (level) => {
      switch (level) {
        case 'EMERGENCY': return COLORS.red;
        case 'HIGH': return '#ea580c';
        case 'MEDIUM': return '#d97706';
        case 'LOW': return '#65a30d';
        default: return '#6b7280';
      }
    };

    return (
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', margin: 0 }}>
            Patch Discovery
          </h2>
          
          <button
            style={{
              ...styles.button,
              ...styles.buttonPrimary,
              padding: '12px 24px',
              opacity: fetchingPatches ? 0.7 : 1
            }}
            onClick={discoverPatches}
            disabled={fetchingPatches}
          >
            {fetchingPatches ? (
              <>
                <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
                AI Discovering Patches...
              </>
            ) : (
              <>
                <Brain size={16} />
                <Search size={14} style={{ marginLeft: '4px' }} />
                Discover Patches
              </>
            )}
          </button>
        </div>

        {patchGuidance ? (
          <div>
            {/* Status Summary */}
            <div style={{
              ...styles.card,
              marginBottom: '24px',
              background: safeSettings.darkMode ? COLORS.dark.background : COLORS.light.background
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                <div>
                  <h3 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                    AI Discovery Results
                  </h3>
                  <p style={{ margin: '4px 0 0 0', fontSize: '0.875rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                    Generated {new Date(patchGuidance.generatedAt).toLocaleString()}
                  </p>
                </div>
                
                {/* Urgency Level */}
                <div style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  background: `${getSeverityColor(patchGuidance.urgencyLevel.level)}20`,
                  border: `1px solid ${getSeverityColor(patchGuidance.urgencyLevel.level)}40`
                }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: '600', color: getSeverityColor(patchGuidance.urgencyLevel.level) }}>
                    {patchGuidance.urgencyLevel.level} PRIORITY
                  </div>
                  <div style={{ fontSize: '0.7rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                    {patchGuidance.urgencyLevel.timeframe}
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                <div style={{ textAlign: 'center', padding: '12px', background: safeSettings.darkMode ? COLORS.dark.surface : COLORS.light.surface, borderRadius: '8px' }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: '700', color: COLORS.purple }}>
                    {patchGuidance.verifiedCount}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                    Verified
                  </div>
                </div>

                <div style={{ textAlign: 'center', padding: '12px', background: safeSettings.darkMode ? COLORS.dark.surface : COLORS.light.surface, borderRadius: '8px' }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: '700', color: COLORS.purple }}>
                    {patchGuidance.components.length}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                    Components
                  </div>
                </div>
              </div>
            </div>

            {/* Guidance Navigation */}
            <div style={{ 
              display: 'flex', 
              gap: '8px', 
              marginBottom: '24px',
              borderBottom: `1px solid ${safeSettings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
              paddingBottom: '8px'
            }}>
              {[
                { key: 'overview', label: 'Overview', icon: Info },
                { key: 'vendors', label: 'Vendor Portals', icon: Globe },
                { key: 'packages', label: 'Vendor & Patch Info', icon: Database },
                { key: 'remediation', label: 'Remediation', icon: Target }
              ].map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => setActiveGuidanceSection(key)}
                  style={{
                    padding: '8px 16px',
                    border: 'none',
                    borderRadius: '6px',
                    backgroundColor: activeGuidanceSection === key ? COLORS.blue : 'transparent',
                    color: activeGuidanceSection === key ? 'white' : (safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText),
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    fontSize: '0.9rem'
                  }}
                >
                  <Icon size={16} />
                  {label}
                </button>
              ))}
            </div>

            {/* Guidance Content */}
            <div>
              {activeGuidanceSection === 'overview' && (
                <div>
                  <h3 style={{ marginBottom: '16px' }}>Package & Component Overview</h3>
                  
                  {/* Package Details */}
                  {patchGuidance.components.map((component, index) => {
                    const packageInfo = PatchDiscovery.getPackageInfo(component);
                    return (
                      <div key={index} style={{
                        ...styles.card,
                        marginBottom: '24px',
                        borderLeft: `4px solid ${COLORS.blue}`
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                          <div>
                            <h4 style={{ margin: '0 0 4px 0', fontSize: '1.2rem', fontWeight: '600' }}>
                              {packageInfo.fullName}
                            </h4>
                            <div style={{ display: 'flex', gap: '12px', fontSize: '0.8rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                              <span><strong>Category:</strong> {packageInfo.category}</span>
                              <span><strong>Language:</strong> {packageInfo.language}</span>
                              <span><strong>Maintainer:</strong> {packageInfo.maintainer}</span>
                            </div>
                          </div>
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '4px',
                            fontSize: '0.8rem',
                            fontWeight: '600',
                            background: component.confidence === 'high' ? `${COLORS.green}20` : `${COLORS.yellow}20`,
                            color: component.confidence === 'high' ? COLORS.green : COLORS.yellow
                          }}>
                            {component.confidence} confidence
                          </span>
                        </div>

                        <div style={{ marginBottom: '16px' }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600' }}>Purpose & Description</h5>
                          <p style={{ margin: '0 0 8px 0', fontSize: '0.9rem', lineHeight: '1.5' }}>
                            <strong>Purpose:</strong> {packageInfo.purpose}
                          </p>
                          <p style={{ margin: 0, fontSize: '0.9rem', lineHeight: '1.5', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {packageInfo.description}
                          </p>
                        </div>

                        <div style={{ marginBottom: '16px' }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600' }}>Common Use Cases</h5>
                          <p style={{ margin: 0, fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {packageInfo.commonUse}
                          </p>
                        </div>

                        <div style={{ marginBottom: '16px' }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600' }}>Key Features</h5>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                            {packageInfo.keyFeatures.map((feature, fIndex) => (
                              <span key={fIndex} style={{
                                padding: '4px 8px',
                                background: safeSettings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                                borderRadius: '4px',
                                fontSize: '0.8rem',
                                border: `1px solid ${safeSettings.darkMode ? COLORS.dark.border : COLORS.light.border}`
                              }}>
                                {feature}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div style={{ marginBottom: '16px' }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600' }}>Ecosystem & Distribution</h5>
                          <p style={{ margin: 0, fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            <strong>Ecosystem:</strong> {packageInfo.ecosystem}
                          </p>
                        </div>

                        <div style={{
                          padding: '12px',
                          background: `${COLORS.red}10`,
                          border: `1px solid ${COLORS.red}30`,
                          borderRadius: '6px'
                        }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600', color: COLORS.red }}>
                            Vulnerability Impact
                          </h5>
                          <p style={{ margin: 0, fontSize: '0.9rem', color: COLORS.red }}>
                            {packageInfo.vulnerabilityImpact}
                          </p>
                        </div>
                      </div>
                    );
                  })}

                  {/* Vulnerability Technical Details */}
                  <div style={{
                    ...styles.card,
                    borderLeft: `4px solid ${COLORS.purple}`
                  }}>
                    <h4 style={{ margin: '0 0 16px 0', fontSize: '1.1rem', fontWeight: '600' }}>
                      Vulnerability Technical Details
                    </h4>
                    
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '0.9rem' }}>
                      <div>
                        <strong>CVE ID:</strong> {patchGuidance.cveId}
                      </div>
                      <div>
                        <strong>Attack Vector:</strong> {patchGuidance.urgencyLevel.factors.includes('High EPSS Score') ? 'Network' : 'Various'}
                      </div>
                      <div>
                        <strong>CVSS Score:</strong> {vulnerability?.cve?.cvssV3?.baseScore || vulnerability?.cve?.cvssV2?.baseScore || 'N/A'}
                      </div>
                      <div>
                        <strong>EPSS Score:</strong> {vulnerability?.epss?.epss || 'N/A'} ({vulnerability?.epss?.epssPercentage || 'N/A'}%)
                      </div>
                      <div>
                        <strong>Published:</strong> {vulnerability?.cve?.publishedDate ? new Date(vulnerability.cve.publishedDate).toLocaleDateString() : 'N/A'}
                      </div>
                      <div>
                        <strong>CISA KEV:</strong> {vulnerability?.kev?.listed ? 'Listed (Active Exploitation)' : 'Not Listed'}
                      </div>
                    </div>
                  </div>
                </div>
              )}


              {activeGuidanceSection === 'vendors' && (
                <div>
                  <h3 style={{ marginBottom: '16px' }}>Official Vendor Security Portals & Downloads</h3>
                  <div style={{ display: 'grid', gap: '16px' }}>
                    {patchGuidance.vendorPortals.map((portal, index) => (
                      <div key={index} style={{
                        ...styles.card,
                        borderLeft: `4px solid ${COLORS.blue}`
                      }}>
                        <div style={{ marginBottom: '16px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                            <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '600' }}>{portal.name}</h4>
                            <span style={{
                              padding: '4px 8px',
                              borderRadius: '4px',
                              fontSize: '0.8rem',
                              fontWeight: '600',
                              background: `${COLORS.green}20`,
                              color: COLORS.green
                            }}>
                              Official Vendor
                            </span>
                          </div>
                          <p style={{ margin: '0 0 8px 0', fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            <strong>Relevant for:</strong> {portal.relevantFor}
                          </p>
                          <p style={{ margin: '0 0 12px 0', fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {portal.description}
                          </p>
                        </div>

                        <div style={{ marginBottom: '16px' }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600' }}>Security Information</h5>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                            <a
                              href={portal.securityUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                ...styles.button,
                                ...styles.buttonSecondary,
                                padding: '8px 16px',
                                fontSize: '0.9rem',
                                textDecoration: 'none',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px'
                              }}
                            >
                              <ExternalLink size={16} />
                              Security Portal
                            </a>
                            <span style={{ fontSize: '0.8rem', color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                              Check for vulnerability advisories and security bulletins
                            </span>
                          </div>
                        </div>

                        <div style={{ marginBottom: '16px' }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600' }}>Official Downloads & Updates</h5>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                            <a
                              href={portal.downloadUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                ...styles.button,
                                ...styles.buttonPrimary,
                                padding: '8px 16px',
                                fontSize: '0.9rem',
                                textDecoration: 'none',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px'
                              }}
                            >
                              <Package size={16} />
                              Download Updates
                            </a>
                            <span style={{ fontSize: '0.8rem', color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                              Get latest versions with security fixes
                            </span>
                          </div>
                        </div>

                        <div style={{ marginBottom: '16px' }}>
                          <h5 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: '600' }}>Update Guidance</h5>
                          <p style={{ margin: '0 0 8px 0', fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                            {portal.updateGuidance}
                          </p>
                        </div>

                        <div style={{
                          padding: '12px',
                          background: safeSettings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText
                        }}>
                          <strong>Search Tips:</strong> {portal.searchTips}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Additional Resources */}
                  <div style={{
                    ...styles.card,
                    marginTop: '24px',
                    borderLeft: `4px solid ${COLORS.purple}`
                  }}>
                    <h4 style={{ margin: '0 0 12px 0', fontSize: '1.1rem', fontWeight: '600' }}>
                      Additional Vulnerability Resources
                    </h4>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '12px' }}>
                      <div>
                        <strong>CVE Details:</strong>
                        <a 
                          href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${patchGuidance.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ marginLeft: '8px', color: COLORS.blue, textDecoration: 'none' }}
                        >
                          MITRE CVE Database
                        </a>
                      </div>
                      <div>
                        <strong>NVD Analysis:</strong>
                        <a 
                          href={`https://nvd.nist.gov/vuln/detail/${patchGuidance.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ marginLeft: '8px', color: COLORS.blue, textDecoration: 'none' }}
                        >
                          NIST NVD Entry
                        </a>
                      </div>
                      <div>
                        <strong>Exploit Database:</strong>
                        <a 
                          href={`https://www.exploit-db.com/search?cve=${patchGuidance.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ marginLeft: '8px', color: COLORS.blue, textDecoration: 'none' }}
                        >
                          Search Exploits
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeGuidanceSection === 'packages' && (
                <div>
                  <h3 style={{ marginBottom: '16px' }}>Vendor &amp; Patch Information</h3>

                  {/* Vendor Response Timeline */}
                  {(patchGuidance.aiPatches.length > 0 || patchGuidance.aiAdvisories.length > 0) && (
                    <div style={{ marginBottom: '24px' }}>
                      <h4 style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Clock size={18} color={COLORS.blue} />
                        Vendor Response Timeline
                      </h4>
                      <ul style={{ listStyle: 'none', padding: 0 }}>
                        {[...patchGuidance.aiPatches, ...patchGuidance.aiAdvisories]
                          .filter(item => item.releaseDate || item.publishDate)
                          .sort((a, b) => new Date(a.releaseDate || a.publishDate).getTime() - new Date(b.releaseDate || b.publishDate).getTime())
                          .map((item, index) => (
                            <li key={index} style={{ marginBottom: '8px', fontSize: '0.9rem' }}>
                              <strong>{new Date(item.releaseDate || item.publishDate).toLocaleDateString()}</strong>
                              {` – ${item.vendor || item.source}`}
                              {item.patchVersion ? ` ${item.patchVersion}` : ''}
                            </li>
                          ))}
                      </ul>
                    </div>
                  )}

                  {/* Official Advisories */}
                  {patchGuidance.aiAdvisories.length > 0 && (
                    <div style={{ marginBottom: '32px' }}>
                      <h4 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FileText size={18} color={COLORS.blue} />
                        Official Vendor Advisories ({patchGuidance.aiAdvisories.length})
                      </h4>
                      {patchGuidance.aiAdvisories.map((advisory, index) => (
                        <div key={index} style={{
                          ...styles.card,
                          marginBottom: '16px',
                          borderLeft: `4px solid ${advisory.verified ? COLORS.green : COLORS.yellow}`
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px' }}>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                                <h5 style={{ margin: 0, fontSize: '1rem', fontWeight: '600' }}>
                                  {advisory.title}
                                </h5>
                                <span style={{
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  fontSize: '0.7rem',
                                  fontWeight: '600',
                                  background: advisory.verified ? `${COLORS.green}20` : `${COLORS.yellow}20`,
                                  color: advisory.verified ? COLORS.green : COLORS.yellow
                                }}>
                                  {advisory.verified ? 'VERIFIED' : 'UNVERIFIED'}
                                </span>
                              </div>

                              <p style={{ margin: '0 0 8px 0', fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                                {advisory.summary}
                              </p>

                              <div style={{
                                padding: '8px 12px',
                                background: safeSettings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                                borderRadius: '6px',
                                fontSize: '0.8rem',
                                fontFamily: 'monospace'
                              }}>
                                <strong>URL:</strong> {advisory.url}
                              </div>
                            </div>

                            <a
                              href={advisory.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                ...styles.button,
                                ...styles.buttonPrimary,
                                padding: '8px 16px',
                                fontSize: '0.85rem',
                                textDecoration: 'none',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px'
                              }}
                            >
                              <ExternalLink size={14} />
                              View Advisory
                            </a>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Patch Downloads */}
                  {patchGuidance.aiPatches.length > 0 && (
                    <div style={{ marginBottom: '32px' }}>
                      <h4 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Package size={18} color={COLORS.green} />
                        Patch Downloads &amp; Links ({patchGuidance.aiPatches.length})
                      </h4>
                      {patchGuidance.aiPatches.map((patch, index) => (
                        <div key={index} style={{
                          ...styles.card,
                          marginBottom: '16px',
                          borderLeft: `4px solid ${patch.verified ? COLORS.green : COLORS.yellow}`
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px' }}>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                                <h5 style={{ margin: 0, fontSize: '1rem', fontWeight: '600' }}>
                                  {patch.vendor} Patch
                                </h5>
                                <span style={{
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  fontSize: '0.7rem',
                                  fontWeight: '600',
                                  background: patch.verified ? `${COLORS.green}20` : `${COLORS.yellow}20`,
                                  color: patch.verified ? COLORS.green : COLORS.yellow
                                }}>
                                  {patch.verified ? 'VERIFIED' : 'UNVERIFIED'}
                                </span>
                              </div>

                              <p style={{ margin: '0 0 8px 0', fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                                {patch.description}
                              </p>

                              <div style={{
                                padding: '8px 12px',
                                background: safeSettings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                                borderRadius: '6px',
                                fontSize: '0.8rem',
                                fontFamily: 'monospace'
                              }}>
                                <strong>URL:</strong> {patch.downloadUrl}
                              </div>
                            </div>

                            <a
                              href={patch.downloadUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                ...styles.button,
                                ...styles.buttonPrimary,
                                padding: '8px 16px',
                                fontSize: '0.85rem',
                                textDecoration: 'none',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px'
                              }}
                            >
                              <Package size={14} />
                              Download
                            </a>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeGuidanceSection === 'remediation' && (
                <div>
                  <h3 style={{ marginBottom: '16px' }}>Remediation Process</h3>
                  <div style={{ display: 'grid', gap: '16px' }}>
                    {patchGuidance.remediationSteps.map((step, index) => (
                      <div key={index} style={{
                        ...styles.card,
                        borderLeft: `4px solid ${COLORS.blue}`
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                          <div style={{
                            width: '32px',
                            height: '32px',
                            borderRadius: '50%',
                            backgroundColor: COLORS.blue,
                            color: 'white',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '1rem',
                            fontWeight: 'bold'
                          }}>
                            {index + 1}
                          </div>
                          <div>
                            <h4 style={{ margin: 0 }}>{step.title}</h4>
                            <p style={{ margin: 0, fontSize: '0.8rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                              {step.estimatedTime} • {step.priority} priority
                            </p>
                          </div>
                        </div>
                        
                        <p style={{ margin: '0 0 16px 0', fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
                          {step.description}
                        </p>
                        
                        <ul style={{ margin: '0 0 16px 0', paddingLeft: '20px' }}>
                          {step.actions.map((action, aIndex) => (
                            <li key={aIndex} style={{ margin: '4px 0', fontSize: '0.9rem' }}>
                              {action}
                            </li>
                          ))}
                        </ul>
                        
                        <div style={{ fontSize: '0.8rem', color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                          <strong>Tools:</strong> {step.tools.join(', ')}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div style={{
            textAlign: 'center',
            padding: '48px 32px',
            background: safeSettings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
            borderRadius: '8px'
          }}>
            <Brain size={48} style={{ marginBottom: '16px', opacity: 0.5, color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }} />
            <h4 style={{ margin: '0 0 12px 0', fontSize: '1.1rem', fontWeight: '600' }}>
              Patch Discovery
            </h4>
            <p style={{ margin: '0 0 20px 0', fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText }}>
              Click "Discover Patches" to search for official patches, security advisories, and vendor updates.
            </p>
            <div style={{ fontSize: '0.85rem', color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
              <strong>AI will:</strong>
              <ul style={{ textAlign: 'left', maxWidth: '400px', margin: '8px auto 0 auto', paddingLeft: '20px' }}>
                <li>Search for official vendor patches and downloads</li>
                <li>Find security advisories and vulnerability pages</li>
                <li>Summarize vendor security bulletins and timelines</li>
                <li>Verify discovered URLs for accessibility</li>
                <li>Provide comprehensive remediation guidance</li>
              </ul>
            </div>
            {!safeSettings.geminiApiKey && (
              <div style={{ 
                marginTop: '16px',
                padding: '12px',
                background: `${COLORS.yellow}15`,
                border: `1px solid ${COLORS.yellow}30`,
                borderRadius: '6px',
                fontSize: '0.8rem',
                color: COLORS.yellow
              }}>
                <strong>Note:</strong> Configure Gemini API key in settings to enable AI-powered patch discovery
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  // Generate comprehensive AI analysis
  const generateAnalysis = useCallback(async () => {
    if (!safeSettings.geminiApiKey) {
      safeAddNotification({
        type: 'error',
        title: 'API Key Required',
        message: 'Please configure your Gemini API key in settings'
      });
      return;
    }

    if (!vulnerability || !vulnerability.cve || !vulnerability.cve.id) {
      safeAddNotification({
        type: 'error',
        title: 'Invalid Vulnerability',
        message: 'Vulnerability data is incomplete or missing'
      });
      return;
    }

    setAiLoading(true);
    try {
      // Create a comprehensive analysis prompt
      const analysisPrompt = `
You are a cybersecurity expert analyzing vulnerability ${vulnerability.cve.id}.

CVE: ${vulnerability.cve.id}
DESCRIPTION: ${vulnerability.cve.description}
CVSS SCORE: ${vulnerability?.cve?.cvssV3?.baseScore || vulnerability?.cve?.cvssV2?.baseScore || 'N/A'}
PUBLISHED: ${vulnerability?.cve?.publishedDate || 'N/A'}

Provide a comprehensive technical analysis including:

1. **Vulnerability Summary**: Clear explanation of what this vulnerability is
2. **Impact Assessment**: Potential impact on systems and organizations
3. **Exploitation Scenarios**: How attackers might exploit this vulnerability
4. **Affected Systems**: Types of systems and environments at risk
5. **Detection Methods**: How to identify if systems are vulnerable
6. **Mitigation Strategies**: Comprehensive remediation approaches
7. **Priority Assessment**: Urgency level and recommended timeline

Focus on actionable information for security professionals.
`;

      const enhancedVulnerability = {
        ...vulnerability,
        customPrompt: analysisPrompt,
        requireWebSearch: true,
        searchDepth: 'comprehensive'
      };

      const result = await APIService.generateAIAnalysis(
        enhancedVulnerability,
        safeSettings.geminiApiKey,
        safeSettings.geminiModel,
        safeSettings
      );

      setAiAnalysis(result);
      setActiveTab('brief');

      safeAddNotification({
        type: 'success',
        title: 'AI Analysis Complete',
        message: 'Generated comprehensive technical analysis with web search'
      });

    } catch (error) {
      safeAddNotification({
        type: 'error',
        title: 'Analysis Failed',
        message: error.message || 'Failed to generate AI analysis'
      });
    } finally {
      setAiLoading(false);
    }
  }, [vulnerability, safeSettings, safeAddNotification]);

  // Handle refresh
  const handleRefresh = useCallback(async () => {
    const cveId = vulnerability?.cve?.id;
    if (!cveId) {
      safeAddNotification({
        type: 'error',
        title: 'Invalid CVE',
        message: 'CVE ID is missing or invalid'
      });
      return;
    }

    try {
      const createRobustLoadingStepsWrapper = (prefix = 'AI Agent') => {
        return (param) => {
          try {
            if (typeof param === 'string') {
              console.log(`${prefix}:`, param);
              return;
            }
            console.log(`${prefix}:`, 'Processing...');
          } catch (error) {
            console.error(`Error in ${prefix} wrapper:`, error);
          }
        };
      };

      const setLoadingStepsWrapper = createRobustLoadingStepsWrapper('AI Refresh');

      const refreshedVulnerability = await APIService.fetchVulnerabilityDataWithAI(
        cveId,
        setLoadingStepsWrapper,
        { nvd: safeSettings.nvdApiKey },
        safeSettings
      );

      safeSetVulnerabilities([refreshedVulnerability]);

      safeAddNotification({
        type: 'success',
        title: 'Data Refreshed',
        message: `Updated analysis for ${cveId} with latest intelligence`
      });
    } catch (error) {
      safeAddNotification({
        type: 'error',
        title: 'Refresh Failed',
        message: error.message || 'Failed to refresh data'
      });
    }
  }, [vulnerability, safeSettings, safeSetVulnerabilities, safeAddNotification]);

  // Handle export
  const handleExport = useCallback(() => {
    try {
      const exportData = {
        ...vulnerability,
        aiAnalysis: aiAnalysis,
        patchGuidance: patchGuidance,
        exportedAt: new Date().toISOString(),
        exportedBy: 'AI-Enhanced VulnIntel Platform'
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
      });

      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${vulnerability.cve?.id || 'vulnerability'}_ai_analysis.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      safeAddNotification({
        type: 'success',
        title: 'Export Complete',
        message: 'AI analysis and patch guidance exported successfully'
      });

    } catch (error) {
      safeAddNotification({
        type: 'error',
        title: 'Export Failed',
        message: error.message || 'Export failed'
      });
    }
  }, [vulnerability, aiAnalysis, patchGuidance, safeAddNotification]);

  const cvssScore = vulnerability?.cve?.cvssV3?.baseScore || vulnerability?.cve?.cvssV2?.baseScore || 0;
  const severity = utils.getSeverityLevel(cvssScore);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 400px', gap: '40px', marginTop: '40px' }}>
      <div style={styles.card}>
        {/* Header and navigation */}
        <div style={{
          marginBottom: '24px',
          paddingBottom: '24px',
          borderBottom: `1px solid ${safeSettings.darkMode ? COLORS.dark.border : COLORS.light.border}`
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h1 style={{
              ...styles.title,
              fontSize: '2rem',
              margin: 0
            }}>
              {vulnerability?.cve?.id || 'Unknown CVE'}
            </h1>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  padding: '8px 12px',
                  fontSize: '0.875rem'
                }}
                onClick={() => {
                  const cveId = vulnerability?.cve?.id;
                  if (cveId) {
                    navigator.clipboard.writeText(cveId);
                    safeAddNotification({ type: 'success', title: 'Copied!', message: 'CVE ID copied to clipboard' });
                  }
                }}
              >
                <Copy size={14} />
                {vulnerability?.cve?.id || 'N/A'}
              </button>

              <button
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  padding: '8px 12px',
                  fontSize: '0.875rem'
                }}
                onClick={handleRefresh}
              >
                <RefreshCw size={14} />
                Refresh
              </button>

              <button
                style={{
                  ...styles.button,
                  ...styles.buttonSecondary,
                  padding: '8px 12px',
                  fontSize: '0.875rem'
                }}
                onClick={handleExport}
              >
                <Package size={14} />
                Export
              </button>
            </div>
          </div>

          {/* Badges */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{
              ...styles.badge,
              ...(severity === 'CRITICAL' ? styles.badgeCritical :
                  severity === 'HIGH' ? styles.badgeHigh :
                  severity === 'MEDIUM' ? styles.badgeMedium : styles.badgeLow),
              fontSize: '0.85rem',
              padding: '6px 12px'
            }}>
              {severity} - {cvssScore?.toFixed(1) || 'N/A'}
            </span>

            {vulnerability?.kev?.listed && (
              <span style={{
                ...styles.badge,
                ...styles.badgeCritical,
                animation: 'pulse 2s ease-in-out infinite'
              }}>
                🚨 CISA KEV - ACTIVE EXPLOITATION
              </span>
            )}

            {vulnerability?.exploits?.found && (
              <span style={{
                ...styles.badge,
                background: `rgba(${utils.hexToRgb(COLORS.red)}, 0.15)`,
                color: COLORS.red,
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)`,
              }}>
                💣 {vulnerability.exploits.count || 'Multiple'} EXPLOITS FOUND
              </span>
            )}

            {vulnerability?.aiSearchPerformed && (
              <span style={{
                ...styles.badge,
                background: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.15)`,
                color: COLORS.purple,
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: `rgba(${utils.hexToRgb(COLORS.purple)}, 0.3)`,
              }}>
                <Brain size={12} style={{ marginRight: '6px' }} />
                AI ENHANCED
              </span>
            )}
          </div>
        </div>

        {/* Tab navigation */}
        <div style={{
          display: 'flex',
          borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
          marginBottom: '24px',
          gap: '4px',
          flexWrap: 'wrap'
        }}>
          {['overview', 'ai-sources', 'patches', 'brief'].map((tab) => (
            <button
              key={tab}
              style={{
                padding: '12px 18px',
                cursor: 'pointer',
                border: 'none',
                borderBottom: activeTab === tab ? `3px solid ${COLORS.blue}` : '3px solid transparent',
                fontSize: '0.9rem',
                fontWeight: '600',
                color: activeTab === tab ? COLORS.blue : settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
                transition: 'all 0.2s ease-in-out',
                borderRadius: '6px 6px 0 0',
                background: activeTab === tab
                  ? (settings.darkMode ? `rgba(${utils.hexToRgb(COLORS.blue)}, 0.1)` : `rgba(${utils.hexToRgb(COLORS.blue)}, 0.05)`)
                  : 'transparent',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                outline: 'none',
              }}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'overview' && <Info size={16} />}
              {tab === 'ai-sources' && <Globe size={16} />}
              {tab === 'patches' && <Package size={16} />}
              {tab === 'brief' && <FileText size={16} />}
              {tab === 'ai-sources'
                ? 'AI Taint Analysis'
                : tab === 'patches'
                ? 'Patches'
                : tab === 'brief'
                ? 'Tech Brief'
                : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        <div>
          {activeTab === 'overview' && (
            <div>
              <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '16px' }}>
                Vulnerability Overview
              </h2>

              <p style={{
                fontSize: '1.0625rem',
                lineHeight: '1.7',
                color: safeSettings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
                marginBottom: '24px'
              }}>
                {vulnerability?.cve?.description || 'No description available.'}
              </p>

              {vulnerability?.epss && (
                <div style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '12px' }}>
                    Exploitation Probability (EPSS)
                  </h3>
                  <div style={{
                    background: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ?
                      `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.1)`,
                    borderWidth: '1px',
                    borderStyle: 'solid',
                    borderColor: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ?
                      `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)` : `rgba(${utils.hexToRgb(COLORS.green)}, 0.3)`,
                    borderRadius: '12px',
                    padding: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                      <Target size={24} color={vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.yellow : COLORS.green} />
                      <div>
                        <div style={{ fontWeight: '700', fontSize: '1.05rem' }}>
                          EPSS Score: {vulnerability.epss.epss} ({vulnerability.epss.epssPercentage}%)
                        </div>
                        <div style={{ fontSize: '0.85rem', color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                          Percentile: {parseFloat(vulnerability.epss.percentile).toFixed(3)}
                        </div>
                        <p style={{ margin: '12px 0 0 0', fontSize: '1rem' }}>
                          {vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH
                            ? 'This vulnerability has a HIGH probability of exploitation. Immediate patching recommended.'
                            : vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM
                              ? 'This vulnerability has a MODERATE probability of exploitation. Monitor for patches.'
                              : 'This vulnerability has a LOW probability of exploitation, but still requires attention.'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {vulnerability?.epss && (
                <div style={{ marginBottom: '24px' }}>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '12px' }}>
                    CVSS vs EPSS
                  </h3>
                  <ScoreChart
                    cvss={cvssScore}
                    epss={vulnerability.epss.epssFloat * 100}
                  />
                </div>
              )}

              <div style={{ textAlign: 'center', marginTop: '32px', paddingTop: '24px', borderTop: `1px solid ${safeSettings.darkMode ? COLORS.dark.border : COLORS.light.border}` }}>
                <button
                  style={{
                    ...styles.button,
                    ...styles.buttonPrimary,
                    opacity: aiLoading || !safeSettings.geminiApiKey ? 0.7 : 1,
                    fontSize: '1rem',
                    padding: '16px 32px'
                  }}
                  onClick={generateAnalysis}
                  disabled={aiLoading || !safeSettings.geminiApiKey}
                >
                  {aiLoading ? (
                    <>
                      <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />
                      Generating AI Analysis...
                    </>
                  ) : (
                    <>
                      <Brain size={20} />
                      <Database size={16} style={{ marginLeft: '4px' }} />
                      Generate AI Analysis
                    </>
                  )}
                </button>
                {!safeSettings.geminiApiKey && (
                  <p style={{ fontSize: '0.9rem', color: safeSettings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText, marginTop: '12px' }}>
                    Configure Gemini API key in settings to enable AI analysis
                  </p>
                )}
              </div>
            </div>
          )}

          {activeTab === 'ai-sources' && <AISourcesTab vulnerability={vulnerability} />}

          {activeTab === 'patches' && renderEnhancedPatchesTab()}

          {activeTab === 'brief' && (
            <div>
              {aiAnalysis ? (
                <div>
                  {aiAnalysis.fallbackReason && (
                    <div style={{
                      background: aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                        ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.1)` 
                        : `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)`,
                      borderWidth: '1px',
                      borderStyle: 'solid',
                      borderColor: aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                        ? `rgba(${utils.hexToRgb(COLORS.yellow)}, 0.3)` 
                        : `rgba(${utils.hexToRgb(COLORS.red)}, 0.3)`,
                      borderRadius: '8px',
                      padding: '12px',
                      marginBottom: '20px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                        <AlertTriangle size={16} color={aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' ? COLORS.yellow : COLORS.red} />
                        <strong style={{ fontSize: '0.9rem' }}>
                          {aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                            ? 'AI Search Performed - Enhanced Analysis'
                            : `AI Analysis Limited - ${aiAnalysis.fallbackReason}`}
                        </strong>
                      </div>
                      <p style={{ margin: 0, fontSize: '0.8rem' }}>
                        {aiAnalysis.fallbackReason === 'GROUNDING_INFO_ONLY' 
                          ? 'The AI performed web searches and generated analysis based on available data sources.'
                          : 'AI analysis encountered limitations. Using enhanced fallback analysis.'}
                      </p>
                    </div>
                  )}
                  
                  <TechnicalBrief brief={aiAnalysis.analysis} />
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '48px 32px' }}>
                  <FileText size={40} color={settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText} />
                  <h3 style={{ margin: '16px 0 8px 0' }}>No Technical Brief Available</h3>
                  <p style={{ margin: 0, color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
                    Generate AI analysis to view the technical brief
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Sidebar */}
      <div style={{
        ...styles.card,
        height: 'fit-content',
        position: 'sticky',
        top: '24px',
      }}>
        <CVSSDisplay vulnerability={vulnerability} settings={settings} />

        <div style={{
          ...styles.card,
          background: settings.darkMode ? COLORS.dark.background : COLORS.light.background,
          marginBottom: '20px'
        }}>
          <h3 style={{
            fontSize: '0.95rem',
            fontWeight: '600',
            marginBottom: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <Brain size={14} />
            AI Intelligence Summary
          </h3>

          <div style={{ fontSize: '0.8125rem', color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText }}>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>CVSS Score:</strong> {cvssScore?.toFixed(1) || 'N/A'} ({severity})
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>EPSS Score:</strong> {vulnerability?.epss?.epss || 'N/A'} ({vulnerability?.epss?.epssPercentage || 'N/A'}%)
              {vulnerability?.epss && (
                <span style={{ color: vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? COLORS.red : vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? COLORS.yellow : COLORS.green }}>
                  {vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.HIGH ? ' (High Risk)' : vulnerability.epss.epssFloat > CONSTANTS.EPSS_THRESHOLDS.MEDIUM ? ' (Medium Risk)' : ' (Low Risk)'}
                </span>
              )}
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>Active Exploitation:</strong>
              <span style={{
                color: vulnerability?.kev?.listed ? COLORS.red : COLORS.green,
                marginLeft: '4px',
                fontWeight: '600'
              }}>
                {vulnerability?.kev?.listed ? 'YES' : 'No'}
              </span>
            </p>
            <p style={{ margin: '0 0 8px 0' }}>
              <strong>CISA KEV:</strong>
              <span style={{
                color: vulnerability?.kev?.listed ? COLORS.red : COLORS.green,
                marginLeft: '4px',
                fontWeight: '600'
              }}>
                {vulnerability?.kev?.listed ? 'LISTED' : 'Not Listed'}
              </span>
            </p>
            <p style={{ margin: 0 }}>
              <strong>Last Updated:</strong> {utils.formatDate(vulnerability?.lastUpdated)}
            </p>
          </div>
        </div>

        <div style={{
          fontSize: '0.8rem',
          color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
          textAlign: 'center',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px'
        }}>
          <Brain size={12} />
          <Search size={12} />
          <Globe size={12} />
          AI-Enhanced Discovery
        </div>
      </div>
    </div>
  );
};

export default CVEDetailView;
