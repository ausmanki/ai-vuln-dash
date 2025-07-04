export interface DetectedComponent {
  name: string;
  type: string;
  ecosystem: string;
  confidence: 'high' | 'low';
}

export function extractAffectedComponents(description: string): DetectedComponent[] {
  const components: DetectedComponent[] = [];
  const lowerDesc = description.toLowerCase();

  const componentPatterns = [
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
}

export function extractComponentNames(description: string): string[] {
  return extractAffectedComponents(description).map(c => c.name);
}
