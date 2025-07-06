import React, { useContext, useMemo, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { COLORS } from '../utils/constants';

interface TechnicalBriefProps {
  brief: string | null | undefined;
  defaultExpandedSections?: string[];
}

interface Section {
  id: string;
  title: string;
  content: string;
  level: number;
}

const TechnicalBrief: React.FC<TechnicalBriefProps> = ({ 
  brief, 
  defaultExpandedSections = []
}) => {
  const { settings } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(defaultExpandedSections)
  );

  if (!brief || brief.trim().length === 0) {
    return (
      <p style={{ 
        fontSize: '0.875rem', 
        color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText 
      }}>
        No technical brief available.
      </p>
    );
  }

  // Extract CVE summary information
  const extractCVESummary = (content: string) => {
    const lines = content.split('\n');
    let cveId = '';
    let status = '';
    let priority = '';
    let confidence = '';
    
    // Extract CVE ID from first line
    const titleMatch = lines[0]?.match(/CVE-\d{4}-\d+/);
    if (titleMatch) {
      cveId = titleMatch[0];
    }
    
    // Extract status, priority, confidence from early lines
    for (const line of lines.slice(0, 15)) {
      if (line.includes('**Status**:')) {
        status = line.replace(/\*\*Status\*\*:\s*/, '').trim();
      }
      if (line.includes('**Priority**:')) {
        priority = line.replace(/\*\*Priority\*\*:\s*/, '').trim();
      }
      if (line.includes('**Confidence**:')) {
        confidence = line.replace(/\*\*Confidence\*\*:\s*/, '').trim();
      }
    }
    
    return { cveId, status, priority, confidence };
  };

  // Parse the markdown content into sections
  const parseSections = (content: string): Section[] => {
    const lines = content.split('\n');
    const sections: Section[] = [];
    let currentSection: Section | null = null;
    let headerContent: string[] = [];
    let inHeaderSection = true;
    let lineIndex = 0;

    console.log('Parsing content with', lines.length, 'lines');

    for (const line of lines) {
      const trimmedLine = line.trim();
      
      // Check for headers (# ## ### etc.)
      const headerMatch = trimmedLine.match(/^(#{1,6})\s+(.+)$/);
      
      if (headerMatch) {
        // Save previous section if exists
        if (currentSection) {
          currentSection.content = currentSection.content.trim();
          console.log(`Adding section: ${currentSection.title}, content length: ${currentSection.content.length}`);
          sections.push(currentSection);
        }
        
        inHeaderSection = false;
        const level = headerMatch[1].length;
        const title = headerMatch[2];
        const id = title.toLowerCase()
          .replace(/[^\w\s-()]/g, '')
          .replace(/\s+/g, '-')
          .replace(/-+/g, '-')
          .replace(/^-|-$/g, '');
        
        currentSection = {
          id: id || `section-${lineIndex}`,
          title,
          content: '',
          level
        };
        
        console.log(`Found header: ${title} (level ${level}, id: ${id})`);
      } else {
        if (inHeaderSection) {
          // This is header content (status, priority, etc.)
          headerContent.push(line);
        } else if (currentSection) {
          // Add to current section content
          currentSection.content += line + '\n';
        }
      }
      
      lineIndex++;
    }

    // Add the last section
    if (currentSection) {
      currentSection.content = currentSection.content.trim();
      console.log(`Adding final section: ${currentSection.title}, content length: ${currentSection.content.length}`);
      sections.push(currentSection);
    }

    // Add header content as the first section if it exists
    if (headerContent.length > 0) {
      const headerContentStr = headerContent.join('\n').trim();
      if (headerContentStr) {
        sections.unshift({
          id: 'header-info',
          title: 'Overview',
          content: headerContentStr,
          level: 1
        });
      }
    }

    console.log(`Total sections parsed: ${sections.length}`);
    return sections;
  };

  const sections = parseSections(brief);
  const cveSummary = extractCVESummary(brief);

  const toggleSection = (sectionId: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(sectionId)) {
      newExpanded.delete(sectionId);
    } else {
      newExpanded.add(sectionId);
    }
    setExpandedSections(newExpanded);
  };

  const isExpanded = (sectionId: string) => expandedSections.has(sectionId);

  // CVE Summary Card Styles
  const summaryCardStyle = {
    backgroundColor: settings.darkMode ? COLORS.dark.primaryBackground : COLORS.light.primaryBackground,
    border: `2px solid ${settings.darkMode ? COLORS.dark.accent : COLORS.light.accent}`,
    borderRadius: '8px',
    padding: '20px',
    marginBottom: '20px',
    boxShadow: settings.darkMode 
      ? '0 4px 6px rgba(0, 0, 0, 0.3)' 
      : '0 4px 6px rgba(0, 0, 0, 0.1)',
  };

  const summaryHeaderStyle = {
    fontSize: '1.5rem',
    fontWeight: '700',
    color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText,
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  };

  const summaryRowStyle = {
    display: 'flex',
    flexWrap: 'wrap' as const,
    gap: '16px',
    marginBottom: '12px',
  };

  const summaryItemStyle = {
    display: 'flex',
    flexDirection: 'column' as const,
    minWidth: '200px',
    flex: '1',
  };

  const summaryLabelStyle = {
    fontSize: '0.875rem',
    fontWeight: '600',
    color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
    marginBottom: '4px',
  };

  const summaryValueStyle = {
    fontSize: '1rem',
    fontWeight: '500',
    color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText,
  };

  // Priority color coding
  const getPriorityColor = (priority: string) => {
    if (priority.includes('P0')) return '#ff4444';
    if (priority.includes('P1')) return '#ff8800';
    if (priority.includes('P2')) return '#ffbb00';
    if (priority.includes('P3')) return '#88cc00';
    return settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText;
  };

  // Confidence color coding
  const getConfidenceColor = (confidence: string) => {
    if (confidence.includes('High')) return '#00cc44';
    if (confidence.includes('Medium')) return '#ffbb00';
    if (confidence.includes('Low')) return '#ff8800';
    return settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText;
  };

  const getSectionHeaderStyle = (level: number, expanded: boolean) => ({
    display: 'flex',
    alignItems: 'center',
    cursor: 'pointer',
    padding: `${Math.max(12 - level, 8)}px 16px`,
    backgroundColor: settings.darkMode ? COLORS.dark.secondaryBackground : COLORS.light.secondaryBackground,
    borderRadius: '6px',
    marginBottom: expanded ? '8px' : '4px',
    marginTop: level === 1 ? '0' : '8px',
    border: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
    userSelect: 'none' as const,
    fontSize: `${1.2 - (level * 0.1)}rem`,
    fontWeight: level <= 2 ? '600' : '500',
    transition: 'all 0.2s ease',
  });

  const getIconStyle = (expanded: boolean) => ({
    display: 'inline-block',
    transition: 'transform 0.2s ease',
    transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
    marginRight: '12px',
    fontSize: '0.875rem',
    color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
  });

  const getContentStyle = (level: number) => ({
    ...styles.card,
    fontSize: '0.9rem',
    lineHeight: '1.6',
    whiteSpace: 'pre-wrap' as const,
    marginTop: '0',
    marginBottom: '12px',
    marginLeft: level > 1 ? `${(level - 1) * 16}px` : '0',
    borderTop: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
    borderTopLeftRadius: '0',
    borderTopRightRadius: '0',
    paddingTop: '16px',
  });

  const handleSectionHover = (e: React.MouseEvent<HTMLDivElement>, isEntering: boolean) => {
    const target = e.currentTarget;
    if (isEntering) {
      target.style.backgroundColor = settings.darkMode ? COLORS.dark.hoverBackground : COLORS.light.hoverBackground;
      target.style.transform = 'translateX(2px)';
    } else {
      target.style.backgroundColor = settings.darkMode ? COLORS.dark.secondaryBackground : COLORS.light.secondaryBackground;
      target.style.transform = 'translateX(0px)';
    }
  };

  // Utility buttons
  const utilityButtonsStyle = {
    display: 'flex',
    gap: '8px',
    marginBottom: '16px',
    flexWrap: 'wrap' as const,
  };

  const buttonStyle = {
    padding: '6px 12px',
    fontSize: '0.75rem',
    border: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
    borderRadius: '4px',
    backgroundColor: settings.darkMode ? COLORS.dark.secondaryBackground : COLORS.light.secondaryBackground,
    color: settings.darkMode ? COLORS.dark.primaryText : COLORS.light.primaryText,
    cursor: 'pointer',
    transition: 'all 0.2s ease',
  };

  const expandAll = () => {
    setExpandedSections(new Set(sections.map(s => s.id)));
  };

  const collapseAll = () => {
    setExpandedSections(new Set());
  };

  const expandCritical = () => {
    const criticalSections = sections.filter(s => 
      s.title.toLowerCase().includes('executive') ||
      s.title.toLowerCase().includes('overview') ||
      s.title.toLowerCase().includes('core facts') ||
      s.title.toLowerCase().includes('actions required') ||
      s.title.toLowerCase().includes('patch information')
    );
    setExpandedSections(new Set(criticalSections.map(s => s.id)));
  };

  return (
    <div style={{ ...styles.card, padding: '20px' }}>
      {/* CVE Summary Card */}
      <div style={summaryCardStyle}>
        <div style={summaryHeaderStyle}>
          <span>📋</span>
          <span>{cveSummary.cveId || 'CVE Analysis'} - Quick Summary</span>
        </div>
        
        <div style={summaryRowStyle}>
          <div style={summaryItemStyle}>
            <div style={summaryLabelStyle}>Status</div>
            <div style={summaryValueStyle}>
              {cveSummary.status || 'Not specified'}
            </div>
          </div>
          
          <div style={summaryItemStyle}>
            <div style={summaryLabelStyle}>Priority</div>
            <div style={{
              ...summaryValueStyle,
              color: getPriorityColor(cveSummary.priority),
              fontWeight: '600',
            }}>
              {cveSummary.priority || 'Not specified'}
            </div>
          </div>
          
          <div style={summaryItemStyle}>
            <div style={summaryLabelStyle}>Confidence</div>
            <div style={{
              ...summaryValueStyle,
              color: getConfidenceColor(cveSummary.confidence),
              fontWeight: '600',
            }}>
              {cveSummary.confidence || 'Not specified'}
            </div>
          </div>
        </div>

        <div style={{
          fontSize: '0.875rem',
          color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
          fontStyle: 'italic',
          marginTop: '8px',
          padding: '8px',
          backgroundColor: settings.darkMode ? COLORS.dark.secondaryBackground : COLORS.light.secondaryBackground,
          borderRadius: '4px',
          borderLeft: `4px solid ${settings.darkMode ? COLORS.dark.accent : COLORS.light.accent}`,
        }}>
          💡 This summary provides a quick overview. Expand sections below for detailed analysis and action items.
        </div>
      </div>

      {/* Utility Buttons */}
      <div style={utilityButtonsStyle}>
        <button 
          style={buttonStyle}
          onClick={expandAll}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = settings.darkMode ? COLORS.dark.hoverBackground : COLORS.light.hoverBackground;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = settings.darkMode ? COLORS.dark.secondaryBackground : COLORS.light.secondaryBackground;
          }}
        >
          Expand All
        </button>
        <button 
          style={buttonStyle}
          onClick={collapseAll}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = settings.darkMode ? COLORS.dark.hoverBackground : COLORS.light.hoverBackground;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = settings.darkMode ? COLORS.dark.secondaryBackground : COLORS.light.secondaryBackground;
          }}
        >
          Collapse All
        </button>
        <button 
          style={buttonStyle}
          onClick={expandCritical}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = settings.darkMode ? COLORS.dark.hoverBackground : COLORS.light.hoverBackground;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = settings.darkMode ? COLORS.dark.secondaryBackground : COLORS.light.secondaryBackground;
          }}
        >
          Show Critical Only
        </button>
        <div style={{
          marginLeft: 'auto',
          fontSize: '0.75rem',
          color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
          alignSelf: 'center'
        }}>
          {expandedSections.size} of {sections.length} sections expanded
        </div>
      </div>

      {/* Sections */}
      {sections.map((section) => {
        const expanded = isExpanded(section.id);
        
        return (
          <div key={section.id} style={{ marginBottom: '4px' }}>
            {/* Section Header */}
            <div
              style={getSectionHeaderStyle(section.level, expanded)}
              onClick={() => toggleSection(section.id)}
              onMouseEnter={(e) => handleSectionHover(e, true)}
              onMouseLeave={(e) => handleSectionHover(e, false)}
            >
              <span style={getIconStyle(expanded)}>▶</span>
              <span style={{ flex: 1 }}>{section.title}</span>
              <span style={{ 
                fontSize: '0.75rem',
                color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
                marginLeft: '8px'
              }}>
                {expanded ? '−' : '+'}
              </span>
            </div>

            {/* Section Content */}
            {expanded && (
              <div style={getContentStyle(section.level)}>
                {section.content && section.content.trim() ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {section.content}
                  </ReactMarkdown>
                ) : (
                  <div style={{ 
                    color: settings.darkMode ? COLORS.dark.tertiaryText : COLORS.light.tertiaryText,
                    fontStyle: 'italic',
                    padding: '16px'
                  }}>
                    No content available for this section.
                  </div>
                )}
                
                {/* Debug info - remove in production */}
                {process.env.NODE_ENV === 'development' && (
                  <div style={{ 
                    fontSize: '0.75rem',
                    color: '#999',
                    borderTop: '1px solid #ddd',
                    paddingTop: '8px',
                    marginTop: '16px'
                  }}>
                    Debug: Content length: {section.content?.length || 0}, ID: {section.id}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default TechnicalBrief;
