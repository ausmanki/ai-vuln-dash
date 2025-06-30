import React, { useState, useCallback, useContext } from 'react';
import { UploadCloud, FileText, XCircle, Loader2, AlertTriangle, Zap, ExternalLink, Eye } from 'lucide-react'; // Added ExternalLink, Eye
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { extractCVEsFromCSV, extractCVEsFromPDF, extractCVEsFromXLSX } from '../services/FileParserService';
import { utils } from '../utils/helpers'; // For severity color and level
import { COLORS } from '../utils/constants'; // For direct color usage if needed

interface BulkUploadComponentProps {
  onClose: () => void;
  startBulkAnalysis: (cveIds: string[]) => Promise<void>;
  bulkAnalysisResults: Array<{cveId: string, data?: any, error?: string}>;
  isBulkLoading: boolean;
  bulkProgress: { current: number, total: number } | null;
}

const BulkUploadComponent: React.FC<BulkUploadComponentProps> = ({
  onClose,
  startBulkAnalysis,
  bulkAnalysisResults,
  isBulkLoading,
  bulkProgress
 }) => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = createStyles(settings.darkMode);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [extractedCVEs, setExtractedCVEs] = useState<string[]>([]);
  const [isParsing, setIsParsing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      if (file.size > 10 * 1024 * 1024) { // 10MB limit
        addNotification({ type: 'error', title: 'File Too Large', message: 'Please upload files smaller than 10MB.' });
        setSelectedFile(null);
        event.target.value = ''; // Clear the input
        return;
      }
      setSelectedFile(file);
      setExtractedCVEs([]);
      setError(null);
    }
  };

  const handleAnalyzeFile = useCallback(async () => {
    if (!selectedFile) return;

    setIsParsing(true);
    setError(null);
    setExtractedCVEs([]);
    addNotification({type: 'info', title: 'Parsing Started', message: `Parsing ${selectedFile.name}...`});

    try {
      let cves: string[] = [];
      if (selectedFile.name.endsWith('.csv')) {
        cves = await extractCVEsFromCSV(selectedFile);
      } else if (selectedFile.name.endsWith('.pdf')) {
        cves = await extractCVEsFromPDF(selectedFile);
      } else if (selectedFile.name.endsWith('.xlsx') || selectedFile.name.endsWith('.xls')) {
        cves = await extractCVEsFromXLSX(selectedFile);
      } else {
        setError("Unsupported file type. Please upload a CSV, PDF, or XLSX file.");
        setIsParsing(false);
        return;
      }

      if (cves.length > 0) {
        setExtractedCVEs(cves);
        addNotification({ type: 'success', title: 'Parsing Complete', message: `Found ${cves.length} CVEs.` });
      } else {
        setError(`No valid CVE IDs found in ${selectedFile.name}.`);
        addNotification({ type: 'warning', title: 'Parsing Complete', message: `No CVEs found in ${selectedFile.name}.` });
      }
    } catch (e: any) {
      console.error("File parsing error:", e);
      setError(`Error parsing file: ${e.message}`);
      addNotification({ type: 'error', title: 'Parsing Failed', message: e.message });
    } finally {
      setIsParsing(false);
    }
  }, [selectedFile, addNotification]);

  const handleStartFullAnalysis = () => {
    if (extractedCVEs.length > 0 && !isBulkLoading) {
      startBulkAnalysis(extractedCVEs);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000, // Ensure it's above other content but potentially below critical modals if any
    }}>
      <div style={{ ...styles.card, width: '90%', maxWidth: '800px', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h2 style={{ ...styles.title, fontSize: '1.5rem' }}>Bulk CVE Analysis</h2>
          <button onClick={onClose} style={{ ...styles.button, ...styles.buttonSecondary, padding: '8px' }} aria-label="Close">
            <XCircle size={20} />
          </button>
        </div>

        <div style={{ marginBottom: '20px', display: 'flex', gap: '10px', alignItems: 'stretch' }}>
          <label htmlFor="file-upload" style={{
            ...styles.button,
            ...styles.buttonSecondary,
            cursor: 'pointer',
            flexShrink: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <UploadCloud size={18} style={{ marginRight: '8px' }} />
            {selectedFile ? 'Change File' : 'Select File'}
          </label>
          <input
            id="file-upload"
            type="file"
            accept=".csv,.pdf,.xlsx"
            onChange={handleFileChange}
            style={{ display: 'none' }}
            disabled={isParsing}
          />
          {selectedFile && (
            <div style={{
              ...styles.input,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexGrow: 1,
              paddingLeft: '12px',
              paddingRight: '12px',
              overflow: 'hidden'
            }}>
              <span style={{textOverflow: 'ellipsis', whiteSpace: 'nowrap', overflow: 'hidden'}}>
                <FileText size={16} style={{ marginRight: '8px', verticalAlign: 'bottom' }} />
                {selectedFile.name}
              </span>
              <button onClick={() => {setSelectedFile(null); setExtractedCVEs([]); setError(null); (document.getElementById('file-upload') as HTMLInputElement).value = '';}}
                      style={{background: 'none', border: 'none', color: styles.app.color, cursor: 'pointer', padding: '4px'}}
                      disabled={isParsing}
                      aria-label="Clear selected file">
                <XCircle size={16}/>
              </button>
            </div>
          )}
          {!selectedFile && <div style={{...styles.input, display:'flex', alignItems:'center', color: styles.subtitle.color}}>No file selected.</div>}
        </div>

        <button
          onClick={handleAnalyzeFile}
          disabled={!selectedFile || isParsing}
          style={{ ...styles.button, ...styles.buttonPrimary, marginBottom: '20px', opacity: (!selectedFile || isParsing) ? 0.6 : 1 }}
        >
          {isParsing ? <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> : <FileText size={18} />}
          {isParsing ? 'Parsing File...' : 'Extract CVEs from File'}
        </button>

        {error && (
          <div style={{ color: COLORS.red, background: `rgba(${utils.hexToRgb(COLORS.red)}, 0.1)`, border: `1px solid rgba(${utils.hexToRgb(COLORS.red)}, 0.3)`, padding: '10px', borderRadius: '8px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={18} /> {error}
          </div>
        )}

        {extractedCVEs.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '10px' }}>Found {extractedCVEs.length} Valid CVEs:</h3>
            <div style={{ maxHeight: '150px', overflowY: 'auto', background: settings.darkMode ? COLORS.dark.background : COLORS.light.background, padding: '10px', borderRadius: '8px', border: styles.border }}>
              {extractedCVEs.map(cve => <div key={cve} style={{padding: '2px 0'}}>{cve}</div>)}
            </div>
            <button
              onClick={handleStartFullAnalysis}
              disabled={extractedCVEs.length === 0 || isBulkLoading || isParsing}
              style={{
                ...styles.button,
                ...styles.buttonPrimary, // Use primary button style
                marginTop: '10px',
                opacity: (extractedCVEs.length === 0 || isBulkLoading || isParsing) ? 0.6 : 1
              }}
            >
              {isBulkLoading ? <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> : <Zap size={18} />}
              {isBulkLoading ? `Analyzing ${bulkProgress?.current}/${bulkProgress?.total}...` : `Start Full Analysis for ${extractedCVEs.length} CVEs`}
            </button>
          </div>
        )}

        {isBulkLoading && bulkProgress && (
          <div style={{ marginTop: '10px', textAlign: 'center', fontStyle: 'italic', color: styles.subtitle.color }}>
            Analyzing {bulkProgress.current} of {bulkProgress.total} CVEs...
          </div>
        )}

        {bulkAnalysisResults.length > 0 && !isBulkLoading && (
          <div style={{ marginTop: '20px', flexGrow: 1, overflowY: 'auto', paddingRight: '10px' /* For scrollbar */ }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 600, marginBottom: '12px', color: styles.app.color }}>Analysis Results:</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {bulkAnalysisResults.map(resultItem => {
                const cveId = resultItem.cveId;
                const resultData = resultItem.data; // This is EnhancedVulnerabilityData
                const error = resultItem.error;

                let cvssScore: number | string = 'N/A';
                let cvssSeverity: string = 'N/A';
                let cvssVersion: string = '';

                if (resultData?.cve?.cvssV3) {
                  cvssScore = resultData.cve.cvssV3.baseScore;
                  cvssSeverity = resultData.cve.cvssV3.baseSeverity;
                  cvssVersion = 'v3';
                } else if (resultData?.cve?.cvssV2) {
                  cvssScore = resultData.cve.cvssV2.baseScore;
                  cvssSeverity = resultData.cve.cvssV2.severity;
                  cvssVersion = 'v2';
                }
                const severityColor = utils.getSeverityColor(cvssSeverity);

                return (
                  <div
                    key={cveId}
                    style={{
                      ...styles.card,
                      padding: '16px',
                      background: settings.darkMode ? COLORS.dark.surface : COLORS.light.surface,
                      borderLeft: `5px solid ${error ? COLORS.red : severityColor}`
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ fontWeight: 'bold', fontSize: '1.1rem', color: styles.app.color, textDecoration: 'none' }}
                        title={`View ${cveId} on NVD`}
                      >
                        {cveId} <ExternalLink size={14} style={{ display:'inline-block', marginLeft:'4px', opacity:0.7 }} />
                      </a>
                      {/* Placeholder for "View Full Details" button */}
                       <button
                          onClick={() => alert(`TODO: Show full details for ${cveId}`)}
                          style={{...styles.button, ...styles.buttonSecondary, padding: '6px 12px', fontSize: '0.8rem'}}
                          title="View Full Details"
                        >
                          <Eye size={14} /> Details
                       </button>
                    </div>

                    {error ? (
                      <div style={{ color: COLORS.red, fontWeight: 'bold' }}><AlertTriangle size={16} style={{marginRight: '5px'}}/> Error: {error}</div>
                    ) : resultData ? (
                      <div style={{ fontSize: '0.9rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
                        <div>
                          <strong>CVSS {cvssVersion}:</strong>
                          <span style={{ color: severityColor, fontWeight: 'bold' }}> {cvssScore} ({cvssSeverity})</span>
                        </div>
                        <div><strong>EPSS:</strong> {resultData.epss?.epssPercentage || 'N/A'}%</div>
                        <div><strong>KEV:</strong> {resultData.kev?.listed ? <span style={{color: COLORS.red, fontWeight:'bold'}}>LISTED</span> : 'Not Listed'}</div>
                        <div><strong>Threat Level:</strong> {resultData.threatLevel || 'N/A'}</div>
                        <div style={{ gridColumn: '1 / -1', marginTop: '8px', whiteSpace: 'pre-wrap', maxHeight: '60px', overflowY: 'auto', fontSize: '0.85rem', color: styles.subtitle.color, borderTop: `1px dashed ${styles.border}`, paddingTop: '8px' }}>
                          <strong>Summary:</strong> {resultData.summary || resultData.cve?.description?.substring(0,150) + '...' || 'No summary available.'}
                        </div>
                      </div>
                    ) : (
                      <div>No analysis data available.</div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BulkUploadComponent;
