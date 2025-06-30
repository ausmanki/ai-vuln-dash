import React, { useState, useCallback, useContext } from 'react';
import { UploadCloud, FileText, XCircle, Loader2, AlertTriangle } from 'lucide-react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { extractCVEsFromCSV } from '../services/FileParserService'; // Updated import

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
        // cves = await extractCVEsFromPDF(selectedFile); // Placeholder for when PDF parsing is implemented
        setError("PDF parsing is not yet implemented. Please use CSV for now.");
      } else if (selectedFile.name.endsWith('.xlsx')) {
        // cves = await extractCVEsFromXLSX(selectedFile); // Placeholder for when XLSX parsing is implemented
        setError("XLSX parsing is not yet implemented. Please use CSV for now.");
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
          <div style={{ marginTop: '20px', flexGrow: 1, overflowY: 'auto' }}>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '10px' }}>Analysis Results:</h3>
            <div style={{ background: settings.darkMode ? COLORS.dark.background : COLORS.light.background, padding: '10px', borderRadius: '8px', border: styles.border }}>
              {bulkAnalysisResults.map(result => (
                <div key={result.cveId} style={{ padding: '8px 0', borderBottom: styles.border, marginBottom: '5px' }}>
                  <strong>{result.cveId}</strong>:
                  {result.error ? <span style={{color: COLORS.red}}> Error: {result.error}</span> :
                                   ` CVSS: ${result.data?.cve?.cvssV3?.baseScore || result.data?.cve?.cvssV2?.baseScore || 'N/A'} (${result.data?.cve?.cvssV3?.baseSeverity || result.data?.cve?.cvssV2?.severity || 'N/A'}), Threat: ${result.data?.threatLevel || 'N/A'}`}
                  {/* TODO: Add a button to view more details for each CVE, possibly opening CVEDetailView in a modal or separate context */}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BulkUploadComponent;
