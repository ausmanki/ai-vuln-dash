import React, { useMemo, useContext, useState, useCallback } from 'react';
import { AppContext } from '../contexts/AppContext';
import { createStyles } from '../utils/styles';
import { X, Code, UploadCloud, File as FileIcon, Loader2 } from 'lucide-react';
import { COLORS } from '../utils/constants';

interface CodeAnalysisPageProps {
  onClose: () => void;
}

const CodeAnalysisPage: React.FC<CodeAnalysisPageProps> = ({ onClose }) => {
  const { settings, addNotification } = useContext(AppContext);
  const styles = useMemo(() => createStyles(settings.darkMode), [settings.darkMode]);
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [sbom, setSbom] = useState<any | null>(null);
  const [sinks, setSinks] = useState<any[] | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      if (selectedFile.type === 'application/zip' || selectedFile.name.endsWith('.zip')) {
        setFile(selectedFile);
        setSbom(null);
        setSinks(null);
      } else {
        addNotification?.({ type: 'error', title: 'Invalid File Type', message: 'Please upload a .zip file.' });
      }
    }
  };

  const handleUpload = async () => {
    if (!file) {
      addNotification?.({ type: 'error', title: 'No File Selected', message: 'Please select a file to upload.' });
      return;
    }

    setIsUploading(true);
    setSbom(null);
    setSinks(null);
    const formData = new FormData();
    formData.append('project', file);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      const result = await response.json();
      addNotification?.({ type: 'success', title: 'Analysis Complete', message: `${file.name} has been analyzed.` });
      setSbom(result.sbom);
      setSinks(result.sinks);

    } catch (error) {
      addNotification?.({ type: 'error', title: 'Upload Failed', message: 'An error occurred during upload.' });
    } finally {
      setIsUploading(false);
    }
  };

  const handleDragEnter = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile.type === 'application/zip' || droppedFile.name.endsWith('.zip')) {
        setFile(droppedFile);
      } else {
        addNotification?.({ type: 'error', title: 'Invalid File Type', message: 'Please upload a .zip file.' });
      }
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1001,
    }}>
      <div style={{
        ...styles.card,
        width: '90%',
        maxWidth: '1280px',
        height: '90vh',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
      }}>
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '16px',
            right: '16px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText,
          }}
          aria-label="Close Code Analysis"
        >
          <X size={24} />
        </button>
        <h2 style={{ ...styles.title, marginBottom: '24px', textAlign: 'center', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
          <Code size={28} />
          CVE-Driven Taint Analysis
        </h2>

        <div
          style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '24px', gap: '24px' }}
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '600px',
              border: `2px dashed ${isDragging ? COLORS.blue : (settings.darkMode ? COLORS.dark.border : COLORS.light.border)}`,
              borderRadius: '12px',
              padding: '48px',
              textAlign: 'center',
              backgroundColor: isDragging ? `rgba(${COLORS.blue}, 0.1)` : (settings.darkMode ? COLORS.dark.surface : COLORS.light.surface),
              transition: 'all 0.2s ease-in-out',
            }}
          >
            <UploadCloud size={64} style={{ color: COLORS.blue, marginBottom: '16px' }} />
            <h3 style={{ ...styles.subtitle, margin: '0 0 8px 0' }}>
              {file ? 'File Selected' : 'Drag & drop your project zip file here'}
            </h3>
            <p style={{ color: settings.darkMode ? COLORS.dark.secondaryText : COLORS.light.secondaryText, margin: '0 0 16px 0' }}>
              {file ? file.name : 'or click to browse'}
            </p>
            <input
              type="file"
              id="file-upload"
              accept=".zip"
              onChange={handleFileChange}
              style={{ display: 'none' }}
            />
            <label htmlFor="file-upload" style={{ ...styles.button, ...styles.buttonSecondary, cursor: 'pointer' }}>
              Browse File
            </label>
          </div>

          {file && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <button
                onClick={handleUpload}
                disabled={isUploading}
                style={{ ...styles.button, ...styles.buttonPrimary, padding: '12px 24px', fontSize: '1rem' }}
              >
                {isUploading ? (
                  <>
                    <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />
                    Analyzing...
                  </>
                ) : 'Analyze Project'}
              </button>
              <button
                onClick={() => setFile(null)}
                style={{ ...styles.button, ...styles.buttonSecondary }}
              >
                Clear
              </button>
            </div>
          )}

          {sbom && (
            <div style={{ width: '100%', maxWidth: '1000px', marginTop: '24px' }}>
                <h3 style={{ ...styles.subtitle, textAlign: 'center', marginBottom: '16px' }}>
                    Generated SBOM (Software Bill of Materials)
                </h3>
                <pre style={{
                    background: settings.darkMode ? COLORS.dark.background : COLORS.light.background,
                    border: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}`,
                    borderRadius: '8px',
                    padding: '16px',
                    maxHeight: '400px',
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    fontSize: '0.85rem',
                }}>
                    {JSON.stringify(sbom, null, 2)}
                </pre>
            </div>
          )}

          {sinks && sinks.length > 0 && (
            <div style={{ width: '100%', maxWidth: '1000px', marginTop: '24px' }}>
                <h3 style={{ ...styles.subtitle, textAlign: 'center', marginBottom: '16px' }}>
                    Potential Vulnerable Sinks Found
                </h3>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr style={{ borderBottom: `2px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}` }}>
                            <th style={{ padding: '12px', textAlign: 'left' }}>CWE</th>
                            <th style={{ padding: '12px', textAlign: 'left' }}>Description</th>
                            <th style={{ padding: '12px', textAlign: 'left' }}>File</th>
                            <th style={{ padding: '12px', textAlign: 'left' }}>Pattern</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sinks.map((sink, index) => (
                            <tr key={index} style={{ borderBottom: `1px solid ${settings.darkMode ? COLORS.dark.border : COLORS.light.border}` }}>
                                <td style={{ padding: '12px' }}>{sink.cwe}</td>
                                <td style={{ padding: '12px' }}>{sink.description}</td>
                                <td style={{ padding: '12px', fontFamily: 'monospace' }}>{sink.file}</td>
                                <td style={{ padding: '12px', fontFamily: 'monospace', color: COLORS.red }}>{sink.pattern}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CodeAnalysisPage;
