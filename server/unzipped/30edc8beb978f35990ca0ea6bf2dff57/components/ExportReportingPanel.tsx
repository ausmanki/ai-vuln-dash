const ExportReportingPanel = ({ onExportCSV, onExportJSON, onExportPDF }) => (
  <div className="export-panel">
    <button onClick={onExportCSV}>Export CSV</button>
    <button onClick={onExportJSON}>Export JSON</button>
    <button onClick={onExportPDF}>Export PDF</button>
  </div>
);

export default ExportReportingPanel;
