const AutomationPanel = ({ automateResponse, runAutomatedResponse }) => (
  <div className="automation-panel">
    <label>
      <input
        type="checkbox"
        checked={automateResponse}
        onChange={runAutomatedResponse}
      />
      Automate Response
    </label>
  </div>
);

export default AutomationPanel;
