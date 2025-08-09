const SettingsModal = ({ settingsOpen, setSettingsOpen }) => (
  settingsOpen && (
    <div className="modal">
      <button onClick={() => setSettingsOpen(false)}>Close</button>
      <h2>Settings</h2>
      {/* Settings form here */}
    </div>
  )
);

export default SettingsModal;
