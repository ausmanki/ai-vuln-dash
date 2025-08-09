import { AppProvider } from './context/AppContext';
import EnhancedSearchComponent from './components/EnhancedSearchComponent';
import EnhancedDashboard from './components/EnhancedDashboard';
import ExportReportingPanel from './components/ExportReportingPanel';
import AutomationPanel from './components/AutomationPanel';
import NotificationManager from './components/NotificationManager';
import EnhancedVulnerabilityCard from './components/EnhancedVulnerabilityCard';
import SettingsModal from './components/SettingsModal';

const App = () => (
  <AppProvider>
    <div className="app">
      <EnhancedSearchComponent />
      <EnhancedDashboard />
      <ExportReportingPanel />
      <AutomationPanel />
      <NotificationManager />
      <EnhancedVulnerabilityCard />
      <SettingsModal />
    </div>
  </AppProvider>
);

export default App;
