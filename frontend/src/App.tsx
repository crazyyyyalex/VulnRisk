import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Navigation } from './components/Navigation';
import HomePage from './pages/index';
import AboutPage from './pages/about';
import APIKeyManagementPage from './pages/api-key-management';
import BatchPage from './pages/batch';
import AnalyticsPage from './pages/analytics';
import AIInsightsPage from './pages/ai-insights';
import ScannerIntegrationsPage from './pages/scanner-integrations';
import FedRAMPCompliancePage from './pages/fedramp-compliance';
import HolisticDashboardPage from './pages/holistic-dashboard';
import RiskAssessment from './pages/risk-assessment';
import AuthCallback from './components/AuthCallback';
import { Auth0Provider } from '@auth0/auth0-react';

const domain = import.meta.env.VITE_AUTH0_DOMAIN;
const clientId = import.meta.env.VITE_AUTH0_CLIENT_ID;
const audience = import.meta.env.VITE_AUTH0_AUDIENCE;

function App() {
  return (
    <Auth0Provider
      domain={domain}
      clientId={clientId}
      authorizationParams={{
        redirect_uri: `${window.location.origin}/callback`,
        audience: audience,
      }}
    >
      <Router>
        <div className="min-h-screen bg-gradient-to-br from-secondary-50 to-primary-50 dark:from-dark-500 dark:to-dark-600">
          <Navigation />
          <Routes>
            <Route path="/" element={<HomePage />} />
                              <Route path="/about" element={<AboutPage />} />
                  <Route path="/api-key-management" element={<APIKeyManagementPage />} />
            <Route path="/batch" element={<BatchPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/ai-insights" element={<AIInsightsPage />} />
            <Route path="/scanner-integrations" element={<ScannerIntegrationsPage />} />
            <Route path="/fedramp-compliance" element={<FedRAMPCompliancePage />} />
            <Route path="/holistic-dashboard" element={<HolisticDashboardPage />} />
            <Route path="/risk-assessment" element={<RiskAssessment />} />
            <Route path="/callback" element={<AuthCallback />} />
          </Routes>
        </div>
      </Router>
    </Auth0Provider>
  );
}

export default App; 