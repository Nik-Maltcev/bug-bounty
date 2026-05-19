import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import PublicRoute from './components/PublicRoute';
import LoginPage from './pages/LoginPage';
import LandingPage from './pages/LandingPage';
import DashboardPage from './pages/DashboardPage';
import ProgramsPage from './pages/ProgramsPage';
import ProgramDetailPage from './pages/ProgramDetailPage';
import ScansPage from './pages/ScansPage';
import ScanDetailPage from './pages/ScanDetailPage';
import ScanReportPage from './pages/ScanReportPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import VulnerabilityDetailPage from './pages/VulnerabilityDetailPage';
import ReportsPage from './pages/ReportsPage';
import ReportEditPage from './pages/ReportEditPage';
import ClientsPage from './pages/ClientsPage';
import AuditLogPage from './pages/AuditLogPage';
import CompliancePage from './pages/CompliancePage';
import ChatPage from './pages/ChatPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route
          path="/"
          element={
            <PublicRoute>
              <LandingPage />
            </PublicRoute>
          }
        />
        <Route
          path="/login"
          element={
            <PublicRoute>
              <LoginPage />
            </PublicRoute>
          }
        />

        {/* Protected routes */}
        <Route
          path="/app"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="programs" element={<ProgramsPage />} />
          <Route path="programs/:id" element={<ProgramDetailPage />} />
          <Route path="programs/:id/chat" element={<ChatPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:id" element={<ScanDetailPage />} />
          <Route path="scans/:id/report" element={<ScanReportPage />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="reports/:id" element={<ReportEditPage />} />
          <Route path="clients" element={<ClientsPage />} />
          <Route path="audit" element={<AuditLogPage />} />
          <Route path="compliance" element={<CompliancePage />} />
        </Route>

        {/* Redirect unknown routes */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
