import React, { useState, useEffect } from 'react';
import { Header } from './components/Header.tsx';
import { Sidebar, NavTab } from './components/Sidebar.tsx';
import { DashboardView } from './components/views/DashboardView.tsx';
import { CasesView } from './components/views/CasesView.tsx';
import { SessionsView } from './components/views/SessionsView.tsx';
import { FindingsView } from './components/views/FindingsView.tsx';
import { CertificatesView } from './components/views/CertificatesView.tsx';
import { AnomaliesView } from './components/views/AnomaliesView.tsx';
import { AiRiskView } from './components/views/AiRiskView.tsx';
import { ReportsView } from './components/views/ReportsView.tsx';
import { ActiveScannerView } from './components/views/ActiveScannerView.tsx';
import { SensorIngestView } from './components/views/SensorIngestView.tsx';
import { AuditLogView } from './components/views/AuditLogView.tsx';
import { SettingsView } from './components/views/SettingsView.tsx';
import { HealthView } from './components/views/HealthView.tsx';
import { ApiClient } from './api/client.ts';
import {
  CaseRecord,
  SessionMetadata,
  Finding,
  Anomaly,
  UserProfile,
} from '../shared/types.ts';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const [currentCase, setCurrentCase] = useState<CaseRecord | null>(null);
  const [sessions, setSessions] = useState<SessionMetadata[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [certificates, setCertificates] = useState<any[]>([]);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedSessionId, setSelectedSessionId] = useState<string | undefined>(undefined);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const [currentUser, setCurrentUser] = useState<UserProfile>({
    id: 'user-admin',
    username: 'admin',
    role: 'ADMIN',
    name: 'Security Administrator',
  });

  const notify = (message: string, type: 'success' | 'error' = 'success') => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 4000);
  };

  const loadCaseData = async () => {
    try {
      const data = await ApiClient.getCases();
      setCases(data.cases || []);
      const activeId = data.activeCaseId || (data.cases.length > 0 ? data.cases[0].id : null);
      setActiveCaseId(activeId);

      if (activeId) {
        const cDetails = await ApiClient.getCase(activeId);
        setCurrentCase(cDetails.record);

        const sess = await ApiClient.getSessions();
        setSessions(sess || []);

        const finds = await ApiClient.getFindings();
        setFindings(finds || []);

        const certs = await ApiClient.getCertificates();
        setCertificates(certs || []);

        const anoms = await ApiClient.getAnomalies();
        setAnomalies(anoms || []);
      }
    } catch (e: any) {
      console.error('Failed to load case data:', e);
      notify(e.message || 'Failed to connect to backend', 'error');
    }
  };

  useEffect(() => {
    loadCaseData();
  }, []);

  const handleSelectCase = async (id: string) => {
    setIsLoading(true);
    try {
      await ApiClient.activateCase(id);
      setActiveCaseId(id);
      await loadCaseData();
      notify('Active forensic case switched.');
    } catch (e: any) {
      notify(e.message, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteCase = async (id: string) => {
    setIsLoading(true);
    try {
      await ApiClient.deleteCase(id);
      await loadCaseData();
      notify('Case deleted.');
    } catch (e: any) {
      notify(e.message, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUploadFile = async (file: File) => {
    setIsLoading(true);
    try {
      const buffer = new Uint8Array(await file.arrayBuffer());
      const res = await ApiClient.uploadPcap(buffer, file.name);
      await loadCaseData();
      setActiveCaseId(res.case.id);
      notify(`PCAP "${file.name}" ingested and analyzed.`);
      setCurrentTab('dashboard');
    } catch (e: any) {
      notify(e.message || 'PCAP ingestion failed', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadIncidentTrace = async () => {
    setIsLoading(true);
    try {
      const res = await ApiClient.loadIncidentTrace();
      await loadCaseData();
      setActiveCaseId(res.case.id);
      notify('Production incident audit trace ingested and reassembled.');
      setCurrentTab('dashboard');
    } catch (e: any) {
      notify(e.message || 'Incident trace loading failed', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTriggerAiEvaluation = async () => {
    setIsLoading(true);
    try {
      const updatedRisk = await ApiClient.evaluateAi();
      if (currentCase) {
        currentCase.riskAssessment = updatedRisk;
      }
      notify('AI risk reasoning and claim verification completed.');
    } catch (e: any) {
      notify(e.message || 'AI evaluation failed', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFilterFindings = (severity: string) => {
    setSeverityFilter(severity);
  };

  const handleInspectSession = (sessionId: string) => {
    setSelectedSessionId(sessionId);
    setCurrentTab('sessions');
  };

  const handleSwitchRole = (role: 'ADMIN' | 'ANALYST' | 'AUDITOR' | 'VIEWER') => {
    setCurrentUser((prev) => ({
      ...prev,
      role,
      name:
        role === 'ADMIN'
          ? 'Chief Security Officer (Admin)'
          : role === 'ANALYST'
          ? 'Senior SOC Forensic Analyst'
          : role === 'AUDITOR'
          ? 'Compliance Auditor'
          : 'Executive Viewer (Read-Only)',
    }));
    notify(`Switched active RBAC profile to ${role}.`);
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans selection:bg-zinc-800 selection:text-white">
      {/* Header */}
      <Header
        cases={cases}
        activeCaseId={activeCaseId}
        currentUser={currentUser}
        onSelectCase={handleSelectCase}
        onNavigateTab={setCurrentTab}
        onSwitchRole={handleSwitchRole}
        onLoadIncidentTrace={handleLoadIncidentTrace}
        isLoading={isLoading}
      />

      {/* Main Body with Sidebar & Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          findingsCount={findings.length}
          anomaliesCount={anomalies.length}
        />

        {/* Viewport Content */}
        <main className="flex-1 p-6 overflow-y-auto bg-zinc-950">
          {notification && (
            <div
              className={`mb-4 p-3 rounded-md text-xs font-medium flex items-center justify-between transition border ${
                notification.type === 'error'
                  ? 'bg-rose-950/40 border-rose-900/60 text-rose-300'
                  : 'bg-emerald-950/40 border-emerald-900/60 text-emerald-300'
              }`}
            >
              <span>{notification.message}</span>
              <button
                onClick={() => setNotification(null)}
                className="text-zinc-500 hover:text-zinc-300 ml-4 cursor-pointer text-sm"
              >
                &times;
              </button>
            </div>
          )}

          {currentTab === 'dashboard' && (
            <DashboardView
              currentCase={currentCase}
              sessions={sessions}
              findings={findings}
              anomalies={anomalies}
              onNavigateTab={setCurrentTab}
              onFilterFindings={handleFilterFindings}
              onRefreshData={loadCaseData}
            />
          )}

          {currentTab === 'scanner' && (
            <ActiveScannerView
              onInspectCase={async (newCaseId) => {
                await loadCaseData();
                setActiveCaseId(newCaseId);
                setCurrentTab('sessions');
              }}
              onRefreshCases={loadCaseData}
            />
          )}

          {currentTab === 'sensor' && (
            <SensorIngestView
              onInspectCase={async (newCaseId) => {
                await loadCaseData();
                setActiveCaseId(newCaseId);
                setCurrentTab('sessions');
              }}
            />
          )}

          {currentTab === 'upload' && (
            <CasesView
              cases={cases}
              activeCaseId={activeCaseId}
              onSelectCase={handleSelectCase}
              onDeleteCase={handleDeleteCase}
              onUploadFile={handleUploadFile}
              onLoadIncidentTrace={handleLoadIncidentTrace}
              isLoading={isLoading}
            />
          )}

          {currentTab === 'sessions' && (
            <SessionsView
              sessions={sessions}
              selectedSessionId={selectedSessionId}
              onSelectSession={setSelectedSessionId}
            />
          )}

          {currentTab === 'findings' && (
            <FindingsView
              findings={findings}
              initialSeverityFilter={severityFilter}
              onInspectSession={handleInspectSession}
            />
          )}

          {currentTab === 'certificates' && (
            <CertificatesView
              certificates={certificates}
              onInspectSession={handleInspectSession}
            />
          )}

          {currentTab === 'anomalies' && (
            <AnomaliesView
              anomalies={anomalies}
              onInspectSession={handleInspectSession}
            />
          )}

          {currentTab === 'ai' && (
            <AiRiskView
              riskAssessment={currentCase?.riskAssessment}
              sessions={sessions}
              findings={findings}
              onTriggerAiEvaluation={handleTriggerAiEvaluation}
              isLoading={isLoading}
            />
          )}

          {currentTab === 'reports' && <ReportsView currentCase={currentCase} />}

          {currentTab === 'audit' && <AuditLogView />}

          {currentTab === 'settings' && <SettingsView />}

          {currentTab === 'health' && <HealthView />}
        </main>
      </div>
    </div>
  );
}
