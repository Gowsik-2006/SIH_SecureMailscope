import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Lock,
  Unlock,
  KeyRound,
  ArrowRight,
  TrendingUp,
  Activity,
  RefreshCw,
  Clock,
} from 'lucide-react';
import { CaseRecord, SessionMetadata, Finding, Anomaly } from '../../../shared/types.ts';
import { NavTab } from '../Sidebar.tsx';

interface DashboardViewProps {
  currentCase: CaseRecord | null;
  sessions: SessionMetadata[];
  findings: Finding[];
  anomalies: Anomaly[];
  onNavigateTab: (tab: NavTab) => void;
  onFilterFindings: (severity: string) => void;
  onRefreshData?: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  currentCase,
  sessions,
  findings,
  anomalies,
  onNavigateTab,
  onFilterFindings,
  onRefreshData,
}) => {
  const [liveAutoRefresh, setLiveAutoRefresh] = useState(false);

  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    if (liveAutoRefresh && onRefreshData) {
      interval = setInterval(() => {
        onRefreshData();
      }, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [liveAutoRefresh, onRefreshData]);

  if (!currentCase) {
    return (
      <div className="p-12 text-center text-zinc-500 font-mono text-xs border border-dashed border-zinc-800 rounded-lg">
        No active forensic capture loaded. Please upload a PCAP or initiate the Live Network Sniffer.
      </div>
    );
  }

  const summary = currentCase.summary || {
    totalSessions: sessions.length,
    protocolCounts: { SMTP: 0, IMAP: 0, POP3: 0, UNKNOWN: 0 },
    verdictCounts: {
      clean_starttls: 0,
      ack_without_tls: 0,
      missing_starttls_in_caps: 0,
      rejected_starttls: 0,
      fallback_to_plaintext: 0,
      encrypted_implicit_tls: 0,
      plaintext_unencrypted: 0,
    },
    severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 },
    totalFindings: findings.length,
    totalAnomalies: anomalies.length,
    criticalSessions: sessions.filter((s) => s.findings.some((f) => f.severity === 'CRITICAL')).length,
    highestCvss: findings.reduce((max, f) => Math.max(max, f.cvssScore), 0),
    riskScore: currentCase.riskAssessment?.overallScore || 0,
    riskLevel: currentCase.riskAssessment?.riskLevel || 'CLEAN',
  };

  const strippedCount = sessions.filter((s) => s.starttlsStripped).length;
  const credsCount = sessions.filter((s) => !!s.credentialsExposed).length;
  const deprecatedTlsCount = sessions.filter(
    (s) => s.tlsVersion === 'TLSv1.0' || s.tlsVersion === 'TLSv1.1' || s.tlsVersion === 'SSLv3.0'
  ).length;

  return (
    <div className="space-y-5 select-none">
      {/* Top Threat Banner if Critical */}
      {summary.severityCounts.CRITICAL > 0 && (
        <div className="bg-rose-950/20 border border-rose-900/60 rounded-lg p-3.5 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-md bg-rose-950/80 border border-rose-800/80 flex items-center justify-center text-rose-300">
              <ShieldAlert className="w-4 h-4 animate-pulse text-rose-400" />
            </div>
            <div>
              <div className="text-xs font-semibold text-rose-200 uppercase tracking-wider font-mono">
                Critical Cryptographic & Stripping Threats Detected
              </div>
              <div className="text-[11px] text-zinc-400 font-sans">
                Identified {summary.severityCounts.CRITICAL} Critical vulnerability event(s) across{' '}
                {summary.criticalSessions} stream(s). Immediate protocol containment recommended.
              </div>
            </div>
          </div>
          <button
            onClick={() => {
              onFilterFindings('CRITICAL');
              onNavigateTab('findings');
            }}
            className="flex items-center space-x-1 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-md text-xs font-medium cursor-pointer transition shadow-xs"
          >
            <span>Review Threats</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Header bar with Live Auto-Refresh */}
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center space-x-2">
          <h2 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
            Forensic Telemetry Overview
          </h2>
          <span className="text-[10px] text-zinc-500 font-mono">
            Case: {currentCase.name}
          </span>
        </div>

        <button
          onClick={() => setLiveAutoRefresh(!liveAutoRefresh)}
          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-mono border transition cursor-pointer ${
            liveAutoRefresh
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
              : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <RefreshCw className={`w-3 h-3 ${liveAutoRefresh ? 'animate-spin' : ''}`} />
          <span>Auto-Refresh (3s): {liveAutoRefresh ? 'ON' : 'OFF'}</span>
        </button>
      </div>

      {/* Primary KPI Grid with Click-Through Drill-Down */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {/* Risk Score */}
        <div
          onClick={() => onNavigateTab('ai')}
          className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 hover:border-zinc-700 transition cursor-pointer"
        >
          <div className="flex items-center justify-between text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Risk Score</span>
            <TrendingUp className="w-3.5 h-3.5 text-zinc-500" />
          </div>
          <div className="mt-1 flex items-baseline space-x-1.5">
            <span
              className={`text-2xl font-bold font-mono tabular-nums ${
                summary.riskScore >= 70
                  ? 'text-rose-400'
                  : summary.riskScore >= 40
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {summary.riskScore}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono">/ 100</span>
          </div>
          <div className="text-[10px] text-zinc-400 font-mono mt-0.5 uppercase">
            Tier: {summary.riskLevel}
          </div>
        </div>

        {/* Sessions Analyzed */}
        <div
          onClick={() => onNavigateTab('sessions')}
          className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 hover:border-zinc-700 transition cursor-pointer"
        >
          <div className="flex items-center justify-between text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Streams Inspected</span>
            <Activity className="w-3.5 h-3.5 text-zinc-500" />
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-zinc-100 tabular-nums">
            {summary.totalSessions}
          </div>
          <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
            SMTP: {summary.protocolCounts.SMTP || 0} | IMAP: {summary.protocolCounts.IMAP || 0}
          </div>
        </div>

        {/* STARTTLS Stripped Attempts */}
        <div
          onClick={() => onNavigateTab('sessions')}
          className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 hover:border-zinc-700 transition cursor-pointer"
        >
          <div className="flex items-center justify-between text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Stripped STARTTLS</span>
            <Unlock className="w-3.5 h-3.5 text-zinc-500" />
          </div>
          <div
            className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
              strippedCount > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {strippedCount}
          </div>
          <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
            {strippedCount > 0 ? 'MITM Injection Active' : 'No Stripping'}
          </div>
        </div>

        {/* Deprecated TLS */}
        <div
          onClick={() => {
            onFilterFindings('HIGH');
            onNavigateTab('findings');
          }}
          className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 hover:border-zinc-700 transition cursor-pointer"
        >
          <div className="flex items-center justify-between text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Deprecated TLS</span>
            <AlertTriangle className="w-3.5 h-3.5 text-zinc-500" />
          </div>
          <div
            className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
              deprecatedTlsCount > 0 ? 'text-amber-400' : 'text-zinc-300'
            }`}
          >
            {deprecatedTlsCount}
          </div>
          <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
            SSL 3.0 / TLS 1.0 / 1.1
          </div>
        </div>

        {/* Credentials Exposed */}
        <div
          onClick={() => {
            onFilterFindings('CRITICAL');
            onNavigateTab('findings');
          }}
          className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 hover:border-zinc-700 transition cursor-pointer"
        >
          <div className="flex items-center justify-between text-zinc-500 text-[10px] font-mono uppercase tracking-wider">
            <span>Plaintext Auth</span>
            <KeyRound className="w-3.5 h-3.5 text-zinc-500" />
          </div>
          <div
            className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
              credsCount > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {credsCount}
          </div>
          <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
            {credsCount > 0 ? 'Credential Interception' : 'Encrypted Auth'}
          </div>
        </div>
      </div>

      {/* Protocol Distribution & STARTTLS Verdict Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* STARTTLS Verdict Breakdown */}
        <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
          <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono mb-3">
            STARTTLS Negotiation Verdicts
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between py-1 border-b border-zinc-800/50">
              <span className="flex items-center space-x-2 text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>Clean STARTTLS Negotiation</span>
              </span>
              <span className="font-mono text-zinc-200 tabular-nums">
                {summary.verdictCounts.clean_starttls}
              </span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-zinc-800/50">
              <span className="flex items-center space-x-2 text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>Injected ACK Without TLS (Stripped)</span>
              </span>
              <span className="font-mono text-rose-400 tabular-nums">
                {summary.verdictCounts.ack_without_tls}
              </span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-zinc-800/50">
              <span className="flex items-center space-x-2 text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                <span>Missing STARTTLS in Capabilities</span>
              </span>
              <span className="font-mono text-amber-400 tabular-nums">
                {summary.verdictCounts.missing_starttls_in_caps}
              </span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-zinc-800/50">
              <span className="flex items-center space-x-2 text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-purple-500"></span>
                <span>Implicit TLS Stream (SMTPS / IMAPS)</span>
              </span>
              <span className="font-mono text-purple-400 tabular-nums">
                {summary.verdictCounts.encrypted_implicit_tls}
              </span>
            </div>

            <div className="flex items-center justify-between py-1">
              <span className="flex items-center space-x-2 text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-zinc-600"></span>
                <span>Plaintext Unencrypted Stream</span>
              </span>
              <span className="font-mono text-zinc-400 tabular-nums">
                {summary.verdictCounts.plaintext_unencrypted}
              </span>
            </div>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
          <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono mb-3">
            Threat Severity Catalog
          </h3>
          <div className="space-y-2 text-xs">
            <div
              onClick={() => {
                onFilterFindings('CRITICAL');
                onNavigateTab('findings');
              }}
              className="flex items-center justify-between py-1 border-b border-zinc-800/50 cursor-pointer hover:text-white"
            >
              <span className="flex items-center space-x-2 text-rose-300">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>Critical Severity Vulnerabilities</span>
              </span>
              <span className="font-mono text-rose-400 font-bold tabular-nums">
                {summary.severityCounts.CRITICAL}
              </span>
            </div>

            <div
              onClick={() => {
                onFilterFindings('HIGH');
                onNavigateTab('findings');
              }}
              className="flex items-center justify-between py-1 border-b border-zinc-800/50 cursor-pointer hover:text-white"
            >
              <span className="flex items-center space-x-2 text-amber-300">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                <span>High Severity Vulnerabilities</span>
              </span>
              <span className="font-mono text-amber-400 tabular-nums">
                {summary.severityCounts.HIGH}
              </span>
            </div>

            <div
              onClick={() => {
                onFilterFindings('MEDIUM');
                onNavigateTab('findings');
              }}
              className="flex items-center justify-between py-1 border-b border-zinc-800/50 cursor-pointer hover:text-white"
            >
              <span className="flex items-center space-x-2 text-yellow-300">
                <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
                <span>Medium Severity Issues</span>
              </span>
              <span className="font-mono text-yellow-400 tabular-nums">
                {summary.severityCounts.MEDIUM}
              </span>
            </div>

            <div
              onClick={() => {
                onFilterFindings('LOW');
                onNavigateTab('findings');
              }}
              className="flex items-center justify-between py-1 border-b border-zinc-800/50 cursor-pointer hover:text-white"
            >
              <span className="flex items-center space-x-2 text-zinc-300">
                <span className="w-2 h-2 rounded-full bg-zinc-500"></span>
                <span>Low Severity Findings</span>
              </span>
              <span className="font-mono text-zinc-400 tabular-nums">
                {summary.severityCounts.LOW}
              </span>
            </div>

            <div className="flex items-center justify-between py-1">
              <span className="flex items-center space-x-2 text-zinc-400">
                <span className="w-2 h-2 rounded-full bg-zinc-700"></span>
                <span>Informational Diagnostics</span>
              </span>
              <span className="font-mono text-zinc-500 tabular-nums">
                {summary.severityCounts.INFORMATIONAL}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* High-Priority Active Findings Table */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
            Active Cryptographic & Protocol Threat Findings
          </h3>
          <button
            onClick={() => onNavigateTab('findings')}
            className="text-[11px] text-zinc-400 hover:text-zinc-200 font-mono flex items-center space-x-1"
          >
            <span>View All ({findings.length})</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-zinc-800/80 text-zinc-500 font-mono text-[10px] uppercase tracking-wider">
                <th className="py-2 px-3">Rule ID</th>
                <th className="py-2 px-3">Severity</th>
                <th className="py-2 px-3">Category</th>
                <th className="py-2 px-3">Vulnerability Title</th>
                <th className="py-2 px-3">Stream Ref</th>
                <th className="py-2 px-3 text-right">CVSS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/40 text-zinc-300">
              {findings.slice(0, 5).map((f) => (
                <tr
                  key={f.id}
                  onClick={() => onNavigateTab('findings')}
                  className="hover:bg-zinc-800/30 transition cursor-pointer"
                >
                  <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">{f.ruleId}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded border uppercase ${
                        f.severity === 'CRITICAL'
                          ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                          : f.severity === 'HIGH'
                          ? 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                          : f.severity === 'MEDIUM'
                          ? 'bg-yellow-950/40 text-yellow-300 border-yellow-900/60'
                          : 'bg-zinc-800 text-zinc-400'
                      }`}
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">{f.category}</td>
                  <td className="py-2.5 px-3 font-medium text-zinc-200">{f.title}</td>
                  <td className="py-2.5 px-3 font-mono text-[10px] text-zinc-500">
                    {f.evidence?.[0]?.streamKey ? f.evidence[0].streamKey.substring(0, 10) + '…' : 'General'}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-right font-bold text-zinc-200 tabular-nums">
                    {f.cvssScore.toFixed(1)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
