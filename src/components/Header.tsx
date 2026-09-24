import React from 'react';
import {
  ShieldAlert,
  FileCode,
  FileText,
  User,
  Globe,
  FolderGit2,
  UploadCloud,
  CheckCircle2,
} from 'lucide-react';
import { CaseRecord, UserProfile } from '../../shared/types.ts';
import { NavTab } from './Sidebar.tsx';

interface HeaderProps {
  cases: CaseRecord[];
  activeCaseId: string | null;
  currentUser: UserProfile;
  onSelectCase: (id: string) => void;
  onNavigateTab: (tab: NavTab) => void;
  onSwitchRole: (role: 'ADMIN' | 'ANALYST' | 'AUDITOR' | 'VIEWER') => void;
  onLoadIncidentTrace: () => void;
  isLoading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  cases,
  activeCaseId,
  currentUser,
  onSelectCase,
  onNavigateTab,
  onSwitchRole,
  onLoadIncidentTrace,
  isLoading,
}) => {
  const activeCase = cases.find((c) => c.id === activeCaseId);

  return (
    <header className="h-14 border-b border-zinc-800/80 bg-zinc-950/90 backdrop-blur-md px-5 flex items-center justify-between sticky top-0 z-30 select-none">
      {/* Brand & Platform Identity */}
      <div className="flex items-center space-x-3">
        <div className="w-7 h-7 rounded-md bg-zinc-900 border border-zinc-700/70 flex items-center justify-center text-zinc-100">
          <ShieldAlert className="w-4 h-4 text-zinc-300" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-xs tracking-tight text-zinc-100">
              SecureMailScope
            </span>
            <span className="text-[10px] text-zinc-400 font-mono">
              /
            </span>
            <span className="text-[11px] text-zinc-400 font-medium">
              Email Protocol & TLS Security Forensics
            </span>
          </div>
        </div>

        {/* Active Incident Case Selector */}
        <div className="hidden lg:flex items-center ml-4 pl-4 border-l border-zinc-800/80">
          <FolderGit2 className="w-3.5 h-3.5 text-zinc-400 mr-2" />
          <select
            value={activeCaseId || ''}
            onChange={(e) => onSelectCase(e.target.value)}
            className="bg-zinc-900 border border-zinc-800 text-xs text-zinc-200 rounded-md px-2.5 py-1 focus:outline-none focus:border-zinc-600 font-sans"
          >
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.packetCount} pkts) - {c.summary?.riskLevel || 'ANALYZED'}
              </option>
            ))}
          </select>
          {activeCase && (
            <span
              className="ml-2 font-mono text-[10px] text-zinc-400 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800"
              title={`SHA256: ${activeCase.fileSha256}`}
            >
              SHA256: {activeCase.fileSha256.substring(0, 10)}…
            </span>
          )}
        </div>
      </div>

      {/* Action Controls & Navigation Shortcuts */}
      <div className="flex items-center space-x-2">
        {/* Live Network Audit Shortcut */}
        <button
          onClick={() => onNavigateTab('scanner')}
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:text-white hover:border-zinc-700 transition cursor-pointer"
          title="Audit Live Mail Server via Real TCP/TLS Connection"
        >
          <Globe className="w-3.5 h-3.5 text-zinc-300" />
          <span>Live Network Audit</span>
        </button>

        {/* Upload Capture Shortcut */}
        <button
          onClick={() => onNavigateTab('upload')}
          className="hidden sm:flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-700 transition cursor-pointer"
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span>Upload PCAP</span>
        </button>

        {/* Load Incident Trace */}
        <button
          onClick={onLoadIncidentTrace}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-zinc-100 hover:bg-white text-zinc-950 transition cursor-pointer disabled:opacity-50 shadow-xs"
          title="Load standard enterprise incident audit trace with multi-vector protocol traffic"
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-zinc-950" />
          <span>Load Incident Trace</span>
        </button>

        {/* Export Quick Links */}
        {activeCaseId && (
          <div className="hidden md:flex items-center space-x-1 border-l border-zinc-800/80 pl-2">
            <a
              href="/api/export/json"
              target="_blank"
              rel="noreferrer"
              className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 transition"
              title="Export JSON Telemetry Report"
            >
              <FileCode className="w-3.5 h-3.5" />
            </a>
            <a
              href="/api/export/html"
              target="_blank"
              rel="noreferrer"
              className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 transition"
              title="Export Formatted Security Report"
            >
              <FileText className="w-3.5 h-3.5" />
            </a>
          </div>
        )}

        {/* RBAC Role Selector */}
        <div className="flex items-center space-x-1.5 pl-2 border-l border-zinc-800/80">
          <User className="w-3.5 h-3.5 text-zinc-500" />
          <select
            value={currentUser.role}
            onChange={(e) =>
              onSwitchRole(e.target.value as 'ADMIN' | 'ANALYST' | 'AUDITOR' | 'VIEWER')
            }
            className="bg-zinc-900 border border-zinc-800 text-xs text-zinc-300 rounded px-2 py-0.5 focus:outline-none font-mono"
          >
            <option value="ADMIN">ADMIN</option>
            <option value="ANALYST">ANALYST</option>
            <option value="AUDITOR">AUDITOR</option>
            <option value="VIEWER">VIEWER</option>
          </select>
        </div>
      </div>
    </header>
  );
};
