import React from 'react';
import {
  FileCheck2,
  Download,
  FileCode,
  FileText,
  Printer,
  ExternalLink,
  Shield,
  Layers,
} from 'lucide-react';
import { CaseRecord } from '../../../shared/types.ts';

interface ReportsViewProps {
  currentCase: CaseRecord | null;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ currentCase }) => {
  if (!currentCase) {
    return (
      <div className="p-8 text-center bg-zinc-900/40 border border-zinc-800 rounded-lg text-zinc-500 font-mono text-xs">
        No case selected. Please upload or select a case to view reports.
      </div>
    );
  }

  const sections = [
    { num: '01', title: 'Executive Summary & Forensic Context', desc: 'Case metadata, risk posture, and analytic verdict.' },
    { num: '02', title: 'Cryptographic Posture & Risk Scores', desc: 'Composite scoring, CVSS matrix, and stream statistics.' },
    { num: '03', title: 'Threat & Finding Matrix', desc: 'Detailed table of findings by severity, rule ID, and category.' },
    { num: '04', title: 'Reconstructed Email Streams Inventory', desc: 'Per-stream endpoints, duration, byte counts, and verdicts.' },
    { num: '05', title: 'Protocol State & STARTTLS Verdict Breakdown', desc: 'STARTTLS state machine transitions and downgrade analysis.' },
    { num: '06', title: 'TLS Handshake & Cipher Suite Registry Details', desc: 'Key exchange, PFS status, cipher encryption, and MAC.' },
    { num: '07', title: 'X.509 Certificate Intelligence & Chain Validation', desc: 'Subject, issuer, validity range, key length, and signatures.' },
    { num: '08', title: 'Cleartext Credential & Data Exposure Analysis', desc: 'Captured cleartext AUTH credentials and protocol leaks.' },
    { num: '09', title: 'Behavioral Anomaly Log (Observed vs Interpreted)', desc: 'Factual wire observations separated from threat inferences.' },
    { num: '10', title: 'MITRE ATT&CK Framework Mapping', desc: 'Adversary technique mappings (T1557.002, T1552, T1588).' },
    { num: '11', title: 'AI Risk Reasoning & Ground-Truth Verification', desc: 'Traceable AI narrative and claim verification guardrails.' },
    { num: '12', title: 'Remediation Action Plan & Defense Matrix', desc: 'Prioritized technical mitigation actions (MTA-STS, DANE).' },
    { num: '13', title: 'Cryptographic Audit Trail & Chain Verification', desc: 'SHA-256 tamper-evident verification of all forensic events.' },
  ];

  return (
    <div className="space-y-5 select-none">
      {/* Top Banner & Export Actions */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <FileCheck2 className="w-4 h-4 text-zinc-300" />
            <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
              Forensic Report Engine (13 Sections)
            </h3>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 font-sans">
            Programmatically verified multi-format reporting for Case: <strong>{currentCase.name}</strong>
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <a
            href="/api/export/json"
            target="_blank"
            rel="noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/70 text-xs font-medium transition"
          >
            <FileCode className="w-3.5 h-3.5 text-zinc-400" />
            <span>Download JSON</span>
          </a>

          <a
            href="/api/export/html"
            target="_blank"
            rel="noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/70 text-xs font-medium transition"
          >
            <ExternalLink className="w-3.5 h-3.5 text-zinc-400" />
            <span>Open HTML Report</span>
          </a>

          <a
            href="/api/export/pdf"
            target="_blank"
            rel="noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-zinc-100 hover:bg-white text-zinc-950 text-xs font-medium transition shadow-xs"
          >
            <Printer className="w-3.5 h-3.5 text-zinc-900" />
            <span>Export PDF</span>
          </a>
        </div>
      </div>

      {/* Sections Grid Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {sections.map((s) => (
          <div
            key={s.num}
            className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5 space-y-1.5"
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-500 font-bold">
                SECTION {s.num}
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            </div>
            <h4 className="text-xs font-medium text-zinc-200">{s.title}</h4>
            <p className="text-[11px] text-zinc-400 font-sans leading-relaxed">{s.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
};
