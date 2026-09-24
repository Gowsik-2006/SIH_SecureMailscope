import React, { useState } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  Wrench,
  FileSearch,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { Finding, FindingSeverity } from '../../../shared/types.ts';

interface FindingsViewProps {
  findings: Finding[];
  initialSeverityFilter?: string;
  onInspectSession?: (sessionId: string) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  initialSeverityFilter,
  onInspectSession,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>(initialSeverityFilter || 'ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
    return true;
  });

  return (
    <div className="space-y-4 select-none">
      {/* Filters Bar */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 rounded px-2.5 py-1.5 focus:outline-none font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical (CVSS &ge; 9.0)</option>
            <option value="HIGH">High (CVSS 7.0 - 8.9)</option>
            <option value="MEDIUM">Medium (CVSS 4.0 - 6.9)</option>
            <option value="LOW">Low (CVSS &lt; 4.0)</option>
          </select>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 rounded px-2.5 py-1.5 focus:outline-none font-mono"
          >
            <option value="ALL">All Categories</option>
            <option value="PROTOCOL">Protocol</option>
            <option value="CRYPTOGRAPHIC">Cryptographic</option>
            <option value="CERTIFICATE">Certificate</option>
            <option value="AUTHENTICATION">Authentication</option>
            <option value="INTEGRITY">Integrity</option>
          </select>
        </div>

        <div className="text-xs text-zinc-500 font-mono">
          Showing {filteredFindings.length} of {findings.length} finding(s)
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-2.5">
        {filteredFindings.map((f) => {
          const isExpanded = expandedFindingId === f.id;
          const isCritical = f.severity === 'CRITICAL';
          const isHigh = f.severity === 'HIGH';

          return (
            <div
              key={f.id}
              className={`bg-zinc-900/40 border rounded-lg overflow-hidden transition ${
                isCritical
                  ? 'border-rose-900/50'
                  : isHigh
                  ? 'border-amber-900/40'
                  : 'border-zinc-800/80'
              }`}
            >
              {/* Finding Summary Bar */}
              <div
                onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                className="p-3.5 flex items-center justify-between cursor-pointer hover:bg-zinc-850/40 transition text-xs"
              >
                <div className="flex items-center space-x-3">
                  <span
                    className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase border ${
                      isCritical
                        ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                        : isHigh
                        ? 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                        : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                    }`}
                  >
                    {f.severity}
                  </span>

                  <span className="font-mono text-[11px] text-zinc-500">
                    {f.ruleId}
                  </span>

                  <span className="font-medium text-zinc-200">
                    {f.title}
                  </span>

                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400">
                    {f.category}
                  </span>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="text-right font-mono">
                    <span className="text-zinc-500 text-[10px]">CVSS </span>
                    <span className="font-bold text-zinc-200">{f.cvssScore.toFixed(1)}</span>
                  </div>

                  {isExpanded ? (
                    <ChevronUp className="w-4 h-4 text-zinc-500" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-zinc-500" />
                  )}
                </div>
              </div>

              {/* Collapsible Deep Inspector */}
              {isExpanded && (
                <div className="p-4 border-t border-zinc-800/80 bg-zinc-950 space-y-4 text-xs font-sans">
                  {/* Description & Impact */}
                  <div>
                    <h4 className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider mb-1">
                      Threat Description & Vulnerability Impact
                    </h4>
                    <p className="text-zinc-300 leading-relaxed font-sans">{f.description}</p>
                    <p className="text-zinc-400 mt-1 italic font-sans">{f.impact}</p>
                  </div>

                  {/* Verifiable Forensic Evidence */}
                  <div>
                    <h4 className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider mb-1 flex items-center space-x-1.5">
                      <FileSearch className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Verifiable Wire Evidence</span>
                    </h4>
                    {f.evidence && f.evidence.length > 0 ? (
                      <div className="bg-zinc-900 border border-zinc-800 rounded p-3 font-mono text-[11px] space-y-1">
                        <div className="text-zinc-400">
                          <span className="text-zinc-500">Stream Reference: </span>
                          <span className="text-zinc-200">{f.evidence[0].streamKey}</span>
                        </div>
                        {f.evidence[0].frameNumber !== undefined && (
                          <div className="text-zinc-400">
                            <span className="text-zinc-500">Frame #: </span>
                            <span className="text-zinc-200">{f.evidence[0].frameNumber}</span>
                          </div>
                        )}
                        {f.evidence[0].byteOffset !== undefined && (
                          <div className="text-zinc-400">
                            <span className="text-zinc-500">Byte Range: </span>
                            <span className="text-zinc-200">
                              {f.evidence[0].byteOffset} - {f.evidence[0].byteOffset + (f.evidence[0].length || 0)}
                            </span>
                          </div>
                        )}
                        {(f.evidence[0].snippetAscii || f.evidence[0].snippetHex) && (
                          <div className="mt-2 pt-2 border-t border-zinc-850">
                            <span className="text-zinc-500 block mb-1">Wire Excerpt:</span>
                            <pre className="text-zinc-300 bg-zinc-950 p-2 rounded whitespace-pre-wrap overflow-x-auto text-[11px]">
                              {f.evidence[0].snippetAscii || f.evidence[0].snippetHex}
                            </pre>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-zinc-500 text-xs italic font-mono">
                        No packet slice attached.
                      </div>
                    )}
                  </div>

                  {/* Technical Remediation Plan */}
                  <div>
                    <h4 className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider mb-1 flex items-center space-x-1.5">
                      <Wrench className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Mitigation & Hardening Action Plan</span>
                    </h4>
                    <div className="bg-zinc-900/60 border border-zinc-800 rounded p-3 font-mono text-[11px] text-zinc-300 whitespace-pre-wrap">
                      {f.remediation}
                    </div>
                  </div>

                  {/* Actions Bar */}
                  {onInspectSession && f.evidence?.[0]?.streamKey && (
                    <div className="pt-2 flex justify-end">
                      <button
                        onClick={() => onInspectSession(f.evidence[0].streamKey)}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium transition cursor-pointer text-xs"
                      >
                        <span>Examine Stream in Session Forensics</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
