import React, { useState } from 'react';
import {
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Lock,
  Eye,
  FileCode,
  Wrench,
} from 'lucide-react';
import { RiskAssessment, SessionMetadata, Finding } from '../../../shared/types.ts';
import { EvidencePacketer } from '../../../server/ai/evidence-packeter.ts';

interface AiRiskViewProps {
  riskAssessment: RiskAssessment | undefined;
  sessions: SessionMetadata[];
  findings: Finding[];
  onTriggerAiEvaluation: () => void;
  isLoading: boolean;
}

export const AiRiskView: React.FC<AiRiskViewProps> = ({
  riskAssessment,
  sessions,
  findings,
  onTriggerAiEvaluation,
  isLoading,
}) => {
  const [showEvidencePacket, setShowEvidencePacket] = useState(false);

  // Generate real-time redacted packet to show in the inspector
  const redactedPacket = EvidencePacketer.createPacket(sessions, true);

  return (
    <div className="space-y-5 select-none">
      {/* Top Header & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div>
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-zinc-300" />
            <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
              Verifiable AI Cryptographic Risk Reasoning
            </h3>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 max-w-xl font-sans">
            Server-side data minimisation, strict PII/credential scrubbing,
            and an automated ground-truth claim checker to reject hallucinations.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowEvidencePacket(!showEvidencePacket)}
            className="px-3 py-1.5 rounded-md bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/70 text-xs font-medium cursor-pointer transition flex items-center space-x-1.5"
          >
            <Eye className="w-3.5 h-3.5 text-zinc-400" />
            <span>{showEvidencePacket ? 'Hide Redacted Packet' : 'Inspect Outbound Packet'}</span>
          </button>

          <button
            onClick={onTriggerAiEvaluation}
            disabled={isLoading}
            className="px-3.5 py-1.5 rounded-md bg-zinc-100 hover:bg-white text-zinc-950 text-xs font-medium cursor-pointer transition flex items-center space-x-1.5 disabled:opacity-50 shadow-xs"
          >
            {isLoading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5" />
            )}
            <span>Execute AI Reasoning</span>
          </button>
        </div>
      </div>

      {/* Outbound Evidence Packet Inspector (Data Minimisation View) */}
      {showEvidencePacket && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-zinc-800/80 pb-2">
            <div className="flex items-center space-x-2">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-semibold text-zinc-100">
                OUTBOUND REDACTED EVIDENCE PAYLOAD
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400">
                STRICT PII SANITIZED
              </span>
            </div>
            <span className="text-[10px] text-zinc-500">
              Only session metadata & cryptosuites sent to LLM
            </span>
          </div>

          <pre className="bg-zinc-950 p-3 rounded border border-zinc-800 text-zinc-300 text-[11px] overflow-x-auto max-h-72 whitespace-pre">
            {JSON.stringify(redactedPacket, null, 2)}
          </pre>
        </div>
      )}

      {/* Verification Guardrails Card */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-3">
        <h4 className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider">
          Forensic Verification Status
        </h4>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800/80 flex items-center space-x-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <div className="font-bold text-zinc-200">PII Redaction Engine</div>
              <div className="text-[10px] text-zinc-500">Pass: Emails & passwords scrubbed</div>
            </div>
          </div>

          <div className="p-3 rounded bg-zinc-950 border border-zinc-800/80 flex items-center space-x-3">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <div className="font-bold text-zinc-200">Ground-Truth Claim Checker</div>
              <div className="text-[10px] text-zinc-500">
                {riskAssessment?.aiClaimsChecked ? 'Pass: No hallucinations detected' : 'Automated check active'}
              </div>
            </div>
          </div>

          <div className="p-3 rounded bg-zinc-950 border border-zinc-800/80 flex items-center space-x-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <div className="font-bold text-zinc-200">Execution Mode</div>
              <div className="text-[10px] text-zinc-500">
                {riskAssessment?.isAiGenerated ? 'Gemini 3.8 Flash' : 'Deterministic Hybrid Engine'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* AI Reasoning & Remediation Output */}
      {riskAssessment ? (
        <div className="space-y-4">
          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-5 space-y-3 font-sans">
            <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
              <div>
                <h4 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
                  Synthesized Forensic Reasoning
                </h4>
                <p className="text-[11px] text-zinc-400 mt-0.5">
                  Automated risk categorization and threat analysis
                </p>
              </div>

              <div className="flex items-center space-x-2 font-mono">
                <span className="text-xs text-zinc-400">Score:</span>
                <span className="text-base font-bold text-zinc-100">{riskAssessment.overallScore}/100</span>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${
                    riskAssessment.riskLevel === 'CRITICAL'
                      ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                      : riskAssessment.riskLevel === 'HIGH'
                      ? 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                      : 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60'
                  }`}
                >
                  {riskAssessment.riskLevel}
                </span>
              </div>
            </div>

            <div className="text-xs text-zinc-300 leading-relaxed font-sans whitespace-pre-wrap">
              {riskAssessment.aiReasoning || riskAssessment.summary}
            </div>
          </div>

          {/* Remediation Plan */}
          {riskAssessment.remediationPlan && riskAssessment.remediationPlan.length > 0 && (
            <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-5 space-y-3 font-sans">
              <div className="flex items-center space-x-2 text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
                <Wrench className="w-3.5 h-3.5 text-zinc-400" />
                <span>Automated Remediation Roadmap</span>
              </div>

              <div className="space-y-2">
                {riskAssessment.remediationPlan.map((step, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded bg-zinc-950 border border-zinc-800/80 text-xs text-zinc-300 flex items-start space-x-3"
                  >
                    <span className="font-mono text-zinc-500 font-bold mt-0.5 text-[11px]">
                      {String(idx + 1).padStart(2, '0')}.
                    </span>
                    <span className="leading-relaxed font-sans">{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="p-8 text-center text-zinc-500 text-xs font-mono bg-zinc-900/40 border border-zinc-800 rounded-lg">
          No AI risk assessment generated yet. Click &quot;Execute AI Reasoning&quot; above to run analysis.
        </div>
      )}
    </div>
  );
};
