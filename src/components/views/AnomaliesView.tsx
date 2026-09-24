import React from 'react';
import { Bug, Eye, Sparkles, AlertCircle } from 'lucide-react';
import { Anomaly } from '../../../shared/types.ts';

interface AnomaliesViewProps {
  anomalies: Anomaly[];
  onInspectSession?: (sessionId: string) => void;
}

export const AnomaliesView: React.FC<AnomaliesViewProps> = ({
  anomalies,
  onInspectSession,
}) => {
  return (
    <div className="space-y-5 select-none">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono flex items-center space-x-2">
            <Bug className="w-3.5 h-3.5 text-zinc-400" />
            <span>Behavioral Network Anomaly Detection</span>
          </h3>
          <p className="text-[11px] text-zinc-400 mt-0.5">
            Strict empirical separation of <strong>Observed Wire Fact</strong> versus{' '}
            <strong>Forensic Threat Interpretation</strong>.
          </p>
        </div>
        <span className="text-xs text-zinc-500 font-mono">
          {anomalies.length} anomaly event(s)
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3.5">
        {anomalies.map((anom) => {
          return (
            <div
              key={anom.id}
              className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-3"
            >
              <div className="flex items-center justify-between border-b border-zinc-800/80 pb-2.5">
                <div className="flex items-center space-x-2">
                  <span className="text-[10px] font-mono text-zinc-500">
                    [{anom.type}]
                  </span>
                  <h4 className="text-xs font-medium text-zinc-200">{anom.title}</h4>
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-[10px] font-mono text-zinc-400 px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800">
                    Stream: {anom.sessionId}
                  </span>
                  <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                    Score: {anom.anomalyScore}/100
                  </span>
                </div>
              </div>

              {/* Two columns: Observed Fact vs Interpreted Threat */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {/* Column 1: Factual Observation */}
                <div className="p-3 rounded bg-zinc-950 border border-zinc-800/80 space-y-1">
                  <div className="text-[10px] font-mono font-semibold text-zinc-400 uppercase tracking-wider flex items-center space-x-1.5">
                    <Eye className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Observed Wire Fact</span>
                  </div>
                  <p className="text-zinc-300 leading-relaxed font-sans">{anom.observed}</p>
                </div>

                {/* Column 2: Threat Interpretation */}
                <div className="p-3 rounded bg-zinc-950 border border-zinc-800/80 space-y-1">
                  <div className="text-[10px] font-mono font-semibold text-zinc-400 uppercase tracking-wider flex items-center space-x-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Forensic Threat Interpretation</span>
                  </div>
                  <p className="text-zinc-300 leading-relaxed font-sans">{anom.interpreted}</p>
                </div>
              </div>

              {/* Wire Evidence Offset */}
              {anom.evidenceRef && (
                <div className="flex items-center justify-between pt-1 text-[11px] font-mono text-zinc-500">
                  <div>
                    Evidence Frame #{anom.evidenceRef.frameNumber || 'N/A'} (Byte Offset:{' '}
                    {anom.evidenceRef.byteOffset || 0})
                  </div>

                  {onInspectSession && (
                    <button
                      onClick={() => onInspectSession(anom.sessionId)}
                      className="text-zinc-400 hover:text-zinc-200 transition cursor-pointer"
                    >
                      Inspect Stream &rarr;
                    </button>
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
