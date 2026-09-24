import React, { useState, useEffect } from 'react';
import { Sliders, CheckCircle2, XCircle, Shield, AlertTriangle } from 'lucide-react';
import { ApiClient } from '../../api/client.ts';
import { RuleDefinition } from '../../../server/engine/rules/rule-catalog.ts';

export const SettingsView: React.FC = () => {
  const [rules, setRules] = useState<RuleDefinition[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const loadRules = async () => {
    try {
      const data = await ApiClient.getRules();
      setRules(data);
    } catch (e: any) {
      console.error('Failed to load rules:', e);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleToggle = async (ruleId: string) => {
    try {
      const updated = await ApiClient.toggleRule(ruleId);
      setRules((prev) => prev.map((r) => (r.id === ruleId ? updated : r)));
      setMessage(`Rule ${ruleId} status updated.`);
      setTimeout(() => setMessage(null), 3000);
    } catch (e: any) {
      setMessage(`Failed to update rule: ${e.message}`);
    }
  };

  return (
    <div className="space-y-5 select-none">
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="flex items-center space-x-2 mb-1">
          <Sliders className="w-4 h-4 text-zinc-300" />
          <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
            Cryptographic & Protocol Detection Rule Catalog
          </h3>
        </div>
        <p className="text-[11px] text-zinc-400 font-sans">
          Configure active wire inspection rules, CVSS scoring baselines, and protocol compliance policies.
        </p>

        {message && (
          <div className="mt-3 p-2 rounded bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-300">
            {message}
          </div>
        )}
      </div>

      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-zinc-800/80 text-zinc-500 font-mono text-[10px] uppercase tracking-wider">
                <th className="py-2 px-3">Rule ID</th>
                <th className="py-2 px-3">Severity</th>
                <th className="py-2 px-3">Category</th>
                <th className="py-2 px-3">Rule Title</th>
                <th className="py-2 px-3">CVSS</th>
                <th className="py-2 px-3 text-right">Status / Toggle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/40 text-zinc-300">
              {rules.map((r) => (
                <tr key={r.id} className="hover:bg-zinc-800/30 transition text-xs">
                  <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">{r.id}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.2 rounded border uppercase ${
                        r.defaultSeverity === 'CRITICAL'
                          ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                          : r.defaultSeverity === 'HIGH'
                          ? 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                          : 'bg-zinc-800 text-zinc-400'
                      }`}
                    >
                      {r.defaultSeverity}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">{r.category}</td>
                  <td className="py-2.5 px-3 text-zinc-200">{r.name}</td>
                  <td className="py-2.5 px-3 font-mono text-zinc-300 font-bold tabular-nums">
                    {r.cvssBaseScore.toFixed(1)}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={() => handleToggle(r.id)}
                      className={`px-2.5 py-0.5 rounded text-[11px] font-mono transition cursor-pointer border ${
                        r.enabled
                          ? 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60 hover:bg-emerald-900/40'
                          : 'bg-zinc-800 text-zinc-500 border-zinc-700 hover:text-zinc-300'
                      }`}
                    >
                      {r.enabled ? 'ENABLED' : 'DISABLED'}
                    </button>
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
