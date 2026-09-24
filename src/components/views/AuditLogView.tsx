import React, { useState, useEffect } from 'react';
import {
  History,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Hash,
  CheckCircle,
} from 'lucide-react';
import { ApiClient } from '../../api/client.ts';
import { AuditRecord } from '../../../shared/types.ts';

export const AuditLogView: React.FC = () => {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [verification, setVerification] = useState<{ valid: boolean; message: string }>({
    valid: true,
    message: 'Loading...',
  });
  const [loading, setLoading] = useState(false);

  const loadAuditData = async () => {
    setLoading(true);
    try {
      const data = await ApiClient.getAudit();
      setRecords(data.records || []);
      setVerification(data.verification || { valid: true, message: 'Verified' });
    } catch (e: any) {
      console.error('Failed to load audit:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditData();
  }, []);

  const handleVerify = async () => {
    setLoading(true);
    try {
      const v = await ApiClient.verifyAudit();
      setVerification(v);
    } catch (e: any) {
      console.error('Failed to verify audit chain:', e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5 select-none">
      {/* Top Banner & Verification */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <History className="w-4 h-4 text-zinc-300" />
            <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
              Tamper-Evident Forensic Audit Trail
            </h3>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 font-sans">
            Cryptographic SHA-256 hash-chaining of all case creation, analysis, and rule actions.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div
            className={`px-3 py-1 rounded-md text-xs font-mono font-medium flex items-center space-x-1.5 border ${
              verification.valid
                ? 'bg-emerald-950/40 border-emerald-900/60 text-emerald-300'
                : 'bg-rose-950/40 border-rose-900/60 text-rose-300'
            }`}
          >
            {verification.valid ? (
              <CheckCircle className="w-3.5 h-3.5" />
            ) : (
              <AlertTriangle className="w-3.5 h-3.5" />
            )}
            <span>{verification.message}</span>
          </div>

          <button
            onClick={handleVerify}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/70 text-xs font-medium cursor-pointer transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Verify Cryptographic Chain</span>
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider mb-3">
          Immutable Audit Records ({records.length})
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-800/80 text-zinc-500 text-[10px] uppercase tracking-wider">
                <th className="py-2 px-3">#</th>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Actor / Role</th>
                <th className="py-2 px-3">Action</th>
                <th className="py-2 px-3">Target ID</th>
                <th className="py-2 px-3">Record Details</th>
                <th className="py-2 px-3">Current Hash (SHA-256)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/40 text-zinc-300">
              {records.map((r) => (
                <tr key={r.id} className="hover:bg-zinc-800/30 transition text-[11px]">
                  <td className="py-2.5 px-3 text-zinc-500">{r.sequence}</td>
                  <td className="py-2.5 px-3 text-zinc-400">
                    {new Date(r.timestamp).toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 3 } as any)}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="text-zinc-200">{r.actor}</span>
                    <span className="text-[10px] text-zinc-500 ml-1.5 font-bold">[{r.role}]</span>
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-[10px] font-mono text-zinc-300">
                      {r.action}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-zinc-500">{r.targetId || '-'}</td>
                  <td className="py-2.5 px-3 font-sans text-zinc-300 max-w-xs truncate" title={r.details}>
                    {r.details}
                  </td>
                  <td className="py-2.5 px-3 text-zinc-500 text-[10px]" title={`Current: ${r.currentHash}\nPrev: ${r.prevHash}`}>
                    {r.currentHash.substring(0, 14)}…
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
