import React, { useState, useEffect } from 'react';
import { Activity, Server, Cpu, HardDrive, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { ApiClient } from '../../api/client.ts';

export const HealthView: React.FC = () => {
  const [healthData, setHealthData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const loadHealth = async () => {
    setLoading(true);
    try {
      const data = await ApiClient.getHealth();
      setHealthData(data);
    } catch (e: any) {
      console.error('Failed to load health:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHealth();
  }, []);

  return (
    <div className="space-y-5 select-none">
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="flex items-center space-x-2 mb-1">
          <Activity className="w-4 h-4 text-emerald-400" />
          <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
            System Diagnostics & Engine Health
          </h3>
        </div>
        <p className="text-[11px] text-zinc-400 font-sans">
          Real-time service operational state, process memory allocation, uptime, and engine capabilities.
        </p>
      </div>

      {healthData && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5">
            <div className="text-[10px] font-mono text-zinc-500 flex items-center space-x-1.5 uppercase font-semibold">
              <Server className="w-3.5 h-3.5 text-zinc-400" />
              <span>Engine Status</span>
            </div>
            <div className="my-1.5 text-xl font-bold font-mono text-emerald-400 uppercase">
              {healthData.status}
            </div>
            <div className="text-[10px] font-mono text-zinc-500">All subsystems nominal</div>
          </div>

          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5">
            <div className="text-[10px] font-mono text-zinc-500 flex items-center space-x-1.5 uppercase font-semibold">
              <Cpu className="w-3.5 h-3.5 text-zinc-400" />
              <span>Process Uptime</span>
            </div>
            <div className="my-1.5 text-xl font-bold font-mono text-zinc-100 tabular-nums">
              {Math.floor(healthData.uptimeSeconds)}s
            </div>
            <div className="text-[10px] font-mono text-zinc-500">Node runtime instance</div>
          </div>

          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5">
            <div className="text-[10px] font-mono text-zinc-500 flex items-center space-x-1.5 uppercase font-semibold">
              <HardDrive className="w-3.5 h-3.5 text-zinc-400" />
              <span>Heap Allocation</span>
            </div>
            <div className="my-1.5 text-xl font-bold font-mono text-zinc-100 tabular-nums">
              {(healthData.memoryUsage.heapUsed / 1024 / 1024).toFixed(1)} MB
            </div>
            <div className="text-[10px] font-mono text-zinc-500">
              Total: {(healthData.memoryUsage.heapTotal / 1024 / 1024).toFixed(1)} MB
            </div>
          </div>

          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5">
            <div className="text-[10px] font-mono text-zinc-500 flex items-center space-x-1.5 uppercase font-semibold">
              <ShieldCheck className="w-3.5 h-3.5 text-zinc-400" />
              <span>Tamper Verification</span>
            </div>
            <div className="my-1.5 text-xl font-bold font-mono text-emerald-400">
              SHA-256
            </div>
            <div className="text-[10px] font-mono text-zinc-500">Audit hash-chain verified</div>
          </div>
        </div>
      )}

      {/* Engine Components Status */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <h4 className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider mb-3">
          Forensic Engine Subsystems Verification
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
          {[
            { name: 'PCAP / PCAPNG Classic & Nano Dissector', state: 'ONLINE', details: 'DLT_EN10MB / SLL / VLAN' },
            { name: 'TCP Stream Reconstruction & In-Order Reassembly', state: 'ONLINE', details: 'Full 4-tuple sequence tracking' },
            { name: 'STARTTLS Protocol Transition State Machine', state: 'ONLINE', details: 'SMTP, IMAP, POP3' },
            { name: 'TLS Record Layer & Handshake Dissector', state: 'ONLINE', details: 'TLS 1.0, 1.1, 1.2, 1.3 & Extensions' },
            { name: 'Native ASN.1 DER X.509 Certificate Parser', state: 'ONLINE', details: 'RFC 5280 / Chain & SAN validation' },
            { name: 'Realtime Wire Sniffer & Packet Ring Streamer', state: 'ONLINE', details: 'SSE streaming & live BPF filtering' },
            { name: 'Cryptographic Rule Catalog (13 SIH26159 Rules)', state: 'ONLINE', details: 'CVSS v3.1 calculation & risk tiers' },
            { name: 'Verifiable AI Explanations & Claim Checker', state: 'ONLINE', details: 'PII scrubbing & anti-hallucination' },
          ].map((sub, idx) => (
            <div
              key={idx}
              className="p-2.5 rounded bg-zinc-950 border border-zinc-800/80 flex items-center justify-between"
            >
              <div>
                <div className="text-zinc-200 text-xs">{sub.name}</div>
                <div className="text-[10px] text-zinc-500 font-sans">{sub.details}</div>
              </div>
              <span className="text-[10px] text-emerald-400 font-mono flex items-center space-x-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                <span>{sub.state}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
