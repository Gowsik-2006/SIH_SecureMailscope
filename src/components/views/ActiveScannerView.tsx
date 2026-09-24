import React, { useState } from 'react';
import {
  Globe,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Terminal,
  Server,
  Lock,
  ExternalLink,
  RefreshCw,
  Award,
  AlertTriangle,
  CheckCircle2,
  FileSearch,
} from 'lucide-react';
import { ApiClient } from '../../api/client.ts';
import { ActiveScanRequest, ActiveScanResult } from '../../../shared/types.ts';

interface ActiveScannerViewProps {
  onInspectCase?: (caseId: string) => void;
  onRefreshCases?: () => void;
}

export const ActiveScannerView: React.FC<ActiveScannerViewProps> = ({
  onInspectCase,
  onRefreshCases,
}) => {
  const [target, setTarget] = useState<string>('smtp.gmail.com');
  const [port, setPort] = useState<number>(587);
  const [protocol, setProtocol] = useState<'SMTP' | 'IMAP' | 'POP3' | 'AUTO'>('SMTP');
  const [checkMtaSts, setCheckMtaSts] = useState<boolean>(true);
  const [checkDane, setCheckDane] = useState<boolean>(true);

  const [scanning, setScanning] = useState<boolean>(false);
  const [result, setResult] = useState<ActiveScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (overrideTarget?: string, overridePort?: number) => {
    const scanTarget = overrideTarget || target;
    const scanPort = overridePort || port;

    if (!scanTarget.trim()) {
      setError('Please specify a mail server hostname, domain, or IP address.');
      return;
    }

    setScanning(true);
    setError(null);

    try {
      const res = await ApiClient.scanMailServer({
        target: scanTarget,
        port: scanPort,
        protocol,
        checkMtaSts,
        checkDane,
      });
      setResult(res);
      if (onRefreshCases) onRefreshCases();
    } catch (err: any) {
      setError(err.message || 'Failed to complete active network scan.');
    } finally {
      setScanning(false);
    }
  };

  const setPreset = (presetTarget: string, presetPort: number, proto: 'SMTP' | 'IMAP' | 'POP3') => {
    setTarget(presetTarget);
    setPort(presetPort);
    setProtocol(proto);
    handleScan(presetTarget, presetPort);
  };

  return (
    <div className="space-y-5 select-none font-sans">
      {/* Header & Description */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Globe className="w-4 h-4 text-zinc-300" />
            <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
              Live Network Audit & STARTTLS Scanner
            </h3>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
            Real Internet Socket I/O
          </span>
        </div>
        <p className="text-[11px] text-zinc-400 mt-1 max-w-3xl">
          Connects via live TCP/TLS sockets to any mail server, domain, or MX record. 
          Audits real-world STARTTLS negotiation, peer X.509 certificate chains, cipher suites, 
          RFC 8461 MTA-STS policies, and records the raw bytes into a verifiable forensic PCAP.
        </p>
      </div>

      {/* Target Input & Quick Presets */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-3.5">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-6 space-y-1">
            <label className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">
              Target Mail Server or Domain (FQDN / IP / Email Domain)
            </label>
            <div className="relative">
              <Server className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. smtp.gmail.com, outlook.office365.com, or enterprise.org"
                className="w-full bg-zinc-950 border border-zinc-800 text-xs text-zinc-200 rounded pl-8.5 pr-3 py-1.5 focus:outline-none focus:border-zinc-600 font-mono"
              />
            </div>
          </div>

          <div className="md:col-span-2 space-y-1">
            <label className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">
              Port
            </label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              className="w-full bg-zinc-950 border border-zinc-800 text-xs text-zinc-200 rounded px-2.5 py-1.5 focus:outline-none focus:border-zinc-600 font-mono"
            />
          </div>

          <div className="md:col-span-2 space-y-1">
            <label className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">
              Protocol
            </label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value as any)}
              className="w-full bg-zinc-950 border border-zinc-800 text-xs text-zinc-200 rounded px-2 py-1.5 focus:outline-none font-mono"
            >
              <option value="SMTP">SMTP (25/587)</option>
              <option value="IMAP">IMAP (143/993)</option>
              <option value="POP3">POP3 (110/995)</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <button
              onClick={() => handleScan()}
              disabled={scanning}
              className="w-full py-1.5 rounded-md bg-zinc-100 hover:bg-white text-zinc-950 text-xs font-semibold cursor-pointer transition flex items-center justify-center space-x-1.5 disabled:opacity-50 shadow-xs"
            >
              {scanning ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Zap className="w-3.5 h-3.5 text-zinc-950" />
              )}
              <span>{scanning ? 'Scanning...' : 'Audit Target'}</span>
            </button>
          </div>
        </div>

        {/* Options & Quick Presets */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-zinc-800/80 text-xs">
          <div className="flex items-center space-x-4">
            <label className="flex items-center space-x-1.5 cursor-pointer text-zinc-400 hover:text-zinc-200 text-[11px]">
              <input
                type="checkbox"
                checked={checkMtaSts}
                onChange={(e) => setCheckMtaSts(e.target.checked)}
                className="rounded border-zinc-700 bg-zinc-950 text-zinc-200"
              />
              <span>Verify RFC 8461 MTA-STS</span>
            </label>

            <label className="flex items-center space-x-1.5 cursor-pointer text-zinc-400 hover:text-zinc-200 text-[11px]">
              <input
                type="checkbox"
                checked={checkDane}
                onChange={(e) => setCheckDane(e.target.checked)}
                className="rounded border-zinc-700 bg-zinc-950 text-zinc-200"
              />
              <span>Verify RFC 7672 DANE TLSA</span>
            </label>
          </div>

          {/* Quick preset links */}
          <div className="flex items-center space-x-2 text-[10px] font-mono">
            <span className="text-zinc-500">Presets:</span>
            <button
              onClick={() => setPreset('smtp.gmail.com', 587, 'SMTP')}
              className="text-zinc-400 hover:text-zinc-200 underline cursor-pointer"
            >
              Gmail (587)
            </button>
            <span className="text-zinc-700">&bull;</span>
            <button
              onClick={() => setPreset('outlook.office365.com', 587, 'SMTP')}
              className="text-zinc-400 hover:text-zinc-200 underline cursor-pointer"
            >
              Microsoft 365 (587)
            </button>
            <span className="text-zinc-700">&bull;</span>
            <button
              onClick={() => setPreset('smtp.mail.yahoo.com', 587, 'SMTP')}
              className="text-zinc-400 hover:text-zinc-200 underline cursor-pointer"
            >
              Yahoo (587)
            </button>
            <span className="text-zinc-700">&bull;</span>
            <button
              onClick={() => setPreset('imap.gmail.com', 993, 'IMAP')}
              className="text-zinc-400 hover:text-zinc-200 underline cursor-pointer"
            >
              Gmail IMAP (993)
            </button>
          </div>
        </div>

        {error && (
          <div className="p-2.5 rounded bg-rose-950/30 border border-rose-900/50 text-xs text-rose-300 flex items-center space-x-2">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Scan Results Inspector */}
      {result && (
        <div className="space-y-4">
          {/* Overview Banner */}
          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-sm font-bold text-zinc-100">
                  {result.targetHost}:{result.port}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-950 text-zinc-400 border border-zinc-800">
                  {result.resolvedIp}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                  {result.protocol}
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 mt-1 font-mono">
                Audit completed in {result.durationMs}ms &bull; Scan ID: {result.scanId}
              </p>
            </div>

            <div className="flex items-center space-x-3">
              <div className="text-right">
                <div className="text-[10px] font-mono text-zinc-500 uppercase">Risk Evaluation</div>
                <div className="flex items-center space-x-1.5">
                  <span className="text-lg font-bold font-mono text-zinc-100">{result.riskScore}/100</span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.2 rounded border uppercase ${
                      result.riskScore >= 70
                        ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                        : result.riskScore >= 40
                        ? 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                        : 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60'
                    }`}
                  >
                    {result.riskScore >= 70 ? 'CRITICAL RISK' : result.riskScore >= 40 ? 'MODERATE RISK' : 'SECURE'}
                  </span>
                </div>
              </div>

              {result.caseId && onInspectCase && (
                <button
                  onClick={() => onInspectCase(result.caseId!)}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs font-medium transition cursor-pointer"
                >
                  <FileSearch className="w-3.5 h-3.5 text-zinc-300" />
                  <span>Inspect Reconstructed PCAP</span>
                  <ExternalLink className="w-3 h-3 text-zinc-400" />
                </button>
              )}
            </div>
          </div>

          {/* Forensic Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* STARTTLS Posture */}
            <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-semibold uppercase text-zinc-400">
                  STARTTLS Negotiation
                </span>
                {result.starttlsNegotiated ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                )}
              </div>
              <div className="text-xs">
                <span className="text-zinc-500 font-mono">Advertised in EHLO: </span>
                <span className={result.starttlsSupported ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                  {result.starttlsSupported ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="text-xs">
                <span className="text-zinc-500 font-mono">Negotiation State: </span>
                <span className={result.starttlsNegotiated ? 'text-emerald-300 font-bold' : 'text-rose-400 font-bold'}>
                  {result.starttlsNegotiated ? 'CLEAN UPGRADE' : 'FAILED / STRIPPED'}
                </span>
              </div>
            </div>

            {/* Negotiated TLS & Cipher */}
            <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-semibold uppercase text-zinc-400">
                  Cryptographic Suite
                </span>
                <Lock className="w-4 h-4 text-zinc-300" />
              </div>
              <div className="text-xs">
                <span className="text-zinc-500 font-mono">TLS Protocol: </span>
                <span className="text-zinc-200 font-mono font-bold">
                  {result.tlsVersion || 'Unencrypted'}
                </span>
              </div>
              <div className="text-xs truncate" title={result.cipherSuite}>
                <span className="text-zinc-500 font-mono">Cipher: </span>
                <span className="text-zinc-300 font-mono">
                  {result.cipherSuite || 'None'}
                </span>
              </div>
            </div>

            {/* DNS Security Policies */}
            <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-semibold uppercase text-zinc-400">
                  MTA-STS & DANE Policies
                </span>
                <ShieldCheck className="w-4 h-4 text-zinc-300" />
              </div>
              <div className="text-xs">
                <span className="text-zinc-500 font-mono">MTA-STS (RFC 8461): </span>
                <span
                  className={
                    result.mtaStsStatus === 'VALID'
                      ? 'text-emerald-400 font-bold font-mono'
                      : 'text-amber-400 font-bold font-mono'
                  }
                >
                  {result.mtaStsStatus}
                </span>
              </div>
              <div className="text-xs">
                <span className="text-zinc-500 font-mono">DANE TLSA (RFC 7672): </span>
                <span
                  className={
                    result.daneStatus === 'VALID'
                      ? 'text-emerald-400 font-bold font-mono'
                      : 'text-zinc-400 font-mono'
                  }
                >
                  {result.daneStatus}
                </span>
              </div>
            </div>
          </div>

          {/* Certificate Intelligence Card */}
          {result.certificateSubject && (
            <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-2.5">
              <div className="flex items-center justify-between border-b border-zinc-800/80 pb-2">
                <div className="flex items-center space-x-2">
                  <Award className="w-3.5 h-3.5 text-zinc-400" />
                  <span className="text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
                    Remote X.509 Certificate Chain
                  </span>
                </div>
                <span className="text-[10px] font-mono text-zinc-500">
                  Key Strength: {result.certificateKeyStrength || '2048-bit'}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                <div>
                  <span className="text-zinc-500 text-[10px] uppercase block">Subject (CN)</span>
                  <span className="text-zinc-200">{result.certificateSubject}</span>
                </div>
                <div>
                  <span className="text-zinc-500 text-[10px] uppercase block">Issuer</span>
                  <span className="text-zinc-300">{result.certificateIssuer}</span>
                </div>
                <div>
                  <span className="text-zinc-500 text-[10px] uppercase block">Expiration</span>
                  <span
                    className={
                      (result.certificateValidDays || 0) < 0
                        ? 'text-rose-400 font-bold'
                        : (result.certificateValidDays || 0) < 30
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }
                  >
                    {result.certificateValidDays !== undefined
                      ? `${result.certificateValidDays} days remaining (${result.certificateExpires?.substring(0, 16)})`
                      : 'N/A'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Threats & Policy Violations */}
          {result.threats.length > 0 && (
            <div className="bg-rose-950/20 border border-rose-900/40 rounded-lg p-3.5 space-y-2">
              <div className="text-[10px] font-mono font-bold text-rose-300 uppercase tracking-wider flex items-center space-x-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                <span>Observed Vulnerabilities & Policy Discrepancies ({result.threats.length})</span>
              </div>
              <div className="space-y-1">
                {result.threats.map((threat, idx) => (
                  <div key={idx} className="text-xs text-rose-200 font-sans flex items-start space-x-2">
                    <span className="text-rose-400 font-mono text-[10px] mt-0.5">&bull;</span>
                    <span>{threat}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Wire Protocol Transcript */}
          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-2">
            <div className="flex items-center justify-between border-b border-zinc-800/80 pb-2">
              <div className="flex items-center space-x-2 text-[10px] font-mono text-zinc-400 uppercase font-semibold">
                <Terminal className="w-3.5 h-3.5 text-zinc-400" />
                <span>Live Socket Dialogue & Wire Transcript</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500">
                {result.rawTranscript.length} wire exchange(s)
              </span>
            </div>

            <div className="space-y-1.5 font-mono text-xs max-h-64 overflow-y-auto pr-1">
              {result.rawTranscript.map((t, idx) => (
                <div
                  key={idx}
                  className={`p-2 rounded border text-[11px] ${
                    t.direction === 'SENT'
                      ? 'bg-zinc-900/80 border-zinc-800 text-zinc-200'
                      : 'bg-zinc-950 border-zinc-850 text-zinc-400'
                  }`}
                >
                  <div className="text-[9px] text-zinc-500 mb-0.5 flex justify-between">
                    <span>{t.direction === 'SENT' ? 'CLIENT → SERVER' : 'SERVER → CLIENT'}</span>
                    <span>{new Date(t.timestamp).toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 3 } as any)}</span>
                  </div>
                  <div className="whitespace-pre-wrap">{t.text}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
