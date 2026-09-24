import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileBox,
  CheckCircle2,
  AlertCircle,
  Trash2,
  HardDrive,
  FileCheck,
  ShieldAlert,
} from 'lucide-react';
import { CaseRecord } from '../../../shared/types.ts';

interface CasesViewProps {
  cases: CaseRecord[];
  activeCaseId: string | null;
  onSelectCase: (id: string) => void;
  onDeleteCase: (id: string) => void;
  onUploadFile: (file: File) => void;
  onLoadIncidentTrace: () => void;
  isLoading: boolean;
}

export const CasesView: React.FC<CasesViewProps> = ({
  cases,
  activeCaseId,
  onSelectCase,
  onDeleteCase,
  onUploadFile,
  onLoadIncidentTrace,
  isLoading,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndUpload = (file: File) => {
    setErrorMsg(null);
    if (!file) return;

    if (file.size === 0) {
      setErrorMsg('Validation Error: Uploaded capture file is empty (0 bytes).');
      return;
    }

    if (file.size > 50 * 1024 * 1024) {
      setErrorMsg('Validation Error: File exceeds maximum allowed size of 50 MB.');
      return;
    }

    onUploadFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndUpload(e.target.files[0]);
    }
  };

  return (
    <div className="space-y-6 select-none">
      {/* Upload Dropzone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`border border-dashed rounded-lg p-8 text-center transition ${
          dragActive
            ? 'border-zinc-400 bg-zinc-900/60'
            : 'border-zinc-800 bg-zinc-900/30 hover:border-zinc-700'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="flex flex-col items-center">
          <div className="w-11 h-11 rounded-md bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-300 mb-3">
            <UploadCloud className="w-5 h-5 text-zinc-400" />
          </div>
          <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono mb-1">
            Ingest Network Packet Capture
          </h3>
          <p className="text-xs text-zinc-400 max-w-md mb-4 font-sans">
            Supports Classic PCAP (microsecond & nanosecond) and PCAPNG captures.
            Automated stream reassembly, STARTTLS stripping analysis, and TLS cryptographic audit.
          </p>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={isLoading}
              className="px-3.5 py-1.5 rounded-md bg-zinc-100 hover:bg-white text-zinc-950 text-xs font-medium cursor-pointer transition disabled:opacity-50 shadow-xs"
            >
              Select PCAP File
            </button>
            <span className="text-xs text-zinc-600 font-mono">or</span>
            <button
              onClick={onLoadIncidentTrace}
              disabled={isLoading}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/70 text-xs font-medium cursor-pointer transition disabled:opacity-50"
            >
              <FileCheck className="w-3.5 h-3.5 text-zinc-400" />
              <span>Load Production Incident Trace</span>
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="mt-4 p-2.5 bg-rose-950/40 border border-rose-900/60 rounded text-xs text-rose-300 flex items-center justify-center space-x-2 font-mono">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Case Management Table */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <FileBox className="w-4 h-4 text-zinc-400" />
            <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
              Forensic Capture Inventory
            </h3>
          </div>
          <span className="text-xs text-zinc-500 font-mono">{cases.length} case(s) loaded</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-zinc-800/80 text-zinc-500 font-mono text-[10px] uppercase tracking-wider">
                <th className="py-2 px-3">Capture Title</th>
                <th className="py-2 px-3">Packets</th>
                <th className="py-2 px-3">Size</th>
                <th className="py-2 px-3">SHA-256 Digest</th>
                <th className="py-2 px-3">Risk Tier</th>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/40 text-zinc-300">
              {cases.map((c) => {
                const isActive = c.id === activeCaseId;
                const risk = c.summary?.riskLevel || 'CLEAN';

                return (
                  <tr
                    key={c.id}
                    className={`hover:bg-zinc-800/30 transition ${
                      isActive ? 'bg-zinc-900/60' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3">
                      <div className="flex items-center space-x-2">
                        {isActive && (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        )}
                        <div>
                          <div className="font-medium text-zinc-200 text-xs">{c.name}</div>
                          <div className="text-[10px] text-zinc-500 font-mono">{c.filename}</div>
                        </div>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-xs tabular-nums">{c.packetCount}</td>
                    <td className="py-2.5 px-3 font-mono text-xs tabular-nums text-zinc-400">
                      {(c.fileSizeBytes / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-500">
                      {c.fileSha256.substring(0, 12)}…
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                          risk === 'CRITICAL'
                            ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                            : risk === 'HIGH'
                            ? 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                            : risk === 'MEDIUM'
                            ? 'bg-yellow-950/40 text-yellow-300 border-yellow-900/60'
                            : 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60'
                        }`}
                      >
                        {risk}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-500">
                      {new Date(c.createdAt).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        {!isActive ? (
                          <button
                            onClick={() => onSelectCase(c.id)}
                            className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[11px] font-medium transition cursor-pointer"
                          >
                            Inspect
                          </button>
                        ) : (
                          <span className="text-[11px] text-emerald-400 font-mono">ACTIVE</span>
                        )}
                        <button
                          onClick={() => onDeleteCase(c.id)}
                          className="p-1 rounded text-zinc-600 hover:text-rose-400 transition cursor-pointer"
                          title="Delete Case"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
