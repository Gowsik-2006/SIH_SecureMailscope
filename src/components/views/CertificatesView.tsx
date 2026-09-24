import React from 'react';
import {
  Award,
  AlertTriangle,
  CheckCircle,
  Calendar,
  Key,
  Shield,
  Fingerprint,
} from 'lucide-react';
import { CertificateInfo } from '../../../shared/types.ts';

interface CertificatesViewProps {
  certificates: {
    sessionId: string;
    streamKey: string;
    protocol: string;
    certificate: CertificateInfo;
  }[];
  onInspectSession?: (sessionId: string) => void;
}

export const CertificatesView: React.FC<CertificatesViewProps> = ({
  certificates,
  onInspectSession,
}) => {
  return (
    <div className="space-y-5 select-none">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono flex items-center space-x-2">
            <Award className="w-3.5 h-3.5 text-zinc-400" />
            <span>X.509 Certificate Intelligence & Chain Audit</span>
          </h3>
          <p className="text-[11px] text-zinc-400 mt-0.5">
            ASN.1 DER public key cryptography and trust chain analysis
          </p>
        </div>
        <span className="text-xs text-zinc-500 font-mono">
          {certificates.length} certificate(s) presented
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {certificates.map((item, idx) => {
          const cert = item.certificate;
          const hasIssues = cert.issues.length > 0;

          return (
            <div
              key={idx}
              className={`bg-zinc-900/40 border rounded-lg p-4 space-y-4 ${
                hasIssues ? 'border-amber-900/50' : 'border-zinc-800/80'
              }`}
            >
              {/* Top Row */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/80 pb-3">
                <div className="flex items-center space-x-3">
                  <div
                    className={`w-8 h-8 rounded-md flex items-center justify-center border ${
                      cert.isExpired || cert.keyLength < 2048
                        ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                        : 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60'
                    }`}
                  >
                    <Shield className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-100 font-mono">{cert.subject}</h4>
                    <div className="text-[11px] text-zinc-400">
                      Issuer: <span className="text-zinc-300">{cert.issuer}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <span className="font-mono text-[11px] text-zinc-400 px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800">
                    Stream: {item.sessionId} ({item.protocol})
                  </span>

                  {onInspectSession && (
                    <button
                      onClick={() => onInspectSession(item.sessionId)}
                      className="text-[11px] text-zinc-400 hover:text-zinc-200 transition cursor-pointer font-mono"
                    >
                      Inspect Stream &rarr;
                    </button>
                  )}
                </div>
              </div>

              {/* Certificate Metadata Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                <div className="bg-zinc-950 p-3 rounded border border-zinc-800/80 space-y-1">
                  <div className="text-zinc-500 text-[10px] uppercase">Public Key Specification</div>
                  <div className="text-zinc-200 font-bold">
                    {cert.keyAlgorithm} - {cert.keyLength} bits
                  </div>
                  <div className="text-[10px] text-zinc-400">
                    {cert.keyLength >= 2048 ? 'Sufficient bit-strength' : 'Weak RSA key (<2048)'}
                  </div>
                </div>

                <div className="bg-zinc-950 p-3 rounded border border-zinc-800/80 space-y-1">
                  <div className="text-zinc-500 text-[10px] uppercase">Signature Algorithm</div>
                  <div className="text-zinc-200 font-bold">{cert.signatureAlgorithm}</div>
                  <div className="text-[10px] text-zinc-400">
                    {cert.isSelfSigned ? 'Self-signed root certificate' : 'Standard CA signed'}
                  </div>
                </div>

                <div className="bg-zinc-950 p-3 rounded border border-zinc-800/80 space-y-1">
                  <div className="text-zinc-500 text-[10px] uppercase">Validity Window</div>
                  <div className="text-zinc-200">
                    {cert.isExpired ? (
                      <span className="text-rose-400 font-bold">EXPIRED</span>
                    ) : (
                      <span className="text-emerald-400">{cert.daysRemaining} days remaining</span>
                    )}
                  </div>
                  <div className="text-[10px] text-zinc-400">
                    {new Date(cert.validFrom).toLocaleDateString()} &rarr;{' '}
                    {new Date(cert.validTo).toLocaleDateString()}
                  </div>
                </div>
              </div>

              {/* SHA256 Fingerprint */}
              <div className="bg-zinc-950 p-2.5 rounded border border-zinc-800/80 flex items-center justify-between text-[11px] font-mono">
                <div className="flex items-center space-x-2">
                  <Fingerprint className="w-3.5 h-3.5 text-zinc-500" />
                  <span className="text-zinc-500">SHA-256 Fingerprint:</span>
                  <span className="text-zinc-300">{cert.rawFingerprintSha256}</span>
                </div>
                <div className="text-zinc-500 text-[10px]">Serial: {cert.serialNumber}</div>
              </div>

              {/* Issues/Anomalies List */}
              {hasIssues && (
                <div className="bg-rose-950/20 border border-rose-900/40 rounded p-3 space-y-1">
                  <div className="text-[10px] font-mono font-bold text-rose-300 uppercase tracking-wider">
                    Certificate Anomalies Detected:
                  </div>
                  {cert.issues.map((issue, i) => (
                    <div key={i} className="text-xs text-rose-200 font-sans flex items-center space-x-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                      <span>{issue}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
