import React, { useState } from 'react';
import {
  Network,
  Clock,
  ArrowRight,
  ShieldAlert,
  Lock,
  Unlock,
  Key,
  Terminal,
  Cpu,
  Search,
} from 'lucide-react';
import { SessionMetadata, ConversationTurn } from '../../../shared/types.ts';

interface SessionsViewProps {
  sessions: SessionMetadata[];
  selectedSessionId?: string;
  onSelectSession?: (id: string) => void;
}

export const SessionsView: React.FC<SessionsViewProps> = ({
  sessions,
  selectedSessionId,
  onSelectSession,
}) => {
  const [activeSessionId, setActiveSessionId] = useState<string>(
    selectedSessionId || (sessions.length > 0 ? sessions[0].id : '')
  );
  const [filterProtocol, setFilterProtocol] = useState<string>('ALL');
  const [filterVerdict, setFilterVerdict] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const currentSession = sessions.find((s) => s.id === activeSessionId) || sessions[0];

  const filteredSessions = sessions.filter((s) => {
    if (filterProtocol !== 'ALL' && s.protocol !== filterProtocol) return false;
    if (filterVerdict !== 'ALL' && s.starttlsVerdict !== filterVerdict) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchIp = s.clientIp.includes(term) || s.serverIp.includes(term);
      const matchId = s.id.toLowerCase().includes(term);
      const matchCipher = s.tlsCipherSuiteName?.toLowerCase().includes(term);
      if (!matchIp && !matchId && !matchCipher) return false;
    }
    return true;
  });

  return (
    <div className="space-y-4 select-none">
      {/* Filters Bar */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, stream ID, cipher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 rounded pl-8 pr-3 py-1.5 focus:outline-none focus:border-zinc-700 font-mono w-56"
            />
          </div>

          <select
            value={filterProtocol}
            onChange={(e) => setFilterProtocol(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 rounded px-2.5 py-1.5 focus:outline-none font-mono"
          >
            <option value="ALL">All Protocols</option>
            <option value="SMTP">SMTP</option>
            <option value="IMAP">IMAP</option>
            <option value="POP3">POP3</option>
          </select>

          <select
            value={filterVerdict}
            onChange={(e) => setFilterVerdict(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 rounded px-2.5 py-1.5 focus:outline-none font-mono"
          >
            <option value="ALL">All STARTTLS Verdicts</option>
            <option value="clean_starttls">Clean STARTTLS</option>
            <option value="ack_without_tls">ACK Without TLS (Stripped)</option>
            <option value="missing_starttls_in_caps">Missing In Capabilities</option>
            <option value="encrypted_implicit_tls">Encrypted Implicit TLS</option>
            <option value="plaintext_unencrypted">Plaintext Unencrypted</option>
          </select>
        </div>

        <div className="text-xs text-zinc-500 font-mono">
          Showing {filteredSessions.length} of {sessions.length} stream(s)
        </div>
      </div>

      {/* Main Split Layout: Session Table & Deep Forensics Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Sessions List */}
        <div className="lg:col-span-5 bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3 overflow-hidden flex flex-col max-h-[720px]">
          <div className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider mb-2 px-1">
            Reconstructed TCP Streams
          </div>

          <div className="overflow-y-auto space-y-1.5 flex-1 pr-1 font-sans">
            {filteredSessions.map((s) => {
              const isSelected = s.id === (currentSession ? currentSession.id : '');
              const hasCrit = s.findings.some((f) => f.severity === 'CRITICAL');
              const hasHigh = s.findings.some((f) => f.severity === 'HIGH');

              return (
                <div
                  key={s.id}
                  onClick={() => {
                    setActiveSessionId(s.id);
                    if (onSelectSession) onSelectSession(s.id);
                  }}
                  className={`p-3 rounded-md border cursor-pointer transition text-xs ${
                    isSelected
                      ? 'bg-zinc-900 border-zinc-600 shadow-xs'
                      : 'bg-zinc-950/70 border-zinc-800/80 hover:border-zinc-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono font-bold text-zinc-200">{s.id}</span>
                      <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-[10px] font-mono text-zinc-300">
                        {s.protocol}
                      </span>
                    </div>

                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.2 rounded uppercase border ${
                        s.starttlsVerdict === 'clean_starttls' || s.starttlsVerdict === 'encrypted_implicit_tls'
                          ? 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60'
                          : s.starttlsVerdict === 'ack_without_tls'
                          ? 'bg-rose-950/40 text-rose-300 border-rose-900/60 animate-pulse'
                          : 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                      }`}
                    >
                      {s.starttlsVerdict.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <div className="text-[11px] text-zinc-400 font-mono flex items-center justify-between">
                    <span>
                      {s.clientIp}:{s.clientPort}
                    </span>
                    <ArrowRight className="w-3 h-3 mx-1 text-zinc-600" />
                    <span>
                      {s.serverIp}:{s.serverPort}
                    </span>
                  </div>

                  <div className="mt-2 pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px]">
                    <span className="text-zinc-500 font-mono">
                      {s.tlsVersion ? (
                        <span className="text-zinc-300">{s.tlsVersion}</span>
                      ) : (
                        <span className="text-zinc-500">Plaintext</span>
                      )}
                    </span>

                    <div className="flex items-center space-x-1.5">
                      {s.findings.length > 0 && (
                        <span
                          className={`px-1.5 py-0.2 rounded font-mono font-bold text-[10px] ${
                            hasCrit
                              ? 'bg-rose-950/40 text-rose-300 border border-rose-900/60'
                              : hasHigh
                              ? 'bg-amber-950/40 text-amber-300 border border-amber-900/60'
                              : 'bg-zinc-800 text-zinc-400'
                          }`}
                        >
                          {s.findings.length} Threat(s)
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Deep Session Forensics Inspector */}
        <div className="lg:col-span-7 bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col max-h-[720px] overflow-hidden">
          {currentSession ? (
            <div className="flex flex-col h-full overflow-hidden">
              {/* Header Details */}
              <div className="border-b border-zinc-800/80 pb-3 mb-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-sm font-bold text-zinc-100">
                      {currentSession.id}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs font-mono">
                      {currentSession.protocol}
                    </span>
                    <span className="font-mono text-xs text-zinc-500">
                      Duration: {currentSession.durationMs}ms ({currentSession.packetCount} pkts)
                    </span>
                  </div>

                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${
                      currentSession.starttlsVerdict === 'clean_starttls'
                        ? 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60'
                        : currentSession.starttlsVerdict === 'ack_without_tls'
                        ? 'bg-rose-950/40 text-rose-300 border-rose-900/60'
                        : 'bg-amber-950/40 text-amber-300 border-amber-900/60'
                    }`}
                  >
                    {currentSession.starttlsVerdict}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-zinc-950 p-2.5 rounded border border-zinc-800/80">
                  <div>
                    <span className="text-zinc-500">Client: </span>
                    <span className="text-zinc-300">
                      {currentSession.clientIp}:{currentSession.clientPort}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Server: </span>
                    <span className="text-zinc-300">
                      {currentSession.serverIp}:{currentSession.serverPort}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Negotiated TLS: </span>
                    <span className="text-zinc-200">
                      {currentSession.tlsVersion || 'Unencrypted'}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Cipher: </span>
                    <span className="text-zinc-300 truncate inline-block max-w-[200px]" title={currentSession.tlsCipherSuiteName}>
                      {currentSession.tlsCipherSuiteName || 'None'}
                    </span>
                  </div>
                </div>

                {/* Plaintext Credential Exposure Warning if present */}
                {currentSession.credentialsExposed && (
                  <div className="mt-2.5 p-2.5 rounded bg-rose-950/30 border border-rose-900/60 text-xs text-rose-300 flex items-start space-x-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold">Credential Exposure: </span>
                      <span>
                        Account &quot;{currentSession.credentialsExposed.username || 'unknown'}&quot; credentials leaked via plaintext {currentSession.credentialsExposed.type}.
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Protocol Conversation & Hex/ASCII Turns */}
              <div className="flex-1 overflow-y-auto space-y-2 pr-2">
                <div className="text-[10px] font-mono font-semibold text-zinc-500 uppercase tracking-wider mb-2 flex items-center space-x-1.5">
                  <Terminal className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Reconstructed Conversation Timeline</span>
                </div>

                {currentSession.conversation && currentSession.conversation.length > 0 ? (
                  currentSession.conversation.map((turn, idx) => {
                    const isC2S = turn.direction === 'C2S';
                    return (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-md border text-xs font-mono ${
                          isC2S
                            ? 'bg-zinc-900/80 border-zinc-800 mr-6'
                            : 'bg-zinc-950 border-zinc-850 ml-6'
                        }`}
                      >
                        <div className="flex items-center justify-between text-[10px] text-zinc-500 mb-1">
                          <span className="font-bold text-zinc-400">
                            {isC2S ? 'CLIENT -> SERVER' : 'SERVER -> CLIENT'} (Frame #{turn.frameNumber})
                          </span>
                          <span>{new Date(turn.timestamp).toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 3 } as any)}</span>
                        </div>

                        {turn.isTls ? (
                          <div className="flex items-center space-x-1.5 text-zinc-300 font-semibold py-0.5">
                            <Lock className="w-3 h-3 text-zinc-400" />
                            <span>{turn.text}</span>
                          </div>
                        ) : (
                          <div className="text-zinc-200 whitespace-pre-wrap leading-relaxed">
                            {turn.text}
                          </div>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <div className="text-zinc-500 text-xs italic font-mono">
                    No application payload turns observed for this stream.
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-zinc-500 text-xs font-mono">
              Select a stream from the left to view deep forensic dissection.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
