import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Key,
  Terminal,
  Copy,
  Check,
  Download,
  Server,
  ArrowRight,
  ShieldCheck,
  Activity,
  FileCode,
} from 'lucide-react';
import { ApiClient } from '../../api/client.ts';
import { CollectorConfig } from '../../../shared/types.ts';

interface SensorIngestViewProps {
  onInspectCase?: (caseId: string) => void;
}

export const SensorIngestView: React.FC<SensorIngestViewProps> = ({ onInspectCase }) => {
  const [config, setConfig] = useState<CollectorConfig | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    ApiClient.getCollectorConfig()
      .then((cfg) => {
        setConfig(cfg);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to load collector config:', err);
        setLoading(false);
      });
  }, []);

  const copyToClipboard = (text: string, type: 'curl' | 'key') => {
    navigator.clipboard.writeText(text);
    if (type === 'curl') {
      setCopiedCurl(true);
      setTimeout(() => setCopiedCurl(false), 2000);
    } else {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const downloadPythonScript = () => {
    if (!config) return;
    const blob = new Blob([config.pythonSnippet], { type: 'text/x-python' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mail_sensor_agent.py';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5 select-none font-sans">
      {/* Top Banner */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-zinc-300" />
            <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider font-mono">
              Remote Sensor & Gateway Ingestion Pipeline
            </h3>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-300 border border-emerald-900/60">
            Ingestion Endpoint Online
          </span>
        </div>
        <p className="text-[11px] text-zinc-400 mt-1 max-w-3xl">
          Deploy lightweight capture sensors across enterprise Linux mail servers (Postfix, Exim, Sendmail, Haraka, Dovecot) 
          or gateway firewalls. Raw PCAPs stream securely over HTTPS directly into the forensic reassembly engine.
        </p>
      </div>

      {/* Sensor Credentials & Statistics */}
      {config && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5 space-y-1.5 font-mono text-xs">
            <div className="text-[10px] text-zinc-500 uppercase font-semibold flex items-center justify-between">
              <span>Ingestion Endpoint</span>
              <Activity className="w-3.5 h-3.5 text-zinc-400" />
            </div>
            <div className="text-zinc-200 text-[11px] truncate font-bold" title={config.endpointUrl}>
              POST /api/collector/ingest
            </div>
            <div className="text-[10px] text-zinc-500">Accepts application/vnd.tcpdump.pcap</div>
          </div>

          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5 space-y-1.5 font-mono text-xs">
            <div className="text-[10px] text-zinc-500 uppercase font-semibold flex items-center justify-between">
              <span>Sensor API Key</span>
              <button
                onClick={() => copyToClipboard(config.apiKey, 'key')}
                className="text-zinc-400 hover:text-zinc-200 cursor-pointer flex items-center space-x-1"
              >
                {copiedKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span className="text-[10px]">{copiedKey ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="text-zinc-200 text-[11px] font-bold truncate">
              {config.apiKey}
            </div>
            <div className="text-[10px] text-zinc-500">Passed via X-Sensor-Key header</div>
          </div>

          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-3.5 space-y-1.5 font-mono text-xs">
            <div className="text-[10px] text-zinc-500 uppercase font-semibold flex items-center justify-between">
              <span>Sensor Ingest Count</span>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-zinc-100 text-lg font-bold">
              {config.ingestCount} batch(es)
            </div>
            <div className="text-[10px] text-zinc-500">
              {config.lastIngestedAt ? `Last active ${new Date(config.lastIngestedAt).toLocaleTimeString()}` : 'Awaiting sensor stream'}
            </div>
          </div>
        </div>
      )}

      {/* Production Bash / tcpdump Sensor Command */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-3 font-sans">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
            <Terminal className="w-4 h-4 text-zinc-400" />
            <span>Option A: Instant Linux Gateway Command (tcpdump + curl)</span>
          </div>

          {config && (
            <button
              onClick={() => copyToClipboard(config.curlExample, 'curl')}
              className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-mono cursor-pointer transition"
            >
              {copiedCurl ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Copied to Clipboard</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Copy Shell Pipeline</span>
                </>
              )}
            </button>
          )}
        </div>

        <p className="text-[11px] text-zinc-400">
          Run this single command on your mail server. It captures 200 packets of port 25/587/465 traffic 
          and streams them directly into the analyzer via standard output pipe:
        </p>

        <pre className="p-3 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-zinc-300 overflow-x-auto whitespace-pre">
          {config?.curlExample || 'Loading sensor configuration...'}
        </pre>
      </div>

      {/* Python Sensor Agent Daemon */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-3 font-sans">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
            <FileCode className="w-4 h-4 text-zinc-400" />
            <span>Option B: Continuous Sensor Daemon (Python 3 Agent)</span>
          </div>

          <button
            onClick={downloadPythonScript}
            className="flex items-center space-x-1.5 px-3 py-1 rounded bg-zinc-100 hover:bg-white text-zinc-950 text-xs font-medium cursor-pointer transition shadow-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download mail_sensor_agent.py</span>
          </button>
        </div>

        <p className="text-[11px] text-zinc-400">
          For continuous 24/7 gateway monitoring, run this standalone Python agent in a systemd service 
          or screen session on your mail relay server:
        </p>

        <pre className="p-3 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-zinc-400 max-h-56 overflow-y-auto whitespace-pre">
          {config?.pythonSnippet || 'Loading Python agent script...'}
        </pre>
      </div>
    </div>
  );
};
