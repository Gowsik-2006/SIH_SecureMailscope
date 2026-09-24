import { CollectorConfig, CaseRecord } from '../../../shared/types.ts';
import { AnalysisQueue } from '../../queue/analysis-queue.ts';

export class SensorCollectorManager {
  private static activeApiKey = 'soc-mail-sensor-key-live-2026';
  private static ingestCount = 0;
  private static lastIngestedAt?: number;

  public static getConfig(baseUrl: string): CollectorConfig {
    const ingestUrl = `${baseUrl.replace(/\/$/, '')}/api/collector/ingest`;

    const curlExample = `sudo tcpdump -i any "tcp port 25 or 587 or 465" -w - -c 200 2>/dev/null | \\
  curl -s -X POST "${ingestUrl}" \\
  -H "X-Sensor-Key: ${this.activeApiKey}" \\
  -H "Content-Type: application/vnd.tcpdump.pcap" \\
  --data-binary @-`;

    const pythonSnippet = `#!/usr/bin/env python3
"""
Enterprise Mail Gateway Sensor Agent for SIH26159 Forensic Platform
Captures live SMTP/IMAP/POP3 wire traffic and streams batches to the forensic analyzer.
"""
import subprocess, requests, time

INGEST_URL = "${ingestUrl}"
API_KEY = "${this.activeApiKey}"

def capture_and_ingest():
    print("[*] Starting live mail traffic sensor on port 25, 587, 465...")
    cmd = ["tcpdump", "-i", "any", "tcp port 25 or 587 or 465", "-w", "-", "-c", "250"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    pcap_data, _ = proc.communicate()
    
    if len(pcap_data) > 24:
        headers = {
            "X-Sensor-Key": API_KEY,
            "Content-Type": "application/vnd.tcpdump.pcap"
        }
        res = requests.post(INGEST_URL, data=pcap_data, headers=headers, timeout=15)
        print(f"[+] Ingested {len(pcap_data)} bytes -> Response: {res.json()}")

if __name__ == "__main__":
    while True:
        try:
            capture_and_ingest()
            time.sleep(5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(10)
`;

    return {
      apiKey: this.activeApiKey,
      endpointUrl: ingestUrl,
      curlExample,
      pythonSnippet,
      ingestCount: this.ingestCount,
      lastIngestedAt: this.lastIngestedAt,
    };
  }

  public static ingest(
    rawBytes: Uint8Array,
    apiKeyProvided: string | undefined,
    originIp: string
  ): { success: boolean; case?: CaseRecord; message: string } {
    if (!apiKeyProvided || apiKeyProvided !== this.activeApiKey) {
      return { success: false, message: 'Invalid or missing X-Sensor-Key header.' };
    }

    if (rawBytes.length < 24) {
      return { success: false, message: 'Payload is too short to be a valid PCAP/PCAPNG header.' };
    }

    try {
      const filename = `sensor_ingest_${originIp.replace(/[^a-zA-Z0-9.-]/g, '_')}_${Date.now()}.pcap`;
      const { caseRecord } = AnalysisQueue.enqueue(rawBytes, filename, 'remote-sensor');
      caseRecord.name = `Sensor Ingest (${originIp})`;

      this.ingestCount++;
      this.lastIngestedAt = Date.now();

      return {
        success: true,
        case: caseRecord,
        message: `Successfully ingested and analyzed ${caseRecord.packetCount} packets from remote sensor (${originIp}).`,
      };
    } catch (e: any) {
      return {
        success: false,
        message: `Forensic analysis of remote sensor stream failed: ${e.message}`,
      };
    }
  }
}
