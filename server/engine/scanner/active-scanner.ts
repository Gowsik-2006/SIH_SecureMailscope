import * as net from 'node:net';
import * as tls from 'node:tls';
import * as dns from 'node:dns/promises';
import { ActiveScanRequest, ActiveScanResult } from '../../../shared/types.ts';
import { AnalysisQueue } from '../../queue/analysis-queue.ts';

interface RecordedTurn {
  direction: 'SENT' | 'RECV';
  timestamp: number;
  data: Buffer;
  text: string;
}

export class ActiveScanner {
  /**
   * Conducts a real, active network audit against a live mail server.
   * Connects via TCP, negotiates STARTTLS, inspects real certificates and ciphers,
   * checks DNS MTA-STS/DANE, and records the raw bytes into a real forensic PCAP.
   */
  public static async scan(req: ActiveScanRequest): Promise<ActiveScanResult> {
    const startTime = Date.now();
    const scanId = `SCAN-${Date.now().toString(36).toUpperCase()}`;
    let targetHost = req.target.trim().toLowerCase();

    // Default ports by protocol
    let port = req.port;
    let protocol: 'SMTP' | 'IMAP' | 'POP3' = req.protocol === 'AUTO' || !req.protocol ? 'SMTP' : req.protocol;

    if (!port) {
      if (protocol === 'IMAP') port = 143;
      else if (protocol === 'POP3') port = 110;
      else port = 25; // standard SMTP
    }

    // If target has no dots or looks like an email domain (e.g. "gmail.com"), resolve MX records
    let baseDomain = targetHost;
    if (targetHost.includes('@')) {
      baseDomain = targetHost.split('@')[1];
      targetHost = baseDomain;
    }

    // Attempt MX resolution if port is 25/587 and domain is not an IP
    if ((port === 25 || port === 587) && !net.isIP(targetHost)) {
      try {
        const mxRecords = await dns.resolveMx(targetHost);
        if (mxRecords && mxRecords.length > 0) {
          // Sort by priority lowest first
          mxRecords.sort((a, b) => a.priority - b.priority);
          targetHost = mxRecords[0].exchange;
        }
      } catch {
        // Fall back to direct targetHost
      }
    }

    // Resolve IP address
    let resolvedIp = '127.0.0.1';
    try {
      const lookup = await dns.lookup(targetHost);
      resolvedIp = lookup.address;
    } catch {
      resolvedIp = net.isIP(targetHost) ? targetHost : '0.0.0.0';
    }

    const transcript: { direction: 'SENT' | 'RECV'; timestamp: number; text: string }[] = [];
    const recordedTurns: RecordedTurn[] = [];
    const threats: string[] = [];
    let banner = '';
    const capabilities: string[] = [];
    let starttlsSupported = false;
    let starttlsNegotiated = false;
    let tlsVersion: string | undefined;
    let cipherSuite: string | undefined;
    let certSubject: string | undefined;
    let certIssuer: string | undefined;
    let certExpires: string | undefined;
    let certValidDays: number | undefined;
    let certKeyStrength: string | undefined;
    let isSelfSigned: boolean | undefined;

    // Check MTA-STS & DANE in parallel with connection attempt
    let mtaStsStatus: 'VALID' | 'MISSING' | 'INVALID' | 'NOT_CHECKED' = 'NOT_CHECKED';
    let mtaStsPolicy: string | undefined;
    let daneStatus: 'VALID' | 'MISSING' | 'NOT_CHECKED' = 'NOT_CHECKED';

    if (req.checkMtaSts !== false && baseDomain) {
      try {
        const txtRecords = await dns.resolveTxt(`_mta-sts.${baseDomain}`);
        const flat = txtRecords.flat().join(' ');
        if (flat.includes('v=STSv1')) {
          mtaStsStatus = 'VALID';
          mtaStsPolicy = flat;
        } else {
          mtaStsStatus = 'MISSING';
          threats.push('MTA-STS DNS Record Missing: vulnerable to active network downgrade attacks.');
        }
      } catch {
        mtaStsStatus = 'MISSING';
        threats.push('MTA-STS DNS Record Missing: domain lacks RFC 8461 enforcement policy.');
      }
    }

    if (req.checkDane !== false && targetHost) {
      try {
        const tlsaRecords = await dns.resolve(
          `_${port}._tcp.${targetHost}`,
          'TLSA' as any
        );
        daneStatus = tlsaRecords && tlsaRecords.length > 0 ? 'VALID' : 'MISSING';
      } catch {
        daneStatus = 'MISSING';
      }
    }

    // Connect to target mail server via real TCP socket
    try {
      await new Promise<void>((resolve, reject) => {
        const timeoutMs = 8000;
        let socket: net.Socket | null = null;
        const timer = setTimeout(() => {
          if (socket) socket.destroy();
          reject(new Error(`Connection to ${targetHost}:${port} timed out after ${timeoutMs}ms`));
        }, timeoutMs);

        socket = net.createConnection({ host: targetHost, port }, async () => {
          // Connected
        });

        socket.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });

        let bufferAccumulator = '';
        let phase: 'BANNER' | 'EHLO_SENT' | 'STARTTLS_SENT' | 'TLS_HANDSHAKE' | 'DONE' = 'BANNER';

        const sendData = (str: string) => {
          if (!socket || socket.destroyed) return;
          const buf = Buffer.from(str, 'utf8');
          recordedTurns.push({
            direction: 'SENT',
            timestamp: Date.now(),
            data: buf,
            text: str.trim(),
          });
          transcript.push({
            direction: 'SENT',
            timestamp: Date.now(),
            text: str.trim(),
          });
          socket.write(buf);
        };

        socket.on('data', async (chunk) => {
          recordedTurns.push({
            direction: 'RECV',
            timestamp: Date.now(),
            data: chunk,
            text: chunk.toString('utf8').trim(),
          });

          const chunkStr = chunk.toString('utf8');
          transcript.push({
            direction: 'RECV',
            timestamp: Date.now(),
            text: chunkStr.trim(),
          });

          bufferAccumulator += chunkStr;

          if (phase === 'BANNER') {
            if (bufferAccumulator.includes('\r\n') || bufferAccumulator.includes('\n')) {
              banner = bufferAccumulator.trim();
              bufferAccumulator = '';

              if (protocol === 'SMTP') {
                phase = 'EHLO_SENT';
                sendData(`EHLO audit-scanner.security.local\r\n`);
              } else if (protocol === 'IMAP') {
                phase = 'EHLO_SENT';
                sendData(`a001 CAPABILITY\r\n`);
              } else if (protocol === 'POP3') {
                phase = 'STARTTLS_SENT';
                sendData(`STLS\r\n`);
              }
            }
          } else if (phase === 'EHLO_SENT') {
            // Check for completed response
            const lines = bufferAccumulator.split(/\r?\n/);
            const isComplete =
              protocol === 'SMTP'
                ? lines.some((l) => /^[0-9]{3} /.test(l))
                : lines.some((l) => l.startsWith('a001 OK') || l.startsWith('a001 BAD'));

            if (isComplete) {
              for (const line of lines) {
                if (line.trim()) capabilities.push(line.trim());
              }

              const capsUpper = bufferAccumulator.toUpperCase();
              if (capsUpper.includes('STARTTLS')) {
                starttlsSupported = true;
              } else {
                threats.push('STARTTLS Capability Missing: Server does not advertise STARTTLS in capabilities.');
              }

              bufferAccumulator = '';

              if (starttlsSupported) {
                phase = 'STARTTLS_SENT';
                if (protocol === 'SMTP') {
                  sendData(`STARTTLS\r\n`);
                } else if (protocol === 'IMAP') {
                  sendData(`a002 STARTTLS\r\n`);
                }
              } else {
                clearTimeout(timer);
                if (socket) socket.end();
                resolve();
              }
            }
          } else if (phase === 'STARTTLS_SENT') {
            const lines = bufferAccumulator.split(/\r?\n/);
            const isReady = lines.some((l) => l.startsWith('220') || l.startsWith('a002 OK') || l.startsWith('+OK'));

            if (isReady) {
              starttlsNegotiated = true;
              phase = 'TLS_HANDSHAKE';
              clearTimeout(timer);

              // Upgrade socket to TLS
              try {
                const tlsSocket = tls.connect({
                  socket: socket!,
                  servername: targetHost,
                  rejectUnauthorized: false, // Audit scanner accepts self-signed/expired to analyze them
                }, () => {
                  tlsVersion = tlsSocket.getProtocol() || undefined;
                  const cipher = tlsSocket.getCipher();
                  cipherSuite = cipher ? `${cipher.name} (${cipher.version})` : undefined;

                  const cert = tlsSocket.getPeerCertificate(true);
                  if (cert && cert.subject) {
                    const rawSubCN = cert.subject.CN || cert.subject.O;
                    certSubject = Array.isArray(rawSubCN) ? rawSubCN[0] : rawSubCN || 'Unknown';

                    const rawIssCN = cert.issuer ? cert.issuer.CN || cert.issuer.O : undefined;
                    certIssuer = Array.isArray(rawIssCN) ? rawIssCN[0] : rawIssCN || 'Unknown';

                    certExpires = cert.valid_to;
                    if (cert.valid_to) {
                      const exp = new Date(cert.valid_to).getTime();
                      certValidDays = Math.round((exp - Date.now()) / (1000 * 60 * 60 * 24));
                      if (certValidDays < 0) {
                        threats.push(`Certificate Expired: validity lapsed ${Math.abs(certValidDays)} days ago.`);
                      } else if (certValidDays < 30) {
                        threats.push(`Certificate Expiring Soon: expires in ${certValidDays} days.`);
                      }
                    }

                    if (cert.bits) {
                      certKeyStrength = `${cert.bits} bits (${cert.asn1Curve || 'RSA'})`;
                      if (cert.bits < 2048) {
                        threats.push(`Weak Public Key: ${cert.bits} bits is below modern cryptographic standards.`);
                      }
                    }

                    // Check self-signed
                    if (cert.issuer && cert.subject && cert.fingerprint === cert.issuerCertificate?.fingerprint) {
                      isSelfSigned = true;
                      threats.push('Self-Signed Certificate: not signed by a trusted Certificate Authority.');
                    }
                  }

                  if (tlsVersion && (tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.1')) {
                    threats.push(`Obsolete TLS Protocol (${tlsVersion}): violates RFC 8996.`);
                  }

                  tlsSocket.end();
                  resolve();
                });

                tlsSocket.on('error', (tlsErr) => {
                  threats.push(`TLS Handshake Failed: ${tlsErr.message}`);
                  resolve();
                });
              } catch (upgradeErr: any) {
                threats.push(`TLS Upgrade Error: ${upgradeErr.message}`);
                resolve();
              }
            } else {
              threats.push(`STARTTLS Command Rejected: ${bufferAccumulator.trim()}`);
              clearTimeout(timer);
              if (socket) socket.end();
              resolve();
            }
          }
        });
      });
    } catch (netErr: any) {
      threats.push(`Network Connection Failed: ${netErr.message}`);
    }

    // Compile recorded turns into a real PCAP binary
    let caseId: string | undefined;
    try {
      const pcapBytes = ActiveScanner.buildPcapFromTurns(targetHost, resolvedIp, port, recordedTurns);
      if (pcapBytes.length > 24) {
        const { caseRecord } = AnalysisQueue.enqueue(
          pcapBytes,
          `live_audit_${targetHost}_${port}.pcap`,
          'active-scanner'
        );
        caseRecord.name = `Live Audit: ${targetHost}:${port}`;
        caseId = caseRecord.id;
      }
    } catch (e: any) {
      console.warn('Failed to build PCAP for live audit:', e.message);
    }

    // Compute composite risk score
    let riskScore = 15; // baseline clean
    if (!starttlsSupported) riskScore = 95;
    else if (!starttlsNegotiated) riskScore = 90;
    else if (threats.some((t) => t.includes('Expired') || t.includes('Self-Signed'))) riskScore = 75;
    else if (threats.some((t) => t.includes('Obsolete') || t.includes('Weak'))) riskScore = 65;
    else if (mtaStsStatus === 'MISSING') riskScore = 35;

    return {
      scanId,
      targetHost,
      resolvedIp,
      port,
      protocol,
      banner: banner || 'No banner received',
      ehloCapabilities: capabilities,
      starttlsSupported,
      starttlsNegotiated,
      tlsVersion,
      cipherSuite,
      certificateSubject: certSubject,
      certificateIssuer: certIssuer,
      certificateExpires: certExpires,
      certificateValidDays: certValidDays,
      certificateKeyStrength: certKeyStrength,
      isSelfSigned,
      mtaStsStatus,
      mtaStsPolicy,
      daneStatus,
      riskScore,
      threats,
      caseId,
      durationMs: Date.now() - startTime,
      timestamp: Date.now(),
      rawTranscript: transcript,
    };
  }

  /**
   * Encodes recorded network bytes into a valid Classic PCAP binary buffer.
   */
  private static buildPcapFromTurns(
    host: string,
    ip: string,
    port: number,
    turns: RecordedTurn[]
  ): Uint8Array {
    const packets: Uint8Array[] = [];

    // Parse IP bytes
    const ipParts = ip.split('.').map((p) => parseInt(p, 10) || 0);
    const serverIpBytes = ipParts.length === 4 ? ipParts : [127, 0, 0, 1];
    const clientIpBytes = [192, 168, 1, 50];

    let seqClient = 1000;
    let seqServer = 5000;

    for (let i = 0; i < turns.length; i++) {
      const turn = turns[i];
      const isC2S = turn.direction === 'SENT';
      const payload = turn.data;

      const srcIp = isC2S ? clientIpBytes : serverIpBytes;
      const dstIp = isC2S ? serverIpBytes : clientIpBytes;
      const srcPort = isC2S ? 54321 : port;
      const dstPort = isC2S ? port : 54321;
      const seq = isC2S ? seqClient : seqServer;
      const ack = isC2S ? seqServer : seqClient;

      if (isC2S) seqClient += payload.length || 1;
      else seqServer += payload.length || 1;

      // Build Frame
      const ethLen = 14;
      const ipLen = 20;
      const tcpLen = 20;
      const totalLen = ethLen + ipLen + tcpLen + payload.length;

      const frame = new Uint8Array(totalLen);
      const view = new DataView(frame.buffer);

      // Ethernet
      frame[12] = 0x08; // IPv4
      frame[13] = 0x00;

      // IPv4
      frame[14] = 0x45;
      view.setUint16(16, ipLen + tcpLen + payload.length);
      view.setUint16(18, i + 1);
      frame[22] = 64; // TTL
      frame[23] = 6;  // TCP
      frame[26] = srcIp[0];
      frame[27] = srcIp[1];
      frame[28] = srcIp[2];
      frame[29] = srcIp[3];
      frame[30] = dstIp[0];
      frame[31] = dstIp[1];
      frame[32] = dstIp[2];
      frame[33] = dstIp[3];

      // TCP
      view.setUint16(34, srcPort);
      view.setUint16(36, dstPort);
      view.setUint32(38, seq);
      view.setUint32(42, ack);
      frame[46] = (5 << 4); // Data offset 20 bytes
      frame[47] = 0x18;     // PSH, ACK
      view.setUint16(48, 64240);

      // Payload
      frame.set(payload, 54);

      // PCAP Packet Record Header (16 bytes)
      const sec = Math.floor(turn.timestamp / 1000);
      const usec = (turn.timestamp % 1000) * 1000;
      const recHeader = new Uint8Array(16);
      const recView = new DataView(recHeader.buffer);
      recView.setUint32(0, sec, true);
      recView.setUint32(4, usec, true);
      recView.setUint32(8, totalLen, true);
      recView.setUint32(12, totalLen, true);

      packets.push(recHeader);
      packets.push(frame);
    }

    // Classic PCAP Global Header (24 bytes)
    const globalHeader = new Uint8Array(24);
    const gView = new DataView(globalHeader.buffer);
    gView.setUint32(0, 0xa1b2c3d4, true); // Magic
    gView.setUint16(4, 2, true);          // Major
    gView.setUint16(6, 4, true);          // Minor
    gView.setUint32(8, 0, true);          // GMT
    gView.setUint32(12, 0, true);         // Accuracy
    gView.setUint32(16, 65535, true);     // Snaplen
    gView.setUint32(20, 1, true);         // Linktype: Ethernet (DLT_EN10MB)

    let totalBytes = 24;
    for (const p of packets) totalBytes += p.length;

    const out = new Uint8Array(totalBytes);
    out.set(globalHeader, 0);
    let offset = 24;
    for (const p of packets) {
      out.set(p, offset);
      offset += p.length;
    }

    return out;
  }
}
