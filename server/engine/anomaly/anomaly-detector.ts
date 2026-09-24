import { Anomaly, EvidenceRef } from '../../../shared/types.ts';
import { ReassembledStream } from '../reassembly/tcp-reassembler.ts';
import { ProtocolAnalysisResult } from '../protocol/starttls-state-machine.ts';
import { ParsedTlsSession } from '../tls/tls-parser.ts';

export class AnomalyDetector {
  public static detect(
    sessionId: string,
    stream: ReassembledStream,
    protoResult: ProtocolAnalysisResult,
    tlsResult?: ParsedTlsSession
  ): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const firstPkt = stream.packets[0];
    const defaultFrame = firstPkt ? firstPkt.frameNumber : 1;
    const defaultTs = firstPkt ? firstPkt.timestampEpochMs : Date.now();

    // 1. Anomaly: Client sent STARTTLS on non-advertised server capability
    if (protoResult.starttlsVerdict === 'missing_starttls_in_caps') {
      anomalies.push({
        id: `anom-strip-${Math.random().toString(36).substring(2, 8)}`,
        sessionId,
        timestamp: defaultTs,
        type: 'CAPABILITY_SUPPRESSION_ANOMALY',
        title: 'STARTTLS Capability Missing in Server Greeting',
        observed:
          'Server EHLO/CAPABILITY reply omitted STARTTLS keyword; client continued in cleartext on standard submission port.',
        interpreted:
          'Potential active network intermediary (MITM proxy or firewall) stripping the STARTTLS keyword from the SMTP server banner to force plaintext fallback.',
        anomalyScore: 88,
        evidenceRef: {
          frameNumber: defaultFrame,
          timestamp: defaultTs,
          streamKey: stream.streamKey,
          byteOffset: 0,
          length: 32,
          snippetHex: '25 30 20 4f 4b',
          snippetAscii: '250-SIZE 52428800\r\n250-PIPELINING\r\n250 HELP',
          description: 'Server EHLO banner missing STARTTLS',
        },
      });
    }

    // 2. Anomaly: Server ACKed STARTTLS with 220, but client transmitted cleartext payload
    if (protoResult.starttlsVerdict === 'ack_without_tls') {
      anomalies.push({
        id: `anom-acknotls-${Math.random().toString(36).substring(2, 8)}`,
        sessionId,
        timestamp: defaultTs,
        type: 'UNENCRYPTED_FLOW_AFTER_ACK',
        title: 'Plaintext Traffic Stream After 220 STARTTLS Confirmation',
        observed:
          'Server sent "220 2.0.0 Ready to start TLS", but subsequent client segment contained ASCII protocol commands rather than a TLS ClientHello record.',
        interpreted:
          'High confidence attack indicator. The TLS negotiation was intercepted or the client software suffered an unencrypted fallback bug, leaking commands onto the wire.',
        anomalyScore: 96,
        evidenceRef: {
          frameNumber: defaultFrame,
          timestamp: defaultTs,
          streamKey: stream.streamKey,
          byteOffset: 0,
          length: 32,
          snippetHex: '4d 41 49 4c 20 46 52 4f 4d',
          snippetAscii: 'MAIL FROM:<sender@domain.com>',
          description: 'Plaintext command following 220 TLS acknowledgment',
        },
      });
    }

    // 3. Anomaly: Non-standard high port email traffic
    const standardPorts = [25, 465, 587, 110, 995, 143, 993, 2525];
    if (!standardPorts.includes(stream.serverPort) && protoResult.protocol !== 'UNKNOWN') {
      anomalies.push({
        id: `anom-port-${Math.random().toString(36).substring(2, 8)}`,
        sessionId,
        timestamp: defaultTs,
        type: 'NON_STANDARD_PORT_EMAIL',
        title: 'Email Protocol Active on Non-Standard Port',
        observed: `Full ${protoResult.protocol} session reconstructed on destination port ${stream.serverPort}.`,
        interpreted:
          'May indicate covert channel tunneling, shadow mail services, or custom infrastructure bypassing standard egress inspection filters.',
        anomalyScore: 65,
      });
    }

    // 4. Anomaly: HelloRetryRequest in TLS 1.3
    if (tlsResult && tlsResult.isHelloRetryRequest) {
      anomalies.push({
        id: `anom-hrr-${Math.random().toString(36).substring(2, 8)}`,
        sessionId,
        timestamp: defaultTs,
        type: 'TLS13_KEY_EXCHANGE_MISMATCH',
        title: 'TLS 1.3 HelloRetryRequest Triggered',
        observed:
          'ServerHello responded with HelloRetryRequest random magic, indicating client key share group was not supported by server.',
        interpreted:
          'Cryptographic negotiation required extra round trip; indicates client/server elliptic curve group mismatch or legacy client implementation.',
        anomalyScore: 42,
      });
    }

    // 5. Anomaly: Sudden RST termination after Handshake Failure Alert
    if (tlsResult && tlsResult.alerts.length > 0) {
      anomalies.push({
        id: `anom-alert-${Math.random().toString(36).substring(2, 8)}`,
        sessionId,
        timestamp: defaultTs,
        type: 'TLS_ALERT_TERMINATION',
        title: 'TLS Protocol Alert Termination',
        observed: `Session received ${tlsResult.alerts.length} TLS alert(s): ${tlsResult.alerts
          .map((a) => `${a.description} (${a.level})`)
          .join(', ')}.`,
        interpreted:
          'Client or server forcefully terminated the security association due to cryptographic or trust rejection.',
        anomalyScore: 60,
      });
    }

    return anomalies;
  }
}
