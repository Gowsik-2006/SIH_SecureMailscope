import {
  CaseSummary,
  RiskAssessment,
  SessionMetadata,
  Finding,
  Anomaly,
  RawPacket,
  EmailProtocol,
  StarttlsVerdict,
  FindingSeverity,
} from '../../shared/types.ts';
import { PcapReader, PcapFileMetadata } from './pcap/pcap-reader.ts';
import { LinkIpTcpParser } from './link/link-ip-tcp.ts';
import { TcpReassembler, ReassembledStream } from './reassembly/tcp-reassembler.ts';
import { StarttlsStateMachine } from './protocol/starttls-state-machine.ts';
import { TlsParser, ParsedTlsSession } from './tls/tls-parser.ts';
import { X509Parser } from './crypto/x509-parser.ts';
import { RuleEngine } from './rules/rule-engine.ts';
import { AnomalyDetector } from './anomaly/anomaly-detector.ts';
import { RiskScorer } from './scoring/risk-scorer.ts';
import crypto from 'crypto';

export interface AnalysisPipelineResult {
  pcapMetadata: PcapFileMetadata;
  fileSha256: string;
  fileSizeBytes: number;
  packetsCount: number;
  sessions: SessionMetadata[];
  findings: Finding[];
  anomalies: Anomaly[];
  summary: CaseSummary;
  riskAssessment: RiskAssessment;
}

export class ForensicAnalyzer {
  public static analyze(pcapBuffer: Uint8Array): AnalysisPipelineResult {
    const fileSha256 = crypto.createHash('sha256').update(pcapBuffer).digest('hex');
    const fileSizeBytes = pcapBuffer.length;

    // 1. Binary parse PCAP / PCAPNG
    const { metadata: pcapMetadata, packets: rawPackets } = PcapReader.parse(pcapBuffer);

    // 2. Decode Link / IP / TCP layers
    const decodedPackets: RawPacket[] = [];
    for (const raw of rawPackets) {
      const pkt = LinkIpTcpParser.parsePacket(raw);
      if (pkt) {
        decodedPackets.push(pkt);
      }
    }

    // 3. TCP Stream Reassembly
    const streams = TcpReassembler.process(decodedPackets);

    // 4. Process each stream
    const sessions: SessionMetadata[] = [];
    const allFindings: Finding[] = [];
    const allAnomalies: Anomaly[] = [];

    const protocolCounts: Record<EmailProtocol, number> = {
      SMTP: 0,
      IMAP: 0,
      POP3: 0,
      UNKNOWN: 0,
    };

    const verdictCounts: Record<StarttlsVerdict, number> = {
      clean_starttls: 0,
      ack_without_tls: 0,
      missing_starttls_in_caps: 0,
      rejected_starttls: 0,
      fallback_to_plaintext: 0,
      encrypted_implicit_tls: 0,
      plaintext_unencrypted: 0,
    };

    for (let i = 0; i < streams.length; i++) {
      const stream = streams[i];
      const sessionId = `sess-${(i + 1).toString().padStart(3, '0')}`;

      // Protocol & STARTTLS state analysis
      const protoResult = StarttlsStateMachine.analyzeStream(stream);

      // TLS Handshake inspection
      // TLS traffic can flow in either direction, combine payload streams to check
      const combinedTlsData = new Uint8Array(stream.c2sData.length + stream.s2cData.length);
      combinedTlsData.set(stream.c2sData, 0);
      combinedTlsData.set(stream.s2cData, stream.c2sData.length);

      let tlsResult: ParsedTlsSession | undefined;
      let certInfo: any = undefined;

      const hasTlsMarker =
        stream.turns.some((t) => t.isTls) ||
        (stream.c2sData.length > 5 && stream.c2sData[0] === 22) ||
        (stream.s2cData.length > 5 && stream.s2cData[0] === 22);

      if (hasTlsMarker) {
        // Parse server records for ServerHello & Certificate
        const sTls = TlsParser.parseHandshakeData(stream.s2cData);
        const cTls = TlsParser.parseHandshakeData(stream.c2sData);

        tlsResult = {
          clientHelloFound: cTls.clientHelloFound || sTls.clientHelloFound,
          serverHelloFound: sTls.serverHelloFound,
          negotiatedVersion: sTls.negotiatedVersion || cTls.negotiatedVersion,
          clientOfferedVersions: cTls.clientOfferedVersions,
          clientSni: cTls.clientSni,
          clientCipherSuites: cTls.clientCipherSuites,
          selectedCipherSuite: sTls.selectedCipherSuite,
          certificatesDer: sTls.certificatesDer,
          isTls13: sTls.isTls13,
          isHelloRetryRequest: sTls.isHelloRetryRequest,
          alerts: [...cTls.alerts, ...sTls.alerts],
        };

        if (tlsResult.certificatesDer.length > 0) {
          certInfo = X509Parser.parse(tlsResult.certificatesDer[0]);
        }
      }

      // Rule evaluation
      const findings = RuleEngine.evaluateSession(
        sessionId,
        stream,
        protoResult,
        tlsResult,
        certInfo
      );

      // Anomaly detection
      const anomalies = AnomalyDetector.detect(
        sessionId,
        stream,
        protoResult,
        tlsResult
      );

      allFindings.push(...findings);
      allAnomalies.push(...anomalies);

      if (protocolCounts[protoResult.protocol] !== undefined) {
        protocolCounts[protoResult.protocol]++;
      }
      if (verdictCounts[protoResult.starttlsVerdict] !== undefined) {
        verdictCounts[protoResult.starttlsVerdict]++;
      }

      sessions.push({
        id: sessionId,
        protocol: protoResult.protocol,
        clientIp: stream.clientIp,
        clientPort: stream.clientPort,
        serverIp: stream.serverIp,
        serverPort: stream.serverPort,
        startTimeEpoch: stream.startTime,
        endTimeEpoch: stream.endTime,
        durationMs: Math.max(0, stream.endTime - stream.startTime),
        packetCount: stream.packets.length,
        bytesCount: stream.packets.reduce((acc, p) => acc + p.capturedLength, 0),
        streamKey: stream.streamKey,
        starttlsVerdict: protoResult.starttlsVerdict,
        starttlsNegotiated: protoResult.starttlsNegotiated,
        starttlsStripped: protoResult.starttlsStripped,
        tlsVersion: tlsResult?.negotiatedVersion,
        tlsCipherSuiteId: tlsResult?.selectedCipherSuite?.id,
        tlsCipherSuiteName: tlsResult?.selectedCipherSuite?.name,
        cipherDetails: tlsResult?.selectedCipherSuite,
        certificate: certInfo,
        serverBanner: protoResult.serverBanner,
        clientHelloSni: tlsResult?.clientSni,
        clientHelloSupportedVersions: tlsResult?.clientOfferedVersions,
        findings,
        anomalies,
        timeline: protoResult.timeline,
        conversation: stream.turns,
        credentialsExposed: protoResult.credentialsExposed,
      });
    }

    // Risk scoring
    const risk = RiskScorer.calculate(allFindings, allAnomalies, sessions.length);

    const summary: CaseSummary = {
      totalSessions: sessions.length,
      protocolCounts,
      verdictCounts,
      severityCounts: risk.severityCounts,
      totalFindings: allFindings.length,
      totalAnomalies: allAnomalies.length,
      criticalSessions: sessions.filter((s) => s.findings.some((f) => f.severity === 'CRITICAL')).length,
      highestCvss: risk.highestCvss,
      riskScore: risk.overallScore,
      riskLevel: risk.riskLevel,
    };

    const riskAssessment: RiskAssessment = {
      overallScore: risk.overallScore,
      riskLevel: risk.riskLevel,
      summary: `Forensic audit inspected ${sessions.length} session(s) containing ${allFindings.length} security finding(s) and ${allAnomalies.length} anomaly event(s). Primary threat indicators: ${
        risk.severityCounts.CRITICAL
      } Critical, ${risk.severityCounts.HIGH} High.`,
      isAiGenerated: false,
      aiVerified: false,
      aiClaimsChecked: false,
      fallbackUsed: true,
      remediationPlan: this.buildRemediationPlan(allFindings),
    };

    return {
      pcapMetadata,
      fileSha256,
      fileSizeBytes,
      packetsCount: decodedPackets.length,
      sessions,
      findings: allFindings,
      anomalies: allAnomalies,
      summary,
      riskAssessment,
    };
  }

  private static buildRemediationPlan(findings: Finding[]): string[] {
    const plan = new Set<string>();
    for (const f of findings) {
      if (f.remediation) {
        plan.add(f.remediation);
      }
    }
    return Array.from(plan);
  }
}
