import {
  Finding,
  EvidenceRef,
  CertificateInfo,
  CipherDetails,
  StarttlsVerdict,
} from '../../../shared/types.ts';
import { RULE_CATALOG, RuleDefinition } from './rule-catalog.ts';
import { ProtocolAnalysisResult } from '../protocol/starttls-state-machine.ts';
import { ParsedTlsSession } from '../tls/tls-parser.ts';
import { ReassembledStream } from '../reassembly/tcp-reassembler.ts';

export class RuleEngine {
  public static evaluateSession(
    sessionId: string,
    stream: ReassembledStream,
    protoResult: ProtocolAnalysisResult,
    tlsResult?: ParsedTlsSession,
    certInfo?: CertificateInfo
  ): Finding[] {
    const findings: Finding[] = [];
    const firstPkt = stream.packets[0];
    const defaultFrame = firstPkt ? firstPkt.frameNumber : 1;
    const defaultTs = firstPkt ? firstPkt.timestampEpochMs : Date.now();

    // 1. Check STARTTLS Stripping / Downgrades
    if (protoResult.starttlsStripped) {
      const rule = RULE_CATALOG['R-STARTTLS-STRIPPED'];
      if (rule && rule.enabled) {
        const evidenceTurn = stream.turns.find(
          (t) =>
            t.text.toUpperCase().includes('STARTTLS') ||
            t.text.toUpperCase().includes('250') ||
            t.text.toUpperCase().includes('MAIL FROM')
        );

        findings.push(
          this.createFinding(rule, sessionId, {
            frameNumber: evidenceTurn ? evidenceTurn.frameNumber : defaultFrame,
            timestamp: evidenceTurn ? evidenceTurn.timestamp : defaultTs,
            streamKey: stream.streamKey,
            byteOffset: 0,
            length: 32,
            snippetHex: '53 54 41 52 54 54 4c 53',
            snippetAscii: evidenceTurn ? evidenceTurn.text.substring(0, 48) : 'STARTTLS stripped',
            description: `STARTTLS stripping detected (${protoResult.starttlsVerdict}). Plaintext commands followed instead of TLS handshake.`,
          })
        );
      }
    }

    // 2. Check Cleartext Credentials Exposure
    if (protoResult.credentialsExposed) {
      const rule = RULE_CATALOG['R-AUTH-CLEARTEXT'];
      if (rule && rule.enabled) {
        findings.push(
          this.createFinding(
            rule,
            sessionId,
            protoResult.credentialsExposed.evidence,
            `User "${protoResult.credentialsExposed.username || 'unknown'}" credentials exposed via cleartext ${
              protoResult.credentialsExposed.type
            }.`
          )
        );
      }
    }

    // 3. Check Deprecated TLS Version
    if (tlsResult && tlsResult.negotiatedVersion) {
      const ver = tlsResult.negotiatedVersion;
      if (ver === 'SSLv2.0' || ver === 'SSLv3.0' || ver === 'TLSv1.0' || ver === 'TLSv1.1') {
        const rule = RULE_CATALOG['R-TLS-VER-DEPRECATED'];
        if (rule && rule.enabled) {
          const sHelloTurn = stream.turns.find(
            (t) => t.isTls && t.tlsContentType === 22 && t.tlsHandshakeType === 2
          );
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: sHelloTurn ? sHelloTurn.frameNumber : defaultFrame,
                timestamp: sHelloTurn ? sHelloTurn.timestamp : defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 2,
                snippetHex: ver === 'TLSv1.0' ? '03 01' : ver === 'TLSv1.1' ? '03 02' : '03 00',
                snippetAscii: `Server negotiated version: ${ver}`,
                description: `Negotiated ${ver} which was formally deprecated by RFC 8996.`,
              },
              `Deprecated protocol version ${ver} negotiated in ServerHello.`
            )
          );
        }
      }
    }

    // 4. Check Cipher Suite Security Status
    if (tlsResult && tlsResult.selectedCipherSuite) {
      const cipher = tlsResult.selectedCipherSuite;

      // Broken / Prohibited Cipher
      if (cipher.securityStatus === 'BROKEN' || cipher.securityStatus === 'INSECURE') {
        const rule = RULE_CATALOG['R-CIPH-BROKEN'];
        if (rule && rule.enabled) {
          const sHelloTurn = stream.turns.find(
            (t) => t.isTls && t.tlsContentType === 22 && t.tlsHandshakeType === 2
          );
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: sHelloTurn ? sHelloTurn.frameNumber : defaultFrame,
                timestamp: sHelloTurn ? sHelloTurn.timestamp : defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 2,
                snippetHex: cipher.id,
                snippetAscii: cipher.name,
                description: `Server selected ${cipher.name} (${cipher.id}): ${cipher.reasons.join('; ')}`,
              },
              `Broken cipher suite ${cipher.name} selected. ${cipher.reasons[0] || ''}`
            )
          );
        }
      }

      // Missing Forward Secrecy
      if (!cipher.pfs) {
        const rule = RULE_CATALOG['R-CIPH-NO-PFS'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 2,
                snippetHex: cipher.id,
                snippetAscii: cipher.name,
                description: `Selected cipher ${cipher.name} relies on static RSA key exchange without PFS.`,
              }
            )
          );
        }
      }

      // Weak CBC mode with SHA-1
      if (cipher.securityStatus === 'WEAK' && cipher.encryption.includes('CBC')) {
        const rule = RULE_CATALOG['R-CIPH-CBC-WEAK'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 2,
                snippetHex: cipher.id,
                snippetAscii: cipher.name,
                description: `Cipher ${cipher.name} uses CBC mode and SHA-1 HMAC.`,
              }
            )
          );
        }
      }
    }

    // 5. Certificate Flaws
    if (certInfo) {
      if (certInfo.isExpired) {
        const rule = RULE_CATALOG['R-CERT-EXPIRED'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 16,
                snippetHex: certInfo.serialNumber.replace(/:/g, ' '),
                snippetAscii: `ValidTo: ${certInfo.validTo}`,
                description: `Certificate expired on ${certInfo.validTo}. Days expired: ${Math.abs(
                  certInfo.daysRemaining
                )}.`,
              },
              `Certificate presented for ${certInfo.subject} expired on ${certInfo.validTo}.`
            )
          );
        }
      }

      if (certInfo.isNotYetValid) {
        const rule = RULE_CATALOG['R-CERT-NOT-YET-VALID'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 16,
                snippetHex: certInfo.serialNumber.replace(/:/g, ' '),
                snippetAscii: `ValidFrom: ${certInfo.validFrom}`,
                description: `Certificate is not valid until ${certInfo.validFrom}.`,
              }
            )
          );
        }
      }

      if (certInfo.keyAlgorithm === 'RSA' && certInfo.keyLength < 2048) {
        const rule = RULE_CATALOG['R-CERT-WEAK-KEY'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 4,
                snippetHex: '04 00',
                snippetAscii: `RSA Modulus: ${certInfo.keyLength} bits`,
                description: `Server certificate RSA key modulus is ${certInfo.keyLength} bits, falling below the mandatory 2048-bit threshold.`,
              },
              `Weak RSA key length (${certInfo.keyLength} bits) found on ${certInfo.subject}.`
            )
          );
        }
      }

      if (
        certInfo.signatureAlgorithm.toLowerCase().includes('sha1') ||
        certInfo.signatureAlgorithm.toLowerCase().includes('md5')
      ) {
        const rule = RULE_CATALOG['R-CERT-WEAK-SIG'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 8,
                snippetHex: '2a 86 48 86 f7 0d 01 01',
                snippetAscii: certInfo.signatureAlgorithm,
                description: `Certificate signed with weak digest algorithm: ${certInfo.signatureAlgorithm}.`,
              }
            )
          );
        }
      }

      if (certInfo.isSelfSigned) {
        const rule = RULE_CATALOG['R-CERT-SELF-SIGNED'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 16,
                snippetHex: certInfo.serialNumber.replace(/:/g, ' '),
                snippetAscii: `Subject=Issuer: ${certInfo.subject}`,
                description: `Certificate is self-signed: Subject matches Issuer (${certInfo.subject}).`,
              }
            )
          );
        }
      }
    }

    // 6. Fatal Alerts
    if (tlsResult && tlsResult.alerts.length > 0) {
      const fatalAlert = tlsResult.alerts.find((a) => a.level === 'fatal');
      if (fatalAlert) {
        const rule = RULE_CATALOG['R-ALERT-FATAL'];
        if (rule && rule.enabled) {
          findings.push(
            this.createFinding(
              rule,
              sessionId,
              {
                frameNumber: defaultFrame,
                timestamp: defaultTs,
                streamKey: stream.streamKey,
                byteOffset: 0,
                length: 2,
                snippetHex: `02 ${fatalAlert.code.toString(16).padStart(2, '0')}`,
                snippetAscii: `Alert: ${fatalAlert.description}`,
                description: `Fatal TLS alert received: ${fatalAlert.description} (code ${fatalAlert.code}). Handshake aborted.`,
              },
              `Fatal TLS Alert (${fatalAlert.description}) terminated connection.`
            )
          );
        }
      }
    }

    return findings;
  }

  private static createFinding(
    rule: RuleDefinition,
    affectedSessionId: string,
    evidence: EvidenceRef,
    customDescription?: string
  ): Finding {
    return {
      id: `find-${rule.id.toLowerCase()}-${Math.random().toString(36).substring(2, 8)}`,
      ruleId: rule.id,
      title: rule.name,
      severity: rule.defaultSeverity,
      category: rule.category,
      affectedSessionId,
      description: customDescription || rule.descriptionTemplate,
      impact: rule.impactTemplate,
      remediation: rule.remediationTemplate,
      cvssScore: rule.cvssBaseScore,
      evidence: [evidence],
    };
  }
}
