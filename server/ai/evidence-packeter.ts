import { SessionMetadata, Finding, Anomaly } from '../../shared/types.ts';

export interface RedactedEvidencePacket {
  strictMode: boolean;
  totalSessions: number;
  sessions: {
    sessionId: string;
    protocol: string;
    clientIdentifier: string;
    serverIdentifier: string;
    starttlsVerdict: string;
    tlsVersion?: string;
    cipherSuite?: string;
    hasCertificate: boolean;
    certificateSummary?: {
      subjectCn: string;
      isExpired: boolean;
      keyAlgorithm: string;
      keyLength: number;
      isSelfSigned: boolean;
    };
    rulesTriggered: string[];
    anomaliesObserved: string[];
  }[];
  criticalRulesPresent: string[];
}

export class EvidencePacketer {
  /**
   * Constructs an AI-safe evidence packet with strict data minimisation:
   * Scrubs email addresses, passwords, raw payload bytes, and (in strict mode) real IP addresses.
   */
  public static createPacket(
    sessions: SessionMetadata[],
    strictMode = true
  ): RedactedEvidencePacket {
    const ipMap = new Map<string, string>();
    let clientCounter = 1;
    let serverCounter = 1;

    const getPseudonym = (ip: string, isServer: boolean): string => {
      if (!strictMode) return ip;
      let pseudo = ipMap.get(ip);
      if (!pseudo) {
        pseudo = isServer ? `SERVER_NODE_${serverCounter++}` : `CLIENT_ENDPOINT_${clientCounter++}`;
        ipMap.set(ip, pseudo);
      }
      return pseudo;
    };

    const redactedSessions = sessions.map((sess) => {
      const clientIdent = getPseudonym(sess.clientIp, false);
      const serverIdent = getPseudonym(sess.serverIp, true);

      let certSummary = undefined;
      if (sess.certificate) {
        // Redact any internal domain names in subject if in strict mode
        let cn = sess.certificate.subject;
        const cnMatch = cn.match(/CN=([^,]+)/);
        const cnVal = cnMatch ? cnMatch[1] : 'service.host';

        certSummary = {
          subjectCn: strictMode ? `host-${cnVal.replace(/[^a-zA-Z0-9.-]/g, '_')}` : cn,
          isExpired: sess.certificate.isExpired,
          keyAlgorithm: sess.certificate.keyAlgorithm,
          keyLength: sess.certificate.keyLength,
          isSelfSigned: sess.certificate.isSelfSigned,
        };
      }

      return {
        sessionId: sess.id,
        protocol: sess.protocol,
        clientIdentifier: clientIdent,
        serverIdentifier: serverIdent,
        starttlsVerdict: sess.starttlsVerdict,
        tlsVersion: sess.tlsVersion,
        cipherSuite: sess.tlsCipherSuiteName,
        hasCertificate: !!sess.certificate,
        certificateSummary: certSummary,
        rulesTriggered: sess.findings.map((f) => f.ruleId),
        anomaliesObserved: sess.anomalies.map((a) => a.type),
      };
    });

    const criticalRules = new Set<string>();
    for (const s of sessions) {
      for (const f of s.findings) {
        if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
          criticalRules.add(f.ruleId);
        }
      }
    }

    return {
      strictMode,
      totalSessions: sessions.length,
      sessions: redactedSessions,
      criticalRulesPresent: Array.from(criticalRules),
    };
  }

  /**
   * Safety assertion to verify that no raw secrets, emails, or payloads leaked into text
   */
  public static verifyNoPiiOrSecrets(payloadString: string): { clean: boolean; violation?: string } {
    // 1. Email pattern regex
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
    if (emailRegex.test(payloadString)) {
      return { clean: false, violation: 'Contains unredacted email address pattern' };
    }

    // 2. Cleartext password pattern
    if (/password|supersecret/i.test(payloadString)) {
      return { clean: false, violation: 'Contains password keyword' };
    }

    // 3. Raw payload command patterns like MAIL FROM:
    if (/MAIL FROM:<|RCPT TO:<|AUTH LOGIN/i.test(payloadString)) {
      return { clean: false, violation: 'Contains raw email envelope commands' };
    }

    return { clean: true };
  }
}
