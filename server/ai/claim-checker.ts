import { SessionMetadata } from '../../shared/types.ts';

export interface AiExplanationPayload {
  executiveSummary: string;
  threatEvaluation: string;
  affectedSessions: string[];
  citedCiphers: string[];
  citedTlsVersions: string[];
  remediationSteps: string[];
}

export class ClaimChecker {
  public static verifyClaims(
    explanation: AiExplanationPayload,
    sessions: SessionMetadata[]
  ): { verified: boolean; errors: string[] } {
    const errors: string[] = [];

    const validSessionIds = new Set(sessions.map((s) => s.id));
    const validCiphers = new Set<string>();
    const validVersions = new Set<string>();

    for (const s of sessions) {
      if (s.tlsCipherSuiteName) validCiphers.add(s.tlsCipherSuiteName);
      if (s.tlsVersion) validVersions.add(s.tlsVersion);
      if (s.clientHelloSupportedVersions) {
        s.clientHelloSupportedVersions.forEach((v) => validVersions.add(v));
      }
    }

    // 1. Verify cited session IDs
    for (const sid of explanation.affectedSessions) {
      if (!validSessionIds.has(sid)) {
        errors.push(`AI hallucination: referenced nonexistent session ID "${sid}".`);
      }
    }

    // 2. Verify cited cipher suites
    for (const cipher of explanation.citedCiphers) {
      // Check if cipher exists in valid ciphers or in standard IANA names present in sessions
      const matched = Array.from(validCiphers).some(
        (vc) => vc.toLowerCase() === cipher.toLowerCase() || vc.includes(cipher) || cipher.includes(vc)
      );
      if (!matched) {
        errors.push(`AI hallucination: cited cipher "${cipher}" was not present in the PCAP capture.`);
      }
    }

    // 3. Verify cited TLS versions
    for (const ver of explanation.citedTlsVersions) {
      const matched = Array.from(validVersions).some((vv) => vv.toLowerCase() === ver.toLowerCase());
      if (!matched) {
        errors.push(`AI hallucination: cited TLS version "${ver}" was not observed in the PCAP capture.`);
      }
    }

    return {
      verified: errors.length === 0,
      errors,
    };
  }
}
