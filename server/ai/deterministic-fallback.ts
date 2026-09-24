import { SessionMetadata, Finding, RiskAssessment } from '../../shared/types.ts';
import { AiExplanationPayload } from './claim-checker.ts';

export class DeterministicFallback {
  public static generateExplanation(
    sessions: SessionMetadata[],
    findings: Finding[]
  ): AiExplanationPayload {
    const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL');
    const highFindings = findings.filter((f) => f.severity === 'HIGH');

    const affectedSessionSet = new Set<string>();
    const citedCiphers = new Set<string>();
    const citedVersions = new Set<string>();

    for (const f of findings) {
      if (f.affectedSessionId) affectedSessionSet.add(f.affectedSessionId);
    }

    for (const s of sessions) {
      if (s.tlsCipherSuiteName) citedCiphers.add(s.tlsCipherSuiteName);
      if (s.tlsVersion) citedVersions.add(s.tlsVersion);
    }

    let summaryText = `Deterministic cryptographic analysis evaluated ${sessions.length} network email session(s). `;
    if (criticalFindings.length > 0) {
      summaryText += `Identified ${criticalFindings.length} CRITICAL vulnerability indicator(s), including ${criticalFindings
        .map((c) => c.title)
        .slice(0, 2)
        .join(' and ')}. Immediate network mitigation required.`;
    } else if (highFindings.length > 0) {
      summaryText += `Identified ${highFindings.length} HIGH severity risk(s). Connections exhibit deprecated cryptographic configurations or invalid certificates.`;
    } else {
      summaryText += `No Critical or High severity threats detected. All sessions adhere to modern cryptographic and protocol requirements.`;
    }

    const threatDetails: string[] = [];
    const strippedSess = sessions.filter((s) => s.starttlsStripped);
    if (strippedSess.length > 0) {
      threatDetails.push(
        `Active or passive STARTTLS degradation observed in ${strippedSess.length} session(s) (${strippedSess
          .map((s) => s.id)
          .join(', ')}). Mail protocols were coerced into cleartext command/credential transmission.`
      );
    }

    const weakTlsSess = sessions.filter(
      (s) => s.tlsVersion === 'SSLv3.0' || s.tlsVersion === 'TLSv1.0' || s.tlsVersion === 'TLSv1.1'
    );
    if (weakTlsSess.length > 0) {
      threatDetails.push(
        `Deprecated protocol versions (${weakTlsSess.map((s) => s.tlsVersion).join(', ')}) active on ${
          weakTlsSess.length
        } session(s), susceptible to historical cipher-downgrade attacks.`
      );
    }

    const remediation: string[] = [];
    if (strippedSess.length > 0) {
      remediation.push('Deploy MTA-STS (RFC 8461) and DANE (RFC 7672) to cryptographically bind TLS requirement to domain DNS.');
      remediation.push('Configure mail transfer agents (MTAs) to reject unencrypted fallback on all submission endpoints.');
    }
    if (weakTlsSess.length > 0) {
      remediation.push('Enforce minimum TLS 1.2 across all mail services; disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1.');
    }
    remediation.push('Replace weak ciphers (RC4, 3DES, static RSA) with AEAD ciphers supporting Perfect Forward Secrecy (PFS).');
    remediation.push('Ensure valid certificates issued by reputable CAs with minimum 2048-bit RSA or 256-bit ECDSA keys.');

    return {
      executiveSummary: summaryText,
      threatEvaluation: threatDetails.join(' ') || 'Standard baseline security maintained.',
      affectedSessions: Array.from(affectedSessionSet),
      citedCiphers: Array.from(citedCiphers),
      citedTlsVersions: Array.from(citedVersions),
      remediationSteps: remediation,
    };
  }
}
