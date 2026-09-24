import { GoogleGenAI, Type } from '@google/genai';
import { SessionMetadata, Finding, RiskAssessment } from '../../shared/types.ts';
import { EvidencePacketer } from './evidence-packeter.ts';
import { ClaimChecker, AiExplanationPayload } from './claim-checker.ts';
import { DeterministicFallback } from './deterministic-fallback.ts';

export class GeminiRiskAdapter {
  private static client: GoogleGenAI | null = null;

  private static getClient(): GoogleGenAI | null {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
      return null;
    }
    if (!this.client) {
      this.client = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
    }
    return this.client;
  }

  public static async analyzeRisk(
    sessions: SessionMetadata[],
    findings: Finding[]
  ): Promise<RiskAssessment> {
    const fallbackData = DeterministicFallback.generateExplanation(sessions, findings);
    const client = this.getClient();

    if (!client) {
      return {
        overallScore: Math.min(100, findings.reduce((max, f) => Math.max(max, f.cvssScore * 10), 0)),
        riskLevel: findings.some((f) => f.severity === 'CRITICAL')
          ? 'CRITICAL'
          : findings.some((f) => f.severity === 'HIGH')
          ? 'HIGH'
          : 'CLEAN',
        summary: fallbackData.executiveSummary,
        aiReasoning: fallbackData.threatEvaluation,
        isAiGenerated: false,
        aiVerified: false,
        aiClaimsChecked: true,
        fallbackUsed: true,
        claimsVerificationNotes: ['GEMINI_API_KEY not configured. Deterministic forensic rules applied.'],
        remediationPlan: fallbackData.remediationSteps,
      };
    }

    try {
      const packet = EvidencePacketer.createPacket(sessions, true);
      const promptText = `You are a forensic threat intelligence auditor evaluating network PCAP extractions for email security protocols (SMTP, IMAP, POP3) over TLS and STARTTLS.
Given the verified cryptographic evidence packet below, produce a JSON risk evaluation.
CRITICAL CONSTRAINT: You MUST cite only the exact session IDs, cipher names, and TLS versions present in the provided evidence. DO NOT hallucinate nonexistent algorithms or session numbers.

Evidence Packet:
${JSON.stringify(packet, null, 2)}`;

      const response = await client.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: promptText,
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              executiveSummary: { type: Type.STRING },
              threatEvaluation: { type: Type.STRING },
              affectedSessions: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
              citedCiphers: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
              citedTlsVersions: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
              remediationSteps: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
            },
            required: ['executiveSummary', 'threatEvaluation', 'affectedSessions', 'remediationSteps'],
          },
        },
      });

      const jsonText = response.text ? response.text.trim() : '';
      if (!jsonText) {
        throw new Error('Empty response received from Gemini model');
      }

      const parsed: AiExplanationPayload = JSON.parse(jsonText);

      // Run rigorous claim verification
      const check = ClaimChecker.verifyClaims(parsed, sessions);

      if (!check.verified) {
        // Hallucination detected: engage deterministic fallback
        return {
          overallScore: Math.min(100, findings.reduce((max, f) => Math.max(max, f.cvssScore * 10), 0)),
          riskLevel: findings.some((f) => f.severity === 'CRITICAL')
            ? 'CRITICAL'
            : findings.some((f) => f.severity === 'HIGH')
            ? 'HIGH'
            : 'CLEAN',
          summary: fallbackData.executiveSummary,
          aiReasoning: `${fallbackData.threatEvaluation} (Note: Raw model proposal was rejected due to ground-truth claim check errors: ${check.errors.join('; ')})`,
          isAiGenerated: false,
          aiVerified: false,
          aiClaimsChecked: true,
          fallbackUsed: true,
          claimsVerificationNotes: check.errors,
          remediationPlan: fallbackData.remediationSteps,
        };
      }

      return {
        overallScore: Math.min(100, findings.reduce((max, f) => Math.max(max, f.cvssScore * 10), 0)),
        riskLevel: findings.some((f) => f.severity === 'CRITICAL')
          ? 'CRITICAL'
          : findings.some((f) => f.severity === 'HIGH')
          ? 'HIGH'
          : 'CLEAN',
        summary: parsed.executiveSummary,
        aiReasoning: parsed.threatEvaluation,
        isAiGenerated: true,
        aiVerified: true,
        aiClaimsChecked: true,
        fallbackUsed: false,
        claimsVerificationNotes: ['All citations cryptographically and contextually verified against PCAP extraction ground-truth.'],
        remediationPlan: parsed.remediationSteps,
      };
    } catch (e: any) {
      console.warn('Gemini analysis error, engaging deterministic fallback:', e.message);
      return {
        overallScore: Math.min(100, findings.reduce((max, f) => Math.max(max, f.cvssScore * 10), 0)),
        riskLevel: findings.some((f) => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
        summary: fallbackData.executiveSummary,
        aiReasoning: fallbackData.threatEvaluation,
        isAiGenerated: false,
        aiVerified: false,
        aiClaimsChecked: false,
        fallbackUsed: true,
        claimsVerificationNotes: [`Model call failed: ${e.message}. Fallback engaged.`],
        remediationPlan: fallbackData.remediationSteps,
      };
    }
  }
}
