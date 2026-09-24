import { Finding, Anomaly, RiskAssessment, FindingSeverity } from '../../../shared/types.ts';

export class RiskScorer {
  public static calculate(
    findings: Finding[],
    anomalies: Anomaly[],
    totalSessions: number
  ): {
    overallScore: number;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
    highestCvss: number;
    severityCounts: Record<FindingSeverity, number>;
  } {
    const severityCounts: Record<FindingSeverity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFORMATIONAL: 0,
    };

    let maxCvss = 0;

    for (const f of findings) {
      if (severityCounts[f.severity] !== undefined) {
        severityCounts[f.severity]++;
      }
      if (f.cvssScore > maxCvss) {
        maxCvss = f.cvssScore;
      }
    }

    // Weight formula
    // Critical: 25 pts each, High: 15 pts each, Medium: 8 pts each, Low: 3 pts each
    let rawScore =
      severityCounts.CRITICAL * 28 +
      severityCounts.HIGH * 16 +
      severityCounts.MEDIUM * 8 +
      severityCounts.LOW * 3 +
      anomalies.length * 4;

    if (totalSessions > 0) {
      // Normalize but keep high if critical findings exist
      if (severityCounts.CRITICAL > 0) {
        rawScore = Math.max(rawScore, 85 + severityCounts.CRITICAL * 3);
      } else if (severityCounts.HIGH > 0) {
        rawScore = Math.max(rawScore, 65 + severityCounts.HIGH * 4);
      }
    }

    const overallScore = Math.min(100, Math.round(rawScore));

    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN' = 'CLEAN';
    if (overallScore >= 80 || severityCounts.CRITICAL > 0) {
      riskLevel = 'CRITICAL';
    } else if (overallScore >= 60 || severityCounts.HIGH > 0) {
      riskLevel = 'HIGH';
    } else if (overallScore >= 35 || severityCounts.MEDIUM > 0) {
      riskLevel = 'MEDIUM';
    } else if (overallScore > 0 || severityCounts.LOW > 0) {
      riskLevel = 'LOW';
    } else {
      riskLevel = 'CLEAN';
    }

    return {
      overallScore,
      riskLevel,
      highestCvss: maxCvss,
      severityCounts,
    };
  }
}
