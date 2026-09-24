import {
  CaseRecord,
  SessionMetadata,
  Finding,
  Anomaly,
  UserProfile,
} from '../../shared/types.ts';
import { AnalysisPipelineResult, ForensicAnalyzer } from '../engine/analyzer.ts';
import { DemoPcapGenerator } from '../engine/datalab/demo-pcap-generator.ts';
import { AuditService } from './audit-service.ts';

export interface StoredCase {
  record: CaseRecord;
  analysis: AnalysisPipelineResult;
  pcapBuffer: Uint8Array;
}

export class CaseRepository {
  private static cases = new Map<string, StoredCase>();
  private static activeCaseId: string | null = null;

  public static initializeWithDemo() {
    if (this.cases.size > 0) return;

    try {
      const demoPcap = DemoPcapGenerator.generateFullDemoPcap();
      const analysis = ForensicAnalyzer.analyze(demoPcap);
      const caseId = 'case-demo-gold-001';

      const record: CaseRecord = {
        id: caseId,
        name: 'Enterprise Protocol Audit & Threat Trace #2026-09A',
        createdAt: Date.now() - 3600000,
        updatedAt: Date.now(),
        filename: 'incident_audit_trace.pcap',
        fileSizeBytes: demoPcap.length,
        fileSha256: analysis.fileSha256,
        packetCount: analysis.packetsCount,
        status: 'COMPLETED',
        progressPercent: 100,
        statusMessage: 'Forensic inspection completed.',
        summary: analysis.summary,
        riskAssessment: analysis.riskAssessment,
      };

      this.cases.set(caseId, {
        record,
        analysis,
        pcapBuffer: demoPcap,
      });

      this.activeCaseId = caseId;

      AuditService.log(
        'system',
        'SYSTEM',
        'INIT_AUDIT_TRACE',
        `Initialized baseline enterprise forensic case "${record.name}" with multi-vector protocol inspection.`,
        caseId
      );
    } catch (e: any) {
      console.error('Failed to initialize demo case:', e);
    }
  }

  public static listCases(): CaseRecord[] {
    return Array.from(this.cases.values()).map((c) => c.record);
  }

  public static getCase(id: string): StoredCase | undefined {
    return this.cases.get(id);
  }

  public static getActiveCaseId(): string | null {
    return this.activeCaseId || (this.cases.size > 0 ? this.cases.keys().next().value || null : null);
  }

  public static setActiveCaseId(id: string) {
    if (this.cases.has(id)) {
      this.activeCaseId = id;
    }
  }

  public static saveCase(
    caseRecord: CaseRecord,
    analysis: AnalysisPipelineResult,
    pcapBuffer: Uint8Array
  ) {
    this.cases.set(caseRecord.id, {
      record: caseRecord,
      analysis,
      pcapBuffer,
    });
    this.activeCaseId = caseRecord.id;
  }

  public static deleteCase(id: string): boolean {
    const deleted = this.cases.delete(id);
    if (deleted && this.activeCaseId === id) {
      this.activeCaseId = this.cases.keys().next().value || null;
    }
    return deleted;
  }
}
