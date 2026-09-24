import { CaseRecord } from '../../shared/types.ts';
import { ForensicAnalyzer } from '../engine/analyzer.ts';
import { CaseRepository } from '../storage/repository.ts';
import { AuditService } from '../storage/audit-service.ts';
import crypto from 'crypto';

export interface AnalysisJob {
  id: string;
  caseId: string;
  filename: string;
  fileSizeBytes: number;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  progress: number;
  error?: string;
}

export class AnalysisQueue {
  private static jobs = new Map<string, AnalysisJob>();

  public static enqueue(
    pcapBuffer: Uint8Array,
    filename: string,
    actor = 'admin'
  ): { job: AnalysisJob; caseRecord: CaseRecord } {
    const caseId = `case-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
    const jobId = `job-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
    const fileSha256 = crypto.createHash('sha256').update(pcapBuffer).digest('hex');

    const caseRecord: CaseRecord = {
      id: caseId,
      name: filename.replace(/\.[^/.]+$/, '').replace(/[_-]/g, ' '),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      filename,
      fileSizeBytes: pcapBuffer.length,
      fileSha256,
      packetCount: 0,
      status: 'PROCESSING',
      progressPercent: 15,
      statusMessage: 'Initiating binary packet stream decoding...',
    };

    const job: AnalysisJob = {
      id: jobId,
      caseId,
      filename,
      fileSizeBytes: pcapBuffer.length,
      status: 'PROCESSING',
      progress: 15,
    };

    this.jobs.set(jobId, job);

    AuditService.log(
      actor,
      'ANALYST',
      'ENQUEUE_ANALYSIS',
      `Uploaded file "${filename}" (${(pcapBuffer.length / 1024).toFixed(1)} KB, SHA256: ${fileSha256.substring(
        0,
        12
      )}...)`,
      caseId
    );

    // Run processing
    try {
      job.progress = 40;
      caseRecord.progressPercent = 40;
      caseRecord.statusMessage = 'Reassembling TCP streams & email protocol state machines...';

      const analysis = ForensicAnalyzer.analyze(pcapBuffer);

      job.progress = 85;
      caseRecord.progressPercent = 85;
      caseRecord.statusMessage = 'Evaluating cryptographic rules, X.509 certs, and anomalies...';

      caseRecord.packetCount = analysis.packetsCount;
      caseRecord.summary = analysis.summary;
      caseRecord.riskAssessment = analysis.riskAssessment;
      caseRecord.status = 'COMPLETED';
      caseRecord.progressPercent = 100;
      caseRecord.statusMessage = 'Analysis finished successfully.';
      caseRecord.updatedAt = Date.now();

      job.status = 'COMPLETED';
      job.progress = 100;

      CaseRepository.saveCase(caseRecord, analysis, pcapBuffer);

      AuditService.log(
        actor,
        'ANALYST',
        'ANALYSIS_COMPLETED',
        `Analysis completed for case "${caseRecord.name}". Sessions: ${analysis.sessions.length}, Findings: ${analysis.findings.length}, Risk: ${analysis.summary.riskLevel}`,
        caseId
      );
    } catch (err: any) {
      job.status = 'FAILED';
      job.error = err.message || 'PCAP analysis failed';
      caseRecord.status = 'FAILED';
      caseRecord.errorMessage = job.error;
      caseRecord.statusMessage = `Failed: ${job.error}`;

      AuditService.log(
        actor,
        'ANALYST',
        'ANALYSIS_FAILED',
        `Analysis failed for file "${filename}": ${job.error}`,
        caseId
      );
    }

    return { job, caseRecord };
  }

  public static getJob(jobId: string): AnalysisJob | undefined {
    return this.jobs.get(jobId);
  }
}
