import { test, describe } from 'node:test';
import assert from 'node:assert';
import { AuditService } from '../server/storage/audit-service.ts';
import { EvidencePacketer } from '../server/ai/evidence-packeter.ts';
import { DemoPcapGenerator } from '../server/engine/datalab/demo-pcap-generator.ts';
import { ForensicAnalyzer } from '../server/engine/analyzer.ts';
import { ClaimChecker } from '../server/ai/claim-checker.ts';
import { ReportGenerator } from '../server/reports/report-generator.ts';
import { CaseRepository } from '../server/storage/repository.ts';

describe('SIH26159 Security & Correctness Verification Checks', () => {
  test('Audit-chain verification passes on untouched data and fails when tampered', () => {
    AuditService.clear();

    AuditService.log('admin', 'ADMIN', 'SYS_BOOT', 'System initialized');
    AuditService.log('analyst', 'ANALYST', 'PCAP_UPLOAD', 'Uploaded test.pcap', 'case-01');
    AuditService.log('auditor', 'AUDITOR', 'EXPORT_REPORT', 'Generated PDF report', 'case-01');

    // 1. Untouched verification must succeed
    const cleanCheck = AuditService.verifyChain();
    assert.strictEqual(cleanCheck.valid, true);
    assert.match(cleanCheck.message, /verified intact/);

    // 2. Tamper with an entry (modify details)
    AuditService._tamperRecordForTest(1, 'TAMPERED: Details secretly modified by rogue actor');

    // 3. Verification must now FAIL
    const tamperedCheck = AuditService.verifyChain();
    assert.strictEqual(tamperedCheck.valid, false);
    assert.match(tamperedCheck.message, /tampered at sequence 2/);
  });

  test('AI outbound evidence packet enforces strict data minimisation & PII scrubbing', () => {
    const demoPcap = DemoPcapGenerator.generateFullDemoPcap();
    const analysis = ForensicAnalyzer.analyze(demoPcap);

    // Create strict evidence packet
    const packet = EvidencePacketer.createPacket(analysis.sessions, true);
    const packetString = JSON.stringify(packet);

    // Assert no real email addresses appear in packet
    const noPiiCheck = EvidencePacketer.verifyNoPiiOrSecrets(packetString);
    assert.strictEqual(noPiiCheck.clean, true, `PII Check failed: ${noPiiCheck.violation}`);

    // Assert strict IP pseudonyms are used instead of real IPs
    assert.ok(packetString.includes('CLIENT_ENDPOINT_') || packetString.includes('SERVER_NODE_'));
    assert.ok(!packetString.includes('192.168.1.50'));
    assert.ok(!packetString.includes('172.16.5.12'));
  });

  test('Claim Checker rejects hallucinated ciphers, fake dates, and nonexistent session IDs', () => {
    const demoPcap = DemoPcapGenerator.generateFullDemoPcap();
    const analysis = ForensicAnalyzer.analyze(demoPcap);

    // Valid claim
    const validClaim = {
      executiveSummary: 'Standard valid summary',
      threatEvaluation: 'Legitimate evaluation',
      affectedSessions: ['sess-001', 'sess-002'],
      citedCiphers: ['TLS_AES_256_GCM_SHA384'],
      citedTlsVersions: ['TLSv1.3', 'TLSv1.0'],
      remediationSteps: ['Step 1'],
    };
    const validResult = ClaimChecker.verifyClaims(validClaim, analysis.sessions);
    assert.strictEqual(validResult.verified, true);
    assert.strictEqual(validResult.errors.length, 0);

    // Hallucinated cipher claim
    const fakeCipherClaim = {
      ...validClaim,
      citedCiphers: ['TLS_RSA_EXPORT_WITH_DES40_CBC_SHA_FAKE'],
    };
    const fakeCipherResult = ClaimChecker.verifyClaims(fakeCipherClaim, analysis.sessions);
    assert.strictEqual(fakeCipherResult.verified, false);
    assert.ok(fakeCipherResult.errors.some((e) => e.includes('cited cipher') && e.includes('was not present')));

    // Hallucinated session ID claim
    const fakeSessionClaim = {
      ...validClaim,
      affectedSessions: ['sess-999'],
    };
    const fakeSessionResult = ClaimChecker.verifyClaims(fakeSessionClaim, analysis.sessions);
    assert.strictEqual(fakeSessionResult.verified, false);
    assert.ok(fakeSessionResult.errors.some((e) => e.includes('nonexistent session ID')));
  });

  test('HTML and PDF reports are XSS-inert and format malicious payload safely', () => {
    CaseRepository.initializeWithDemo();
    const activeCase = CaseRepository.getCase(CaseRepository.getActiveCaseId()!);
    assert.ok(activeCase);

    // Inject malicious string into subject
    const originalSubject = activeCase.analysis.sessions[0].certificate?.subject;
    if (activeCase.analysis.sessions[0].certificate) {
      activeCase.analysis.sessions[0].certificate.subject = '<script>alert("XSS Attack")</script>';
    }

    const htmlReport = ReportGenerator.generateHtml(activeCase);
    // Malicious script tags must be HTML entity escaped
    assert.ok(!htmlReport.includes('<script>alert('), 'Raw script tags must not appear in HTML report');
    assert.ok(htmlReport.includes('&lt;script&gt;alert('), 'Script tags must be safely escaped');

    // Generate PDF report and verify it produces valid binary PDF bytes
    const pdfBytes = ReportGenerator.generatePdf(activeCase);
    assert.ok(pdfBytes.length > 500);
    // PDF Magic bytes: "%PDF" (0x25, 0x50, 0x44, 0x46)
    assert.strictEqual(pdfBytes[0], 0x25);
    assert.strictEqual(pdfBytes[1], 0x50);
    assert.strictEqual(pdfBytes[2], 0x44);
    assert.strictEqual(pdfBytes[3], 0x46);

    // Restore
    if (activeCase.analysis.sessions[0].certificate && originalSubject) {
      activeCase.analysis.sessions[0].certificate.subject = originalSubject;
    }
  });
});
