import { test, describe } from 'node:test';
import assert from 'node:assert';
import { DemoPcapGenerator } from '../server/engine/datalab/demo-pcap-generator.ts';
import { ForensicAnalyzer } from '../server/engine/analyzer.ts';
import { PcapReader } from '../server/engine/pcap/pcap-reader.ts';
import { CipherRegistry } from '../server/engine/tls/cipher-registry.ts';

describe('SIH26159 Engine & Forensic Analysis Pipeline Tests', () => {
  test('PcapReader rejects invalid and empty files safely', () => {
    // 1. Empty buffer
    assert.throws(() => {
      PcapReader.parse(new Uint8Array(0));
    }, /Empty PCAP buffer/);

    // 2. Text file renamed to .pcap
    const textBuffer = new TextEncoder().encode('This is not a PCAP file at all. Just random text!');
    assert.throws(() => {
      PcapReader.parse(textBuffer);
    }, /Invalid PCAP magic/);

    // 3. Short buffer < 24 bytes
    assert.throws(() => {
      PcapReader.parse(new Uint8Array([0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02]));
    }, /Truncated PCAP header/);
  });

  test('CipherRegistry accurately classifies modern vs broken suites', () => {
    // TLS 1.3 AES-256-GCM
    const aes256Gcm = CipherRegistry.lookup(0x1302);
    assert.strictEqual(aes256Gcm.name, 'TLS_AES_256_GCM_SHA384');
    assert.strictEqual(aes256Gcm.securityStatus, 'SECURE');
    assert.strictEqual(aes256Gcm.pfs, true);

    // RC4 128 SHA
    const rc4Sha = CipherRegistry.lookup(0x0005);
    assert.strictEqual(rc4Sha.name, 'TLS_RSA_WITH_RC4_128_SHA');
    assert.strictEqual(rc4Sha.securityStatus, 'BROKEN');
    assert.strictEqual(rc4Sha.pfs, false);

    // 3DES EDE CBC
    const tripleDes = CipherRegistry.lookup(0x000a);
    assert.strictEqual(tripleDes.securityStatus, 'INSECURE');
    assert.strictEqual(tripleDes.pfs, false);
  });

  test('Demo PCAP generation and end-to-end forensic analysis pipeline', () => {
    const pcapBytes = DemoPcapGenerator.generateFullDemoPcap();
    assert.ok(pcapBytes.length > 500, 'PCAP buffer should have substantial byte length');

    // Run real forensic analysis pipeline
    const result = ForensicAnalyzer.analyze(pcapBytes);

    assert.ok(result.sessions.length >= 5, `Expected at least 5 sessions, got ${result.sessions.length}`);
    assert.ok(result.findings.length > 0, 'Should detect forensic findings');
    assert.ok(result.anomalies.length > 0, 'Should detect anomaly events');

    // --- Assert Scenario 1: Secure TLS 1.3 SMTP ---
    const s1 = result.sessions.find((s) => s.serverPort === 587 && s.clientPort === 49201);
    assert.ok(s1, 'Scenario 1 session must exist');
    assert.strictEqual(s1.protocol, 'SMTP');
    assert.strictEqual(s1.starttlsVerdict, 'clean_starttls');
    assert.strictEqual(s1.tlsVersion, 'TLSv1.3');
    assert.strictEqual(s1.tlsCipherSuiteName, 'TLS_AES_256_GCM_SHA384');
    // Ensure no high or critical findings on secure session
    const s1HighCrit = s1.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    assert.strictEqual(s1HighCrit.length, 0, 'Secure TLS 1.3 session must yield 0 High/Critical findings');

    // --- Assert Scenario 2: Stripped STARTTLS MITM ---
    const s2 = result.sessions.find((s) => s.clientIp === '172.16.5.12' && s.serverPort === 25);
    assert.ok(s2, 'Scenario 2 session must exist');
    assert.strictEqual(s2.starttlsVerdict, 'ack_without_tls');
    assert.strictEqual(s2.starttlsStripped, true);
    // Must trigger R-STARTTLS-STRIPPED and R-AUTH-CLEARTEXT
    const s2StrippedFinding = s2.findings.find((f) => f.ruleId === 'R-STARTTLS-STRIPPED');
    assert.ok(s2StrippedFinding, 'Stripped session must yield R-STARTTLS-STRIPPED');
    assert.strictEqual(s2StrippedFinding.severity, 'CRITICAL');
    assert.ok(s2StrippedFinding.evidence.length > 0, 'Finding must cite evidence');

    // --- Assert Scenario 3: Legacy TLS 1.0 + RC4 + Expired Self-Signed 1024-bit RSA ---
    const s3 = result.sessions.find((s) => s.clientIp === '10.10.4.19');
    assert.ok(s3, 'Scenario 3 session must exist');
    assert.strictEqual(s3.tlsVersion, 'TLSv1.0');
    assert.strictEqual(s3.tlsCipherSuiteName, 'TLS_RSA_WITH_RC4_128_SHA');

    // Assert findings list
    const s3RuleIds = s3.findings.map((f) => f.ruleId);
    assert.ok(s3RuleIds.includes('R-TLS-VER-DEPRECATED'), 'Must flag deprecated TLS 1.0');
    assert.ok(s3RuleIds.includes('R-CIPH-BROKEN'), 'Must flag broken RC4 cipher');
    assert.ok(s3RuleIds.includes('R-CIPH-NO-PFS'), 'Must flag missing forward secrecy');
    assert.ok(s3RuleIds.includes('R-CERT-EXPIRED'), 'Must flag expired certificate');
    assert.ok(s3RuleIds.includes('R-CERT-WEAK-KEY'), 'Must flag weak RSA key length');
    assert.ok(s3RuleIds.includes('R-CERT-SELF-SIGNED'), 'Must flag self-signed certificate');

    // --- Assert Scenario 4: IMAP Cleartext Login on Port 143 ---
    const s4 = result.sessions.find((s) => s.clientIp === '192.168.2.80');
    assert.ok(s4, 'Scenario 4 session must exist');
    assert.strictEqual(s4.protocol, 'IMAP');
    assert.strictEqual(s4.starttlsVerdict, 'missing_starttls_in_caps');
    const s4AuthFinding = s4.findings.find((f) => f.ruleId === 'R-AUTH-CLEARTEXT');
    assert.ok(s4AuthFinding, 'Must flag cleartext IMAP credential exposure');
    assert.strictEqual(s4AuthFinding.severity, 'CRITICAL');

    // --- Assert Scenario 5: TLS Handshake Alert ---
    const s5 = result.sessions.find((s) => s.clientIp === '192.168.3.11');
    assert.ok(s5, 'Scenario 5 session must exist');
    const s5AlertFinding = s5.findings.find((f) => f.ruleId === 'R-ALERT-FATAL');
    assert.ok(s5AlertFinding, 'Must flag fatal TLS alert');

    // Assert Overall Risk
    assert.strictEqual(result.summary.riskLevel, 'CRITICAL');
    assert.ok(result.summary.riskScore >= 90);
  });
});
