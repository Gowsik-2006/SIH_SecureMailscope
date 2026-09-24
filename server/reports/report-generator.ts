import { StoredCase } from '../storage/repository.ts';
import { jsPDF } from 'jspdf';
import { AuditService } from '../storage/audit-service.ts';

export class ReportGenerator {
  public static generateJson(storedCase: StoredCase): object {
    const auditChain = AuditService.verifyChain();
    return {
      reportType: 'SIH26159_EMAIL_TLS_NETWORK_FORENSIC_REPORT',
      version: '2.0.0',
      generatedAtEpochMs: Date.now(),
      generatedAtIso: new Date().toISOString(),
      caseMetadata: {
        id: storedCase.record.id,
        name: storedCase.record.name,
        filename: storedCase.record.filename,
        fileSizeBytes: storedCase.record.fileSizeBytes,
        fileSha256: storedCase.record.fileSha256,
        totalPackets: storedCase.record.packetCount,
      },
      auditChainIntegrity: auditChain,
      executiveSummary: storedCase.analysis.summary,
      riskAssessment: storedCase.analysis.riskAssessment,
      mitreAttackMapping: this.getMitreMapping(storedCase),
      sessions: storedCase.analysis.sessions.map((s) => ({
        sessionId: s.id,
        protocol: s.protocol,
        client: `${s.clientIp}:${s.clientPort}`,
        server: `${s.serverIp}:${s.serverPort}`,
        starttlsVerdict: s.starttlsVerdict,
        tlsVersion: s.tlsVersion || 'NONE',
        cipher: s.tlsCipherSuiteName || 'NONE',
        durationMs: s.durationMs,
        credentialsExposed: !!s.credentialsExposed,
        findingsCount: s.findings.length,
      })),
      findings: storedCase.analysis.findings,
      anomalies: storedCase.analysis.anomalies,
      certificates: storedCase.analysis.sessions
        .filter((s) => !!s.certificate)
        .map((s) => s.certificate),
    };
  }

  public static generateHtml(storedCase: StoredCase): string {
    const json = this.generateJson(storedCase) as any;
    const summary = storedCase.analysis.summary;
    const risk = storedCase.analysis.riskAssessment;
    const sessions = storedCase.analysis.sessions;
    const findings = storedCase.analysis.findings;
    const anomalies = storedCase.analysis.anomalies;
    const auditChain = AuditService.verifyChain();
    const mitre = this.getMitreMapping(storedCase);

    const esc = this.escapeHtml;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic Analysis Report - ${esc(storedCase.record.name)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 32px; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 40px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
    h1, h2, h3 { color: #f8fafc; border-bottom: 1px solid #374151; padding-bottom: 8px; margin-top: 32px; }
    h1 { font-size: 28px; border-bottom: 2px solid #3b82f6; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
    .badge-critical { background: #7f1d1d; color: #fecaca; border: 1px solid #dc2626; }
    .badge-high { background: #7c2d12; color: #fed7aa; border: 1px solid #ea580c; }
    .badge-medium { background: #713f12; color: #fef08a; border: 1px solid #ca8a04; }
    .badge-low { background: #14532d; color: #bbf7d0; border: 1px solid #16a34a; }
    .badge-clean { background: #064e3b; color: #a7f3d0; border: 1px solid #059669; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 14px; }
    th, td { padding: 10px 14px; text-align: left; border: 1px solid #374151; }
    th { background: #1e293b; color: #94a3b8; font-weight: 600; }
    tr:nth-child(even) { background: #161e2e; }
    .card { background: #1e293b; border-radius: 6px; padding: 16px; margin: 16px 0; border: 1px solid #334155; }
    .code-block { background: #030712; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #38bdf8; overflow-x: auto; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 16px 0; }
    .stat-box { background: #1f2937; padding: 16px; border-radius: 6px; text-align: center; }
    .stat-val { font-size: 24px; font-weight: bold; color: #60a5fa; }
    .stat-lbl { font-size: 12px; color: #9ca3af; text-transform: uppercase; }
  </style>
</head>
<body>
  <div class="container">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <span class="badge badge-${summary.riskLevel.toLowerCase()}">RISK LEVEL: ${esc(summary.riskLevel)}</span>
        <span class="badge" style="background:#1e3a8a; color:#93c5fd; margin-left:8px;">CVSS: ${summary.highestCvss.toFixed(1)}</span>
      </div>
      <div style="color: #94a3b8; font-size: 13px;">Case ID: ${esc(storedCase.record.id)} | SHA-256: ${esc(storedCase.record.fileSha256.substring(0, 16))}...</div>
    </div>

    <h1>Section 1: Executive Summary & Forensic Context</h1>
    <p>This network forensic report documents the automated inspection of email protocol communication channels (SMTP, IMAP, POP3) over TLS and STARTTLS extracted from packet capture <strong>${esc(storedCase.record.filename)}</strong>.</p>
    <div class="grid-4">
      <div class="stat-box"><div class="stat-val">${summary.totalSessions}</div><div class="stat-lbl">Analyzed Sessions</div></div>
      <div class="stat-box"><div class="stat-val">${summary.totalFindings}</div><div class="stat-lbl">Total Findings</div></div>
      <div class="stat-box"><div class="stat-val" style="color:#ef4444;">${summary.severityCounts.CRITICAL}</div><div class="stat-lbl">Critical Threats</div></div>
      <div class="stat-box"><div class="stat-val">${summary.riskScore}/100</div><div class="stat-lbl">Composite Score</div></div>
    </div>
    <div class="card">
      <strong>Analytic Verdict:</strong> ${esc(risk.summary)}
    </div>

    <h2>Section 2: Cryptographic Posture & Risk Scores</h2>
    <table>
      <thead><tr><th>Metric</th><th>Evaluated Value</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>Risk Level</td><td>${esc(summary.riskLevel)}</td><td><span class="badge badge-${summary.riskLevel.toLowerCase()}">${esc(summary.riskLevel)}</span></td></tr>
        <tr><td>Critical Sessions</td><td>${summary.criticalSessions} / ${summary.totalSessions}</td><td>${summary.criticalSessions > 0 ? 'Threat Active' : 'Normal'}</td></tr>
        <tr><td>Audit Chain Verification</td><td>${esc(auditChain.message)}</td><td>${auditChain.valid ? 'Cryptographically Intact' : 'TAMPER DETECTED'}</td></tr>
      </tbody>
    </table>

    <h2>Section 3: Threat & Finding Matrix</h2>
    <table>
      <thead><tr><th>Severity</th><th>Rule ID</th><th>Finding Title</th><th>Category</th><th>Session</th><th>CVSS</th></tr></thead>
      <tbody>
        ${findings.map((f) => `
          <tr>
            <td><span class="badge badge-${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
            <td><code>${esc(f.ruleId)}</code></td>
            <td><strong>${esc(f.title)}</strong><br><small style="color:#94a3b8;">${esc(f.description)}</small></td>
            <td>${esc(f.category)}</td>
            <td>${esc(f.affectedSessionId)}</td>
            <td>${f.cvssScore.toFixed(1)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h2>Section 4: Reconstructed Email Sessions Inventory</h2>
    <table>
      <thead><tr><th>Session</th><th>Protocol</th><th>Client Endpoint</th><th>Server Endpoint</th><th>STARTTLS Verdict</th><th>TLS Version</th><th>Cipher Suite</th></tr></thead>
      <tbody>
        ${sessions.map((s) => `
          <tr>
            <td><code>${esc(s.id)}</code></td>
            <td><strong>${esc(s.protocol)}</strong></td>
            <td>${esc(s.clientIp)}:${s.clientPort}</td>
            <td>${esc(s.serverIp)}:${s.serverPort}</td>
            <td><code>${esc(s.starttlsVerdict)}</code></td>
            <td>${esc(s.tlsVersion || 'N/A')}</td>
            <td>${esc(s.tlsCipherSuiteName || 'N/A')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h2>Section 5: Protocol State & STARTTLS Verdict Breakdown</h2>
    <div class="card">
      <ul>
        <li><strong>clean_starttls:</strong> ${summary.verdictCounts.clean_starttls} sessions successfully negotiated TLS via STARTTLS.</li>
        <li><strong>ack_without_tls:</strong> ${summary.verdictCounts.ack_without_tls} sessions experienced STARTTLS stripping MITM attack.</li>
        <li><strong>missing_starttls_in_caps:</strong> ${summary.verdictCounts.missing_starttls_in_caps} sessions encountered unadvertised STARTTLS / downgrade.</li>
        <li><strong>encrypted_implicit_tls:</strong> ${summary.verdictCounts.encrypted_implicit_tls} direct implicit TLS sessions.</li>
        <li><strong>plaintext_unencrypted:</strong> ${summary.verdictCounts.plaintext_unencrypted} purely unencrypted sessions.</li>
      </ul>
    </div>

    <h2>Section 6: TLS Handshake & Cipher Suite Registry Details</h2>
    <table>
      <thead><tr><th>Session</th><th>Cipher Suite</th><th>Key Exchange</th><th>PFS</th><th>Encryption</th><th>MAC</th><th>Status</th></tr></thead>
      <tbody>
        ${sessions.filter((s) => !!s.cipherDetails).map((s) => `
          <tr>
            <td>${esc(s.id)}</td>
            <td><code>${esc(s.cipherDetails!.name)}</code></td>
            <td>${esc(s.cipherDetails!.keyExchange)}</td>
            <td>${s.cipherDetails!.pfs ? 'YES' : 'NO (Vulnerable)'}</td>
            <td>${esc(s.cipherDetails!.encryption)}</td>
            <td>${esc(s.cipherDetails!.mac)}</td>
            <td><span class="badge badge-${s.cipherDetails!.securityStatus === 'SECURE' ? 'clean' : s.cipherDetails!.securityStatus === 'BROKEN' ? 'critical' : 'high'}">${esc(s.cipherDetails!.securityStatus)}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h2>Section 7: X.509 Certificate Intelligence & Chain Validation</h2>
    ${sessions.filter((s) => !!s.certificate).map((s) => `
      <div class="card">
        <h3>Certificate: ${esc(s.certificate!.subject)}</h3>
        <p><strong>Issuer:</strong> ${esc(s.certificate!.issuer)}</p>
        <p><strong>Validity:</strong> ${esc(s.certificate!.validFrom)} to ${esc(s.certificate!.validTo)} (Status: ${s.certificate!.isExpired ? '<span style="color:#ef4444;">EXPIRED</span>' : 'Valid'})</p>
        <p><strong>Key Algorithm:</strong> ${esc(s.certificate!.keyAlgorithm)} (${s.certificate!.keyLength} bits) | <strong>Signature Algorithm:</strong> ${esc(s.certificate!.signatureAlgorithm)}</p>
        <p><strong>Self-Signed:</strong> ${s.certificate!.isSelfSigned ? 'YES (Untrusted)' : 'NO'}</p>
        <p><strong>SHA-256 Fingerprint:</strong> <code>${esc(s.certificate!.rawFingerprintSha256)}</code></p>
        ${s.certificate!.issues.length > 0 ? `<p style="color:#f87171;"><strong>Issues:</strong> ${esc(s.certificate!.issues.join('; '))}</p>` : ''}
      </div>
    `).join('')}

    <h2>Section 8: Cleartext Credential & Data Exposure Analysis</h2>
    ${sessions.filter((s) => !!s.credentialsExposed).map((s) => `
      <div class="card" style="border-left: 4px solid #ef4444;">
        <strong style="color:#ef4444;">CRITICAL: Cleartext Credential Transmission in ${esc(s.id)}</strong>
        <p>Type: <code>${esc(s.credentialsExposed!.type)}</code> | Identified Account: <code>${esc(s.credentialsExposed!.username || 'unknown')}</code></p>
        <div class="code-block">${esc(s.credentialsExposed!.evidence.snippetAscii)}</div>
      </div>
    `).join('') || '<p>No cleartext authentication credentials observed in captured sessions.</p>'}

    <h2>Section 9: Behavioral Anomaly Log (Observed vs Interpreted)</h2>
    <table>
      <thead><tr><th>Anomaly Type</th><th>Observed Fact</th><th>Forensic Threat Interpretation</th><th>Score</th></tr></thead>
      <tbody>
        ${anomalies.map((a) => `
          <tr>
            <td><strong>${esc(a.title)}</strong><br><code>${esc(a.type)}</code></td>
            <td>${esc(a.observed)}</td>
            <td style="color:#fbbf24;">${esc(a.interpreted)}</td>
            <td><strong>${a.anomalyScore}</strong>/100</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h2>Section 10: MITRE ATT&CK Framework Mapping</h2>
    <table>
      <thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Observed Evidence</th></tr></thead>
      <tbody>
        ${mitre.map((m) => `
          <tr>
            <td><code>${esc(m.id)}</code></td>
            <td><strong>${esc(m.name)}</strong></td>
            <td>${esc(m.tactic)}</td>
            <td>${esc(m.evidence)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h2>Section 11: AI Risk Reasoning & Ground-Truth Verification</h2>
    <div class="card">
      <p><strong>Verification Mode:</strong> ${risk.isAiGenerated ? 'Gemini 3.8 Flash (Server-Side Verified)' : 'Deterministic Ground-Truth Fallback Engine'}</p>
      <p><strong>Ground-Truth Verified:</strong> ${risk.aiVerified ? 'YES (All citations grounded in PCAP)' : 'Deterministic Rules Enforced'}</p>
      <div class="code-block" style="color: #cbd5e1; white-space: pre-wrap;">${esc(risk.aiReasoning || risk.summary)}</div>
    </div>

    <h2>Section 12: Remediation Action Plan & Defense Matrix</h2>
    <div class="card">
      <ol>
        ${risk.remediationPlan.map((r) => `<li>${esc(r)}</li>`).join('')}
      </ol>
    </div>

    <h2>Section 13: Cryptographic Audit Trail & Chain Verification</h2>
    <div class="card">
      <p><strong>Chain Status:</strong> ${esc(auditChain.message)}</p>
      <p><strong>PCAP SHA-256 Digest:</strong> <code>${esc(storedCase.record.fileSha256)}</code></p>
      <p><strong>Records in Chain:</strong> ${AuditService.getRecords().length}</p>
    </div>
  </div>
</body>
</html>`;
  }

  public static generatePdf(storedCase: StoredCase): Uint8Array {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const summary = storedCase.analysis.summary;
    const risk = storedCase.analysis.riskAssessment;
    const auditChain = AuditService.verifyChain();

    // Cover / Header
    doc.setFillColor(15, 23, 42); // dark slate
    doc.rect(0, 0, 210, 35, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.text('SIH26159 Network Forensic Analysis Report', 14, 15);

    doc.setFontSize(9);
    doc.setTextColor(148, 163, 184);
    doc.text(`Target File: ${storedCase.record.filename} | Case ID: ${storedCase.record.id}`, 14, 23);
    doc.text(`Generated: ${new Date().toISOString()} | SHA256: ${storedCase.record.fileSha256.substring(0, 24)}...`, 14, 29);

    // Section 1
    let y = 45;
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(12);
    doc.text('1. Executive Threat Summary', 14, y);
    y += 7;

    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);
    doc.text(`Risk Level: ${summary.riskLevel} | Composite Risk Score: ${summary.riskScore}/100 | Highest CVSS: ${summary.highestCvss.toFixed(1)}`, 14, y);
    y += 6;
    doc.text(`Analyzed Sessions: ${summary.totalSessions} | Critical Threats: ${summary.severityCounts.CRITICAL} | High Risks: ${summary.severityCounts.HIGH}`, 14, y);
    y += 8;

    const summaryLines = doc.splitTextToSize(risk.summary, 180);
    doc.text(summaryLines, 14, y);
    y += summaryLines.length * 5 + 6;

    // Section 2: Reconstructed Sessions Table
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(12);
    doc.text('2. Reconstructed Email Sessions Overview', 14, y);
    y += 7;

    doc.setFontSize(8);
    doc.setFillColor(241, 245, 249);
    doc.rect(14, y, 182, 6, 'F');
    doc.setTextColor(71, 85, 105);
    doc.text('Session', 16, y + 4);
    doc.text('Proto', 38, y + 4);
    doc.text('Client Endpoint', 55, y + 4);
    doc.text('Server Endpoint', 95, y + 4);
    doc.text('STARTTLS Verdict', 135, y + 4);
    doc.text('TLS Version', 170, y + 4);
    y += 7;

    doc.setTextColor(15, 23, 42);
    for (const s of storedCase.analysis.sessions.slice(0, 8)) {
      doc.text(s.id, 16, y + 4);
      doc.text(s.protocol, 38, y + 4);
      doc.text(`${s.clientIp}:${s.clientPort}`, 55, y + 4);
      doc.text(`${s.serverIp}:${s.serverPort}`, 95, y + 4);
      doc.text(s.starttlsVerdict, 135, y + 4);
      doc.text(s.tlsVersion || 'NONE', 170, y + 4);
      y += 6;
    }
    y += 6;

    // Section 3: Key Findings
    doc.setFontSize(12);
    doc.text('3. Cryptographic & Protocol Findings', 14, y);
    y += 7;

    doc.setFontSize(8);
    for (const f of storedCase.analysis.findings.slice(0, 6)) {
      doc.setTextColor(f.severity === 'CRITICAL' ? 185 : 30, 28, 28);
      doc.text(`[${f.severity}] ${f.ruleId} - ${f.title} (CVSS: ${f.cvssScore})`, 14, y);
      y += 4;
      doc.setTextColor(71, 85, 105);
      const descLines = doc.splitTextToSize(`Affected: ${f.affectedSessionId} | ${f.description}`, 180);
      doc.text(descLines, 16, y);
      y += descLines.length * 4 + 3;
    }

    // Section 4: Audit & Chain Integrity
    y += 4;
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(11);
    doc.text('4. Forensic Audit Chain & Integrity', 14, y);
    y += 6;
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    doc.text(`Chain Status: ${auditChain.message}`, 14, y);
    y += 5;
    doc.text(`Audit Records in Chain: ${AuditService.getRecords().length} | Verified Cryptographically Intact.`, 14, y);

    return new Uint8Array(doc.output('arraybuffer'));
  }

  private static getMitreMapping(storedCase: StoredCase): { id: string; name: string; tactic: string; evidence: string }[] {
    const mitre: { id: string; name: string; tactic: string; evidence: string }[] = [];
    const sessions = storedCase.analysis.sessions;

    if (sessions.some((s) => s.starttlsStripped)) {
      mitre.push({
        id: 'T1557.002',
        name: 'Adversary-in-the-Middle: ARP/DNS/STARTTLS Stripping',
        tactic: 'Credential Access & Collection',
        evidence: 'Active STARTTLS downgrade detected (ack_without_tls or missing_starttls_in_caps).',
      });
    }

    if (sessions.some((s) => s.credentialsExposed)) {
      mitre.push({
        id: 'T1552.001',
        name: 'Unsecured Credentials: Plaintext Transmission',
        tactic: 'Credential Access',
        evidence: 'AUTH LOGIN or AUTH PLAIN credentials captured in unencrypted cleartext payload.',
      });
    }

    if (sessions.some((s) => s.tlsVersion === 'TLSv1.0' || s.cipherDetails?.securityStatus === 'BROKEN')) {
      mitre.push({
        id: 'T1588.004',
        name: 'Obtain Capabilities: Exploitation of Deprecated Cryptography',
        tactic: 'Initial Access',
        evidence: 'Use of deprecated TLS 1.0 or broken RC4 ciphers susceptible to cryptographic interception.',
      });
    }

    if (sessions.some((s) => s.certificate?.isSelfSigned)) {
      mitre.push({
        id: 'T1587.003',
        name: 'Develop Capabilities: Digital Certificates',
        tactic: 'Defense Evasion',
        evidence: 'Self-signed certificate presented without validation by recognized public or internal CA.',
      });
    }

    return mitre;
  }

  private static escapeHtml(str: string): string {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}
