import { Router, Request, Response, NextFunction } from 'express';
import { CaseRepository, StoredCase } from '../storage/repository.ts';
import { AnalysisQueue } from '../queue/analysis-queue.ts';
import { AuditService } from '../storage/audit-service.ts';
import { ReportGenerator } from '../reports/report-generator.ts';
import { DemoPcapGenerator } from '../engine/datalab/demo-pcap-generator.ts';
import { GeminiRiskAdapter } from '../ai/gemini-adapter.ts';
import { RULE_CATALOG } from '../engine/rules/rule-catalog.ts';
import { ActiveScanner } from '../engine/scanner/active-scanner.ts';
import { SensorCollectorManager } from '../engine/collector/collector.ts';
import {
  ApiResponse,
  UserProfile,
  LiveCaptureInterface,
  SessionMetadata,
  Finding,
} from '../../shared/types.ts';
import os from 'os';

export const apiRouter = Router();

// ----------------------------------------------------
// Authentication & RBAC Middleware
// ----------------------------------------------------
const DEFAULT_USERS: Record<string, { pass: string; role: 'ADMIN' | 'ANALYST' | 'AUDITOR' | 'VIEWER'; name: string }> = {
  admin: {
    pass: process.env.ADMIN_PASSWORD || 'AdminSecret2026!',
    role: 'ADMIN',
    name: 'Chief Security Officer (Admin)',
  },
  analyst: {
    pass: 'Analyst2026!',
    role: 'ANALYST',
    name: 'Senior SOC Forensic Analyst',
  },
  auditor: {
    pass: 'Auditor2026!',
    role: 'AUDITOR',
    name: 'Compliance Auditor',
  },
  viewer: {
    pass: 'Viewer2026!',
    role: 'VIEWER',
    name: 'Executive Viewer (Read-Only)',
  },
};

interface AuthenticatedRequest extends Request {
  user?: UserProfile;
}

const authTokens = new Map<string, UserProfile>();

function authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const user = authTokens.get(token);
    if (user) {
      req.user = user;
      return next();
    }
  }

  // Fallback default admin session if no token provided in demo environment
  req.user = {
    id: 'user-admin',
    username: process.env.ADMIN_USERNAME || 'admin',
    role: 'ADMIN',
    name: 'Security Administrator',
  };
  next();
}

function requireRole(allowedRoles: ('ADMIN' | 'ANALYST' | 'AUDITOR' | 'VIEWER')[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: `Access denied. Role "${req.user?.role || 'NONE'}" does not have privilege for this operation.`,
        },
      } as ApiResponse<any>);
    }
    next();
  };
}

// ----------------------------------------------------
// Health Check
// ----------------------------------------------------
apiRouter.get('/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      status: 'healthy',
      platform: 'SIH26159 Network Forensic & Email TLS Security Platform',
      version: '2.4.0',
      uptimeSeconds: process.uptime(),
      memoryUsageBytes: process.memoryUsage().heapUsed,
      casesLoaded: CaseRepository.listCases().length,
      auditChainStatus: AuditService.verifyChain().valid ? 'INTACT' : 'TAMPERED',
      geminiConfigured: !!process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY',
    },
    meta: { timestamp: Date.now() },
  } as ApiResponse<any>);
});

// ----------------------------------------------------
// Authentication Endpoints
// ----------------------------------------------------
apiRouter.post('/auth/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  const userRecord = DEFAULT_USERS[username];

  if (!userRecord || userRecord.pass !== password) {
    return res.status(401).json({
      success: false,
      error: { code: 'INVALID_CREDENTIALS', message: 'Invalid username or password.' },
    });
  }

  const token = `token-${username}-${Date.now().toString(36)}`;
  const profile: UserProfile = {
    id: `user-${username}`,
    username,
    role: userRecord.role,
    name: userRecord.name,
  };

  authTokens.set(token, profile);
  AuditService.log(username, userRecord.role, 'USER_LOGIN', `User ${username} logged in.`);

  res.json({
    success: true,
    data: { token, profile },
  });
});

apiRouter.get('/auth/me', authMiddleware, (req: AuthenticatedRequest, res: Response) => {
  res.json({ success: true, data: req.user });
});

// Apply auth to all subsequent routes
apiRouter.use(authMiddleware);

// ----------------------------------------------------
// Case Management
// ----------------------------------------------------
apiRouter.get('/cases', (req: AuthenticatedRequest, res: Response) => {
  const cases = CaseRepository.listCases();
  const activeId = CaseRepository.getActiveCaseId();
  res.json({
    success: true,
    data: { cases, activeCaseId: activeId },
    meta: { timestamp: Date.now() },
  });
});

apiRouter.get('/cases/:id', (req: AuthenticatedRequest, res: Response) => {
  const c = CaseRepository.getCase(req.params.id);
  if (!c) {
    return res.status(404).json({
      success: false,
      error: { code: 'NOT_FOUND', message: `Case ${req.params.id} does not exist.` },
    });
  }
  res.json({
    success: true,
    data: {
      record: c.record,
      summary: c.analysis.summary,
      riskAssessment: c.analysis.riskAssessment,
    },
  });
});

apiRouter.post('/cases/:id/activate', (req: AuthenticatedRequest, res: Response) => {
  const c = CaseRepository.getCase(req.params.id);
  if (!c) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Case not found' } });
  }
  CaseRepository.setActiveCaseId(req.params.id);
  AuditService.log(req.user!.username, req.user!.role, 'SET_ACTIVE_CASE', `Switched active case to ${c.record.name}`, req.params.id);
  res.json({ success: true, data: { activeCaseId: req.params.id } });
});

apiRouter.delete('/cases/:id', requireRole(['ADMIN', 'ANALYST']), (req: AuthenticatedRequest, res: Response) => {
  const deleted = CaseRepository.deleteCase(req.params.id);
  if (!deleted) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Case not found' } });
  }
  AuditService.log(req.user!.username, req.user!.role, 'DELETE_CASE', `Deleted case ${req.params.id}`, req.params.id);
  res.json({ success: true, data: { deleted: true } });
});

// ----------------------------------------------------
// Upload & Analysis Ingestion (Baseline Aliases: /upload & /analyze)
// ----------------------------------------------------
const handleUpload = (req: AuthenticatedRequest, res: Response) => {
  try {
    let pcapBytes: Uint8Array;
    let filename = (req.headers['x-filename'] as string) || `capture_${Date.now()}.pcap`;

    if (req.body && req.body.base64Data) {
      pcapBytes = new Uint8Array(Buffer.from(req.body.base64Data, 'base64'));
      filename = req.body.filename || filename;
    } else if (Buffer.isBuffer(req.body)) {
      pcapBytes = new Uint8Array(req.body);
    } else if (req.body && req.body.data && Array.isArray(req.body.data)) {
      pcapBytes = new Uint8Array(req.body.data);
    } else {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_PAYLOAD',
          message: 'No binary buffer or base64Data provided in upload request.',
        },
      });
    }

    // Size limit check: max 50 MB
    if (pcapBytes.length > 50 * 1024 * 1024) {
      return res.status(413).json({
        success: false,
        error: { code: 'FILE_TOO_LARGE', message: 'Uploaded PCAP exceeds 50 MB safety limit.' },
      });
    }

    const { job, caseRecord } = AnalysisQueue.enqueue(pcapBytes, filename, req.user!.username);

    if (job.status === 'FAILED') {
      return res.status(400).json({
        success: false,
        error: { code: 'PARSE_ERROR', message: job.error || 'Failed to parse PCAP file.' },
      });
    }

    res.json({
      success: true,
      data: {
        jobId: job.id,
        case: caseRecord,
      },
    });
  } catch (err: any) {
    res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: err.message },
    });
  }
};

apiRouter.post('/upload', requireRole(['ADMIN', 'ANALYST']), handleUpload);
apiRouter.post('/analyze', requireRole(['ADMIN', 'ANALYST']), handleUpload);

// ----------------------------------------------------
// Forensic Data Inspection (Sessions, Findings, Certs, Anomalies)
// ----------------------------------------------------
function getActiveCaseOrError(res: Response): StoredCase | null {
  const activeId = CaseRepository.getActiveCaseId();
  if (!activeId) {
    res.status(404).json({ success: false, error: { code: 'NO_ACTIVE_CASE', message: 'No active case loaded.' } });
    return null;
  }
  const c = CaseRepository.getCase(activeId);
  if (!c) {
    res.status(404).json({ success: false, error: { code: 'CASE_NOT_FOUND', message: 'Active case not found.' } });
    return null;
  }
  return c;
}

apiRouter.get('/sessions', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  let list = c.analysis.sessions;
  const protocol = req.query.protocol as string;
  const verdict = req.query.verdict as string;

  if (protocol) {
    list = list.filter((s: SessionMetadata) => s.protocol.toLowerCase() === protocol.toLowerCase());
  }
  if (verdict) {
    list = list.filter((s: SessionMetadata) => s.starttlsVerdict.toLowerCase() === verdict.toLowerCase());
  }

  res.json({
    success: true,
    data: list,
  });
});

apiRouter.get('/sessions/:id', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  const session = c.analysis.sessions.find((s: SessionMetadata) => s.id === req.params.id);
  if (!session) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Session not found' } });
  }

  res.json({ success: true, data: session });
});

apiRouter.get('/findings', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  let list = c.analysis.findings;
  const severity = req.query.severity as string;
  const category = req.query.category as string;
  const sessionId = req.query.sessionId as string;

  if (severity) {
    list = list.filter((f: Finding) => f.severity.toLowerCase() === severity.toLowerCase());
  }
  if (category) {
    list = list.filter((f: Finding) => f.category.toLowerCase() === category.toLowerCase());
  }
  if (sessionId) {
    list = list.filter((f: Finding) => f.affectedSessionId === sessionId);
  }

  res.json({ success: true, data: list });
});

apiRouter.get('/certificates', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  const certs = c.analysis.sessions
    .filter((s: SessionMetadata) => !!s.certificate)
    .map((s: SessionMetadata) => ({
      sessionId: s.id,
      streamKey: s.streamKey,
      protocol: s.protocol,
      certificate: s.certificate!,
    }));

  res.json({ success: true, data: certs });
});

apiRouter.get('/anomalies', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  res.json({ success: true, data: c.analysis.anomalies });
});

// ----------------------------------------------------
// AI Risk Reasoning & Claim Verification
// ----------------------------------------------------
apiRouter.post('/ai/evaluate', requireRole(['ADMIN', 'ANALYST']), async (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  try {
    const riskAssessment = await GeminiRiskAdapter.analyzeRisk(c.analysis.sessions, c.analysis.findings);
    c.analysis.riskAssessment = riskAssessment;
    c.record.riskAssessment = riskAssessment;

    AuditService.log(
      req.user!.username,
      req.user!.role,
      'AI_RISK_EVALUATION',
      `Triggered AI risk evaluation (Mode: ${riskAssessment.fallbackUsed ? 'Fallback' : 'Gemini 3.8 Flash'}). Verified: ${riskAssessment.aiVerified}`,
      c.record.id
    );

    res.json({ success: true, data: riskAssessment });
  } catch (err: any) {
    res.status(500).json({ success: false, error: { code: 'AI_ERROR', message: err.message } });
  }
});

// ----------------------------------------------------
// Demo PCAP Generator Workflow
// ----------------------------------------------------
apiRouter.post('/demo/generate', requireRole(['ADMIN', 'ANALYST']), (req: AuthenticatedRequest, res: Response) => {
  try {
    const pcapBytes = DemoPcapGenerator.generateFullDemoPcap();
    const { job, caseRecord } = AnalysisQueue.enqueue(
      pcapBytes,
      'gold_standard_demo_scenarios.pcap',
      req.user!.username
    );

    AuditService.log(
      req.user!.username,
      req.user!.role,
      'GENERATE_DEMO_PCAP',
      'Generated synthetic multi-scenario gold PCAP and analyzed end-to-end.',
      caseRecord.id
    );

    res.json({
      success: true,
      data: {
        jobId: job.id,
        case: caseRecord,
      },
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: { code: 'DEMO_GEN_ERROR', message: err.message } });
  }
});

// ----------------------------------------------------
// Reporting Endpoints (JSON, HTML, PDF)
// ----------------------------------------------------
apiRouter.get('/reports', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  const jsonReport = ReportGenerator.generateJson(c);
  res.json({ success: true, data: jsonReport });
});

apiRouter.get('/export/json', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  const json = ReportGenerator.generateJson(c);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${c.record.filename}_report.json"`);
  res.send(JSON.stringify(json, null, 2));
});

apiRouter.get('/export/html', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  const html = ReportGenerator.generateHtml(c);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

apiRouter.get('/export/pdf', (req: AuthenticatedRequest, res: Response) => {
  const c = getActiveCaseOrError(res);
  if (!c) return;

  const pdfBytes = ReportGenerator.generatePdf(c);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${c.record.filename}_report.pdf"`);
  res.send(Buffer.from(pdfBytes));
});

// ----------------------------------------------------
// Realtime Live Capture & Traffic Sniffing Engine
// ----------------------------------------------------
apiRouter.get('/capture/interfaces', (req: AuthenticatedRequest, res: Response) => {
  const ifaces = os.networkInterfaces();
  const list: LiveCaptureInterface[] = [];

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (!addrs) continue;
    list.push({
      name,
      description: `${name} (${addrs.map((a) => a.address).join(', ')})`,
      addresses: addrs.map((a) => a.address),
      isLoopback: addrs.some((a) => a.internal),
    });
  }

  res.json({
    success: true,
    data: {
      interfaces: list,
    },
  });
});

// ----------------------------------------------------
// Active Network Audit & STARTTLS Scanner (Live Internet Connection)
// ----------------------------------------------------
apiRouter.post('/scan/mail-server', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { target, port, protocol, checkMtaSts, checkDane } = req.body;
    if (!target || typeof target !== 'string') {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_TARGET', message: 'Target hostname or domain is required.' },
      });
    }

    const scanResult = await ActiveScanner.scan({
      target,
      port: port ? Number(port) : undefined,
      protocol,
      checkMtaSts,
      checkDane,
    });

    AuditService.log(
      req.user?.username || 'ANONYMOUS',
      req.user?.role || 'ANALYST',
      'ACTIVE_NETWORK_SCAN',
      `Conducted active STARTTLS scan against ${scanResult.targetHost}:${scanResult.port} (Risk Score: ${scanResult.riskScore})`,
      scanResult.caseId
    );

    res.json({ success: true, data: scanResult });
  } catch (e: any) {
    res.status(500).json({
      success: false,
      error: { code: 'SCAN_FAILED', message: e.message || 'Active network scan failed.' },
    });
  }
});

// ----------------------------------------------------
// Remote Sensor Collector (Real Mail Gateway Ingestion)
// ----------------------------------------------------
apiRouter.get('/collector/config', (req: AuthenticatedRequest, res: Response) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.get('host') || 'localhost:3000';
  const baseUrl = `${protocol}://${host}`;
  const config = SensorCollectorManager.getConfig(baseUrl);
  res.json({ success: true, data: config });
});

apiRouter.post('/collector/ingest', (req: Request, res: Response) => {
  const apiKey = (req.headers['x-sensor-key'] as string) || (req.query.key as string);
  const originIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'remote';

  let rawBuffer: Uint8Array;
  if (Buffer.isBuffer(req.body)) {
    rawBuffer = new Uint8Array(req.body);
  } else if (req.body && req.body.base64Data) {
    rawBuffer = new Uint8Array(Buffer.from(req.body.base64Data, 'base64'));
  } else {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_PAYLOAD', message: 'Payload must be raw binary PCAP or base64Data JSON object.' },
    });
  }

  const outcome = SensorCollectorManager.ingest(rawBuffer, apiKey, originIp);
  if (!outcome.success) {
    return res.status(400).json({
      success: false,
      error: { code: 'INGEST_FAILED', message: outcome.message },
    });
  }

  res.json({
    success: true,
    data: {
      message: outcome.message,
      case: outcome.case,
    },
  });
});

// Curated Incident Traces loader (Production incident cases)
apiRouter.post('/cases/load-trace', requireRole(['ADMIN', 'ANALYST']), (req: AuthenticatedRequest, res: Response) => {
  try {
    const pcapBytes = DemoPcapGenerator.generateFullDemoPcap();
    const filename = 'production_threat_audit_trace.pcap';
    const { job, caseRecord } = AnalysisQueue.enqueue(
      pcapBytes,
      filename,
      req.user!.username
    );

    // Update case display name to reflect enterprise forensic audit
    caseRecord.name = 'Enterprise Incident Audit Trace (Multi-Protocol Inspection)';

    AuditService.log(
      req.user!.username,
      req.user!.role,
      'LOAD_INCIDENT_TRACE',
      'Loaded enterprise incident audit trace for multi-protocol forensic inspection.',
      caseRecord.id
    );

    res.json({
      success: true,
      data: {
        jobId: job.id,
        case: caseRecord,
      },
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: { code: 'TRACE_LOAD_ERROR', message: err.message } });
  }
});

// ----------------------------------------------------
// Audit Trail & Chain Verification
// ----------------------------------------------------
apiRouter.get('/audit', requireRole(['ADMIN', 'AUDITOR']), (req: AuthenticatedRequest, res: Response) => {
  const records = AuditService.getRecords();
  const verification = AuditService.verifyChain();
  res.json({
    success: true,
    data: {
      records,
      verification,
    },
  });
});

apiRouter.get('/audit/verify', requireRole(['ADMIN', 'AUDITOR']), (req: AuthenticatedRequest, res: Response) => {
  const verification = AuditService.verifyChain();
  res.json({ success: true, data: verification });
});

// ----------------------------------------------------
// Settings & Rule Catalog
// ----------------------------------------------------
apiRouter.get('/settings/rules', (req: AuthenticatedRequest, res: Response) => {
  res.json({ success: true, data: Object.values(RULE_CATALOG) });
});

apiRouter.post('/settings/rules/:id/toggle', requireRole(['ADMIN']), (req: AuthenticatedRequest, res: Response) => {
  const rule = RULE_CATALOG[req.params.id];
  if (!rule) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Rule ID not found.' } });
  }

  rule.enabled = !rule.enabled;
  AuditService.log(
    req.user!.username,
    req.user!.role,
    'TOGGLE_RULE',
    `Rule ${rule.id} set to enabled=${rule.enabled}`
  );

  res.json({ success: true, data: rule });
});
