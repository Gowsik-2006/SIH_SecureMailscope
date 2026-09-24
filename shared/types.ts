export type EmailProtocol = 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN';

export type StarttlsVerdict =
  | 'clean_starttls'
  | 'ack_without_tls'
  | 'missing_starttls_in_caps'
  | 'rejected_starttls'
  | 'fallback_to_plaintext'
  | 'encrypted_implicit_tls'
  | 'plaintext_unencrypted';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type FindingCategory =
  | 'CRYPTOGRAPHIC'
  | 'PROTOCOL'
  | 'CERTIFICATE'
  | 'AUTHENTICATION'
  | 'INTEGRITY'
  | 'ANOMALY';

export type CipherSecurityStatus = 'SECURE' | 'ACCEPTABLE' | 'WEAK' | 'INSECURE' | 'BROKEN';

export interface CipherDetails {
  id: string; // e.g. "0x002F"
  hexCode: number;
  name: string; // e.g. "TLS_RSA_WITH_AES_128_CBC_SHA"
  standardName?: string;
  protocol: string;
  keyExchange: string; // RSA, ECDHE, DHE, etc.
  auth: string; // RSA, ECDSA, etc.
  encryption: string; // AES-128-CBC, RC4-128, etc.
  keyLength: number; // bits
  mac: string; // SHA1, SHA256, AEAD
  pfs: boolean; // Perfect Forward Secrecy
  securityStatus: CipherSecurityStatus;
  reasons: string[];
}

export interface CertificateInfo {
  id: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  validFromEpoch: number;
  validToEpoch: number;
  isExpired: boolean;
  isNotYetValid: boolean;
  daysRemaining: number;
  sans: string[];
  keyAlgorithm: string;
  keyLength: number;
  signatureAlgorithm: string;
  isSelfSigned: boolean;
  chainValid?: boolean;
  rawFingerprintSha256: string;
  issues: string[];
}

export interface EvidenceRef {
  frameNumber: number;
  timestamp: number;
  streamKey: string;
  byteOffset: number;
  length: number;
  snippetHex: string;
  snippetAscii: string;
  description: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: FindingSeverity;
  category: FindingCategory;
  affectedSessionId: string;
  description: string;
  impact: string;
  remediation: string;
  cvssScore: number;
  evidence: EvidenceRef[];
}

export interface Anomaly {
  id: string;
  sessionId: string;
  timestamp: number;
  type: string;
  title: string;
  observed: string; // Factual observation in PCAP
  interpreted: string; // Threat inference
  anomalyScore: number; // 0-100
  evidenceRef?: EvidenceRef;
}

export interface PacketFlags {
  syn: boolean;
  ack: boolean;
  fin: boolean;
  rst: boolean;
  psh: boolean;
  urg: boolean;
}

export interface RawPacket {
  frameNumber: number;
  timestampSec: number;
  timestampUsec: number;
  timestampEpochMs: number;
  linkType: number;
  capturedLength: number;
  originalLength: number;
  srcMac?: string;
  dstMac?: string;
  vlanId?: number;
  ipVersion: 4 | 6 | 0;
  srcIp: string;
  dstIp: string;
  transportProto: 'TCP' | 'UDP' | 'OTHER';
  srcPort: number;
  dstPort: number;
  tcpSeq?: number;
  tcpAck?: number;
  tcpFlags?: PacketFlags;
  tcpWindow?: number;
  payloadOffset: number;
  payloadLength: number;
  payloadHexSnippet: string;
  payloadAsciiSnippet: string;
  data: Uint8Array;
}

export interface ConversationTurn {
  frameNumber: number;
  timestamp: number;
  direction: 'C2S' | 'S2C';
  text: string;
  isTls: boolean;
  tlsContentType?: number;
  tlsHandshakeType?: number;
}

export interface SessionTimelineEvent {
  timestamp: number;
  frameNumber: number;
  stage: string;
  description: string;
  isError?: boolean;
  isSecurityWarning?: boolean;
}

export interface SessionMetadata {
  id: string;
  protocol: EmailProtocol;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  startTimeEpoch: number;
  endTimeEpoch: number;
  durationMs: number;
  packetCount: number;
  bytesCount: number;
  streamKey: string;
  starttlsVerdict: StarttlsVerdict;
  starttlsNegotiated: boolean;
  starttlsStripped: boolean;
  tlsVersion?: string;
  tlsCipherSuiteId?: string;
  tlsCipherSuiteName?: string;
  cipherDetails?: CipherDetails;
  certificate?: CertificateInfo;
  serverBanner?: string;
  clientHelloSni?: string;
  clientHelloSupportedVersions?: string[];
  findings: Finding[];
  anomalies: Anomaly[];
  timeline: SessionTimelineEvent[];
  conversation: ConversationTurn[];
  credentialsExposed?: {
    type: string;
    username?: string;
    hasPlaintextPassword: boolean;
    evidence: EvidenceRef;
  };
}

export interface RiskAssessment {
  overallScore: number; // 0 - 100
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
  summary: string;
  aiReasoning?: string;
  isAiGenerated: boolean;
  aiVerified: boolean;
  aiClaimsChecked: boolean;
  fallbackUsed: boolean;
  claimsVerificationNotes?: string[];
  remediationPlan: string[];
}

export interface CaseSummary {
  totalSessions: number;
  protocolCounts: Record<EmailProtocol, number>;
  verdictCounts: Record<StarttlsVerdict, number>;
  severityCounts: Record<FindingSeverity, number>;
  totalFindings: number;
  totalAnomalies: number;
  criticalSessions: number;
  highestCvss: number;
  riskScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
}

export interface CaseRecord {
  id: string;
  name: string;
  createdAt: number;
  updatedAt: number;
  filename: string;
  fileSizeBytes: number;
  fileSha256: string;
  packetCount: number;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  progressPercent: number;
  statusMessage?: string;
  errorMessage?: string;
  summary?: CaseSummary;
  riskAssessment?: RiskAssessment;
}

export interface AuditRecord {
  id: string;
  sequence: number;
  timestamp: number;
  actor: string;
  role: string;
  action: string;
  targetId?: string;
  details: string;
  prevHash: string;
  currentHash: string;
}

export interface UserProfile {
  id: string;
  username: string;
  role: 'ADMIN' | 'ANALYST' | 'AUDITOR' | 'VIEWER';
  name: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  meta?: {
    timestamp: number;
    requestId?: string;
  };
}

export interface AnalysisFilter {
  severity?: FindingSeverity;
  protocol?: EmailProtocol;
  category?: FindingCategory;
  sessionId?: string;
  search?: string;
}

export interface LiveCaptureInterface {
  name: string;
  description: string;
  addresses: string[];
  isLoopback: boolean;
}

export interface LiveCaptureStatus {
  active: boolean;
  interfaceName?: string;
  bpfFilter?: string;
  packetsCaptured: number;
  bytesCaptured?: number;
  startTime?: number;
  ratePacketsPerSec?: number;
  rateBytesPerSec?: number;
}

export interface LivePacketEvent {
  id: string;
  packetNumber: number;
  timestamp: number;
  relativeMs: number;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | 'TLS' | 'TCP';
  tcpFlags: string[];
  length: number;
  info: string;
  payloadPreview?: string;
  rawHex?: string;
  rawAscii?: string;
  isSecurityAlert?: boolean;
  alertSeverity?: FindingSeverity;
  alertMessage?: string;
}

export interface LiveCaptureTelemetry {
  status: LiveCaptureStatus;
  recentPackets: LivePacketEvent[];
  alerts: LivePacketEvent[];
  protocolCounts: Record<string, number>;
  throughput: {
    packetsPerSec: number;
    bytesPerSec: number;
  };
}

export interface ActiveScanRequest {
  target: string;
  port?: number;
  protocol?: 'SMTP' | 'IMAP' | 'POP3' | 'AUTO';
  checkMtaSts?: boolean;
  checkDane?: boolean;
}

export interface ActiveScanResult {
  scanId: string;
  targetHost: string;
  resolvedIp: string;
  port: number;
  protocol: 'SMTP' | 'IMAP' | 'POP3';
  banner: string;
  ehloCapabilities: string[];
  starttlsSupported: boolean;
  starttlsNegotiated: boolean;
  tlsVersion?: string;
  cipherSuite?: string;
  certificateSubject?: string;
  certificateIssuer?: string;
  certificateExpires?: string;
  certificateValidDays?: number;
  certificateKeyStrength?: string;
  isSelfSigned?: boolean;
  mtaStsStatus?: 'VALID' | 'MISSING' | 'INVALID' | 'NOT_CHECKED';
  mtaStsPolicy?: string;
  daneStatus?: 'VALID' | 'MISSING' | 'NOT_CHECKED';
  riskScore: number;
  threats: string[];
  caseId?: string;
  durationMs: number;
  timestamp: number;
  rawTranscript: {
    direction: 'SENT' | 'RECV';
    timestamp: number;
    text: string;
  }[];
}

export interface CollectorConfig {
  apiKey: string;
  endpointUrl: string;
  curlExample: string;
  pythonSnippet: string;
  ingestCount: number;
  lastIngestedAt?: number;
}
