import { FindingSeverity, FindingCategory } from '../../../shared/types.ts';

export interface RuleDefinition {
  id: string;
  name: string;
  category: FindingCategory;
  defaultSeverity: FindingSeverity;
  cvssBaseScore: number;
  descriptionTemplate: string;
  impactTemplate: string;
  remediationTemplate: string;
  enabled: boolean;
}

export const RULE_CATALOG: Record<string, RuleDefinition> = {
  'R-STARTTLS-STRIPPED': {
    id: 'R-STARTTLS-STRIPPED',
    name: 'STARTTLS Downgrade / Stripping Attack Detected',
    category: 'PROTOCOL',
    defaultSeverity: 'CRITICAL',
    cvssBaseScore: 9.8,
    descriptionTemplate:
      'The email session was manipulated by an adversary or MITM proxy to strip or bypass STARTTLS encryption, causing plaintext transmission of email commands or credentials.',
    impactTemplate:
      'High confidentiality and integrity loss. Attackers on the network path can eavesdrop on confidential messages, hijack sessions, and steal cleartext credentials.',
    remediationTemplate:
      'Enforce strict MTA-STS (RFC 8461) and DANE (RFC 7672) policies. Reject unencrypted fallback for submission ports (587, 465).',
    enabled: true,
  },
  'R-AUTH-CLEARTEXT': {
    id: 'R-AUTH-CLEARTEXT',
    name: 'Cleartext Authentication Credentials Transmitted',
    category: 'AUTHENTICATION',
    defaultSeverity: 'CRITICAL',
    cvssBaseScore: 9.4,
    descriptionTemplate:
      'Authentication commands (AUTH PLAIN, AUTH LOGIN, USER/PASS) were sent over an unencrypted channel without TLS.',
    impactTemplate:
      'Direct account takeover. Passwords transmitted across network hops can be intercepted via passive sniffing or ARP spoofing.',
    remediationTemplate:
      'Require implicit TLS or explicit STARTTLS before permitting authentication commands on all email endpoints.',
    enabled: true,
  },
  'R-TLS-VER-DEPRECATED': {
    id: 'R-TLS-VER-DEPRECATED',
    name: 'Deprecated TLS Protocol Version Negotiated',
    category: 'CRYPTOGRAPHIC',
    defaultSeverity: 'HIGH',
    cvssBaseScore: 7.5,
    descriptionTemplate:
      'The session negotiated an obsolete TLS version (SSLv3, TLS 1.0, or TLS 1.1) formally deprecated by RFC 8996.',
    impactTemplate:
      'Vulnerable to historical cryptographic attacks including POODLE, BEAST, and cryptographic downgrade vectors.',
    remediationTemplate:
      'Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in mail server configurations. Enforce TLS 1.2 or TLS 1.3 exclusively.',
    enabled: true,
  },
  'R-CIPH-BROKEN': {
    id: 'R-CIPH-BROKEN',
    name: 'Cryptographically Broken or Prohibited Cipher Suite',
    category: 'CRYPTOGRAPHIC',
    defaultSeverity: 'CRITICAL',
    cvssBaseScore: 9.1,
    descriptionTemplate:
      'The negotiated cipher suite utilizes broken or insecure algorithms (e.g., RC4, 3DES, DES, or NULL).',
    impactTemplate:
      'RC4 keystream bias allows plaintext reconstruction (RFC 7465); 3DES is vulnerable to Sweet32 birthday collision attacks.',
    remediationTemplate:
      'Remove RC4, 3DES, DES, and NULL ciphers from the server cipher suite list. Prefer AES-GCM or ChaCha20-Poly1305.',
    enabled: true,
  },
  'R-CIPH-NO-PFS': {
    id: 'R-CIPH-NO-PFS',
    name: 'Missing Perfect Forward Secrecy (PFS)',
    category: 'CRYPTOGRAPHIC',
    defaultSeverity: 'MEDIUM',
    cvssBaseScore: 5.9,
    descriptionTemplate:
      'The selected cipher uses static RSA key exchange instead of Ephemeral Diffie-Hellman (ECDHE / DHE).',
    impactTemplate:
      'If the server private key is compromised in the future, past recorded encrypted sessions can be retroactively decrypted.',
    remediationTemplate:
      'Configure the server to exclusively offer Ephemeral Diffie-Hellman key exchange suites (ECDHE / DHE).',
    enabled: true,
  },
  'R-CIPH-CBC-WEAK': {
    id: 'R-CIPH-CBC-WEAK',
    name: 'Legacy CBC Cipher Mode with SHA-1 MAC',
    category: 'CRYPTOGRAPHIC',
    defaultSeverity: 'LOW',
    cvssBaseScore: 3.7,
    descriptionTemplate:
      'The session negotiated AES-CBC mode with SHA-1 HMAC rather than an Authenticated Encryption with Associated Data (AEAD) cipher.',
    impactTemplate:
      'CBC mode has historically been vulnerable to padding oracle attacks (e.g. Lucky Thirteen); SHA-1 has reduced collision resistance.',
    remediationTemplate:
      'Prioritize AEAD ciphers (AES-GCM or ChaCha20-Poly1305) over CBC mode ciphers in TLS configuration.',
    enabled: true,
  },
  'R-CERT-EXPIRED': {
    id: 'R-CERT-EXPIRED',
    name: 'Expired X.509 Server Certificate',
    category: 'CERTIFICATE',
    defaultSeverity: 'HIGH',
    cvssBaseScore: 7.4,
    descriptionTemplate:
      'The presented server certificate is past its validity end date (notAfter).',
    impactTemplate:
      'Clients cannot reliably verify server identity, causing connection warnings, delivery aborts, or exposure to impersonation.',
    remediationTemplate:
      'Renew and deploy a valid certificate immediately via an automated ACME client (e.g., Certbot).',
    enabled: true,
  },
  'R-CERT-NOT-YET-VALID': {
    id: 'R-CERT-NOT-YET-VALID',
    name: 'Certificate Not Yet Valid',
    category: 'CERTIFICATE',
    defaultSeverity: 'HIGH',
    cvssBaseScore: 7.0,
    descriptionTemplate:
      'The presented certificate validity start time (notBefore) is in the future.',
    impactTemplate:
      'Indicates severe clock skew or pre-dated certificate, preventing cryptographic validation.',
    remediationTemplate:
      'Check system time synchronization (NTP) and reissue certificate with correct validity range.',
    enabled: true,
  },
  'R-CERT-WEAK-KEY': {
    id: 'R-CERT-WEAK-KEY',
    name: 'Insufficient RSA Public Key Length',
    category: 'CERTIFICATE',
    defaultSeverity: 'HIGH',
    cvssBaseScore: 7.5,
    descriptionTemplate:
      'The server certificate uses an RSA public key smaller than 2048 bits (e.g., 1024 bits or 512 bits).',
    impactTemplate:
      '1024-bit RSA keys are vulnerable to factorization by determined adversaries, allowing private key reconstruction.',
    remediationTemplate:
      'Re-generate key pairs using a minimum of 2048-bit RSA or 256-bit ECDSA (prime256v1).',
    enabled: true,
  },
  'R-CERT-WEAK-SIG': {
    id: 'R-CERT-WEAK-SIG',
    name: 'Weak Signature Algorithm on Certificate',
    category: 'CERTIFICATE',
    defaultSeverity: 'MEDIUM',
    cvssBaseScore: 6.5,
    descriptionTemplate:
      'The certificate was signed using SHA-1 or MD5 hash algorithms.',
    impactTemplate:
      'Hash collisions allow attackers to forge rogue certificates for server domains.',
    remediationTemplate:
      'Reissue certificates using SHA-256 or stronger signature digest algorithms (e.g., SHA-384).',
    enabled: true,
  },
  'R-CERT-SELF-SIGNED': {
    id: 'R-CERT-SELF-SIGNED',
    name: 'Self-Signed Certificate in Production',
    category: 'CERTIFICATE',
    defaultSeverity: 'MEDIUM',
    cvssBaseScore: 5.3,
    descriptionTemplate:
      'The server presented a self-signed certificate lacking verification by a recognized Certificate Authority.',
    impactTemplate:
      'Leaves connections susceptible to MITM interception unless certificates are pinned manually across all clients.',
    remediationTemplate:
      'Deploy certificates issued by a trusted public CA (e.g., Let’s Encrypt) or an internal enterprise PKI.',
    enabled: true,
  },
  'R-ALERT-FATAL': {
    id: 'R-ALERT-FATAL',
    name: 'TLS Handshake Aborted by Fatal Alert',
    category: 'INTEGRITY',
    defaultSeverity: 'MEDIUM',
    cvssBaseScore: 4.8,
    descriptionTemplate:
      'A fatal TLS alert frame was exchanged, terminating the cryptographic handshake.',
    impactTemplate:
      'Interrupted secure channel setup; mail clients may abort or fallback to unencrypted transmission.',
    remediationTemplate:
      'Investigate client and server cipher compatibility, certificate validity, and protocol version support.',
    enabled: true,
  },
};
