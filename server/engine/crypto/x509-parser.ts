import { CertificateInfo } from '../../../shared/types.ts';
import crypto from 'crypto';

interface Asn1Node {
  tag: number;
  headerLength: number;
  length: number;
  data: Uint8Array;
  children: Asn1Node[];
}

export class X509Parser {
  public static parse(der: Uint8Array): CertificateInfo {
    const defaultCert: CertificateInfo = {
      id: 'cert-' + Math.random().toString(36).substring(2, 9),
      subject: 'CN=Unknown',
      issuer: 'CN=Unknown',
      serialNumber: '00',
      validFrom: new Date(0).toISOString(),
      validTo: new Date(0).toISOString(),
      validFromEpoch: 0,
      validToEpoch: 0,
      isExpired: false,
      isNotYetValid: false,
      daysRemaining: 0,
      sans: [],
      keyAlgorithm: 'RSA',
      keyLength: 2048,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      isSelfSigned: false,
      rawFingerprintSha256: crypto.createHash('sha256').update(der).digest('hex'),
      issues: [],
    };

    if (!der || der.length < 32) {
      defaultCert.issues.push('Invalid certificate DER: length too short');
      return defaultCert;
    }

    try {
      const root = this.decodeTlv(der, 0);
      if (!root || root.children.length < 1) {
        defaultCert.issues.push('Invalid ASN.1 Root Sequence');
        return defaultCert;
      }

      // Root is SEQUENCE { TBSCertificate, signatureAlgorithm, signatureValue }
      const tbs = root.children[0];
      if (!tbs || tbs.children.length < 5) {
        defaultCert.issues.push('Malformed TBSCertificate structure');
        return defaultCert;
      }

      let childIdx = 0;

      // 1. Version [0] EXPLICIT
      if ((tbs.children[childIdx].tag & 0x1f) === 0 && (tbs.children[childIdx].tag & 0x80) !== 0) {
        childIdx++;
      }

      // 2. Serial Number
      let serialStr = '00';
      if (childIdx < tbs.children.length && tbs.children[childIdx].tag === 0x02) {
        serialStr = Array.from(tbs.children[childIdx].data)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(':');
        childIdx++;
      }

      // 3. Signature AlgorithmIdentifier
      let sigAlgoStr = 'sha256WithRSAEncryption';
      if (childIdx < tbs.children.length) {
        sigAlgoStr = this.extractAlgorithm(tbs.children[childIdx]);
        childIdx++;
      }

      // 4. Issuer Name
      let issuerStr = 'CN=Unknown';
      if (childIdx < tbs.children.length) {
        issuerStr = this.extractDn(tbs.children[childIdx]);
        childIdx++;
      }

      // 5. Validity
      let notBeforeDate = new Date();
      let notAfterDate = new Date();
      if (childIdx < tbs.children.length && tbs.children[childIdx].children.length >= 2) {
        const valSeq = tbs.children[childIdx];
        notBeforeDate = this.parseTimeNode(valSeq.children[0]);
        notAfterDate = this.parseTimeNode(valSeq.children[1]);
        childIdx++;
      }

      // 6. Subject Name
      let subjectStr = 'CN=Unknown';
      if (childIdx < tbs.children.length) {
        subjectStr = this.extractDn(tbs.children[childIdx]);
        childIdx++;
      }

      // 7. SubjectPublicKeyInfo
      let keyAlgo = 'RSA';
      let keyBits = 2048;
      if (childIdx < tbs.children.length) {
        const spki = tbs.children[childIdx];
        const keyInfo = this.extractPublicKeyInfo(spki);
        keyAlgo = keyInfo.algo;
        keyBits = keyInfo.bits;
        childIdx++;
      }

      // 8. Extensions (tagged [3])
      const sans: string[] = [];
      while (childIdx < tbs.children.length) {
        const extContainer = tbs.children[childIdx];
        if ((extContainer.tag & 0x1f) === 3) {
          const extSans = this.extractSans(extContainer);
          sans.push(...extSans);
        }
        childIdx++;
      }

      const now = Date.now();
      const validFromEpoch = notBeforeDate.getTime();
      const validToEpoch = notAfterDate.getTime();
      const isExpired = now > validToEpoch;
      const isNotYetValid = now < validFromEpoch;
      const daysRemaining = Math.floor((validToEpoch - now) / (1000 * 60 * 60 * 24));
      const isSelfSigned = subjectStr.toLowerCase() === issuerStr.toLowerCase();

      const issues: string[] = [];
      if (isExpired) {
        issues.push(`Certificate expired on ${notAfterDate.toISOString()}`);
      }
      if (isNotYetValid) {
        issues.push(`Certificate is not yet valid until ${notBeforeDate.toISOString()}`);
      }
      if (isSelfSigned) {
        issues.push('Certificate is self-signed (untrusted authority)');
      }
      if (keyAlgo === 'RSA' && keyBits < 2048) {
        issues.push(`Weak RSA key length: ${keyBits} bits (minimum recommended is 2048)`);
      }
      if (sigAlgoStr.toLowerCase().includes('sha1') || sigAlgoStr.toLowerCase().includes('md5')) {
        issues.push(`Insecure signature algorithm: ${sigAlgoStr}`);
      }

      return {
        id: 'cert-' + crypto.createHash('sha256').update(der).digest('hex').substring(0, 12),
        subject: subjectStr,
        issuer: issuerStr,
        serialNumber: serialStr,
        validFrom: notBeforeDate.toISOString(),
        validTo: notAfterDate.toISOString(),
        validFromEpoch,
        validToEpoch,
        isExpired,
        isNotYetValid,
        daysRemaining,
        sans,
        keyAlgorithm: keyAlgo,
        keyLength: keyBits,
        signatureAlgorithm: sigAlgoStr,
        isSelfSigned,
        rawFingerprintSha256: crypto.createHash('sha256').update(der).digest('hex'),
        issues,
      };
    } catch (e: any) {
      defaultCert.issues.push(`ASN.1 parsing exception: ${e.message}`);
      return defaultCert;
    }
  }

  private static decodeTlv(buffer: Uint8Array, offset: number): Asn1Node | null {
    if (offset >= buffer.length) return null;

    const tag = buffer[offset];
    let lenByte = buffer[offset + 1];
    let length = 0;
    let headerLength = 2;

    if (lenByte < 0x80) {
      length = lenByte;
    } else {
      const numBytes = lenByte & 0x7f;
      headerLength = 2 + numBytes;
      if (offset + headerLength > buffer.length) return null;

      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | buffer[offset + 2 + i];
      }
    }

    const valueStart = offset + headerLength;
    const valueEnd = valueStart + length;
    if (valueEnd > buffer.length) {
      // truncated value
      return null;
    }

    const data = buffer.slice(valueStart, valueEnd);
    const children: Asn1Node[] = [];

    // Is constructed (Sequence, Set, Explicit Tag)
    const isConstructed = (tag & 0x20) !== 0;
    if (isConstructed && length > 0) {
      let subOffset = 0;
      while (subOffset < data.length) {
        const child = this.decodeTlv(data, subOffset);
        if (!child) break;
        children.push(child);
        subOffset += child.headerLength + child.length;
      }
    }

    return { tag, headerLength, length, data, children };
  }

  private static extractDn(nameNode: Asn1Node): string {
    const parts: string[] = [];

    for (const rdn of nameNode.children) {
      for (const attr of rdn.children) {
        if (attr.children.length >= 2) {
          const oidNode = attr.children[0];
          const valNode = attr.children[1];
          const oid = this.decodeOid(oidNode.data);
          const valStr = new TextDecoder('utf-8', { fatal: false }).decode(valNode.data);

          if (oid === '2.5.4.3') parts.push(`CN=${valStr}`);
          else if (oid === '2.5.4.10') parts.push(`O=${valStr}`);
          else if (oid === '2.5.4.11') parts.push(`OU=${valStr}`);
          else if (oid === '2.5.4.6') parts.push(`C=${valStr}`);
          else if (oid === '2.5.4.7') parts.push(`L=${valStr}`);
          else parts.push(`${oid}=${valStr}`);
        }
      }
    }

    return parts.length > 0 ? parts.join(', ') : 'CN=Unknown';
  }

  private static extractAlgorithm(algoNode: Asn1Node): string {
    if (algoNode.children.length > 0) {
      const oid = this.decodeOid(algoNode.children[0].data);
      const map: Record<string, string> = {
        '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
        '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
        '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
        '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
        '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
        '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
        '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
      };
      return map[oid] || oid;
    }
    return 'sha256WithRSAEncryption';
  }

  private static extractPublicKeyInfo(spkiNode: Asn1Node): { algo: string; bits: number } {
    let algo = 'RSA';
    let bits = 2048;

    if (spkiNode.children.length >= 2) {
      const algoNode = spkiNode.children[0];
      const bitStringNode = spkiNode.children[1];

      if (algoNode.children.length > 0) {
        const oid = this.decodeOid(algoNode.children[0].data);
        if (oid.startsWith('1.2.840.10045')) {
          algo = 'ECDSA';
          bits = 256;
        } else {
          algo = 'RSA';
        }
      }

      // If RSA, decode the BIT STRING which encapsulates RSAPublicKey (SEQUENCE { modulus, publicExponent })
      if (algo === 'RSA' && bitStringNode.data.length > 2) {
        // First byte of BIT STRING is unused bits counter (usually 0x00)
        const innerDer = bitStringNode.data.slice(1);
        const innerSeq = this.decodeTlv(innerDer, 0);
        if (innerSeq && innerSeq.children.length >= 2) {
          const modulusNode = innerSeq.children[0];
          let modLen = modulusNode.data.length;
          // Strip leading zero byte if present for positive integer
          if (modulusNode.data[0] === 0x00) {
            modLen -= 1;
          }
          bits = modLen * 8;
        }
      }
    }

    return { algo, bits };
  }

  private static extractSans(extNode: Asn1Node): string[] {
    const sans: string[] = [];
    const walk = (node: Asn1Node) => {
      // Check for SAN OID: 2.5.29.17
      if (node.children.length >= 2) {
        const oid = this.decodeOid(node.children[0].data);
        if (oid === '2.5.29.17') {
          // The extension value is wrapped in an OCTET STRING
          const valNode = node.children[node.children.length - 1];
          const inner = this.decodeTlv(valNode.data, 0);
          if (inner) {
            for (const item of inner.children) {
              const tag = item.tag;
              // dNSName is context-specific tag [2] = 0x82
              // iPAddress is context-specific tag [7] = 0x87
              if (tag === 0x82) {
                const dns = new TextDecoder('utf-8').decode(item.data);
                sans.push(`DNS:${dns}`);
              } else if (tag === 0x87) {
                if (item.data.length === 4) {
                  sans.push(`IP:${Array.from(item.data).join('.')}`);
                }
              }
            }
          }
        }
      }
      for (const child of node.children) {
        walk(child);
      }
    };
    walk(extNode);
    return sans;
  }

  private static parseTimeNode(timeNode: Asn1Node): Date {
    const str = new TextDecoder('ascii').decode(timeNode.data);
    if (timeNode.tag === 0x17) {
      // UTCTime: YYMMDDHHMMSSZ
      const yearPrefix = parseInt(str.substring(0, 2), 10) >= 50 ? '19' : '20';
      const iso = `${yearPrefix}${str.substring(0, 2)}-${str.substring(2, 4)}-${str.substring(
        4,
        6
      )}T${str.substring(6, 8)}:${str.substring(8, 10)}:${str.substring(10, 12)}Z`;
      return new Date(iso);
    } else {
      // GeneralizedTime: YYYYMMDDHHMMSSZ
      const iso = `${str.substring(0, 4)}-${str.substring(4, 6)}-${str.substring(
        6,
        8
      )}T${str.substring(8, 10)}:${str.substring(10, 12)}:${str.substring(12, 14)}Z`;
      return new Date(iso);
    }
  }

  private static decodeOid(data: Uint8Array): string {
    if (data.length === 0) return '';
    const first = data[0];
    const parts = [Math.floor(first / 40), first % 40];

    let val = 0;
    for (let i = 1; i < data.length; i++) {
      const b = data[i];
      val = (val << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) {
        parts.push(val);
        val = 0;
      }
    }

    return parts.join('.');
  }
}
