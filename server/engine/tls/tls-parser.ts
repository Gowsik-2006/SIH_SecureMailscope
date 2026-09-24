import { CipherDetails } from '../../../shared/types.ts';
import { CipherRegistry } from './cipher-registry.ts';

export interface ParsedTlsSession {
  clientHelloFound: boolean;
  serverHelloFound: boolean;
  negotiatedVersion?: string;
  clientOfferedVersions: string[];
  clientSni?: string;
  clientCipherSuites: CipherDetails[];
  selectedCipherSuite?: CipherDetails;
  certificatesDer: Uint8Array[];
  isTls13: boolean;
  isHelloRetryRequest: boolean;
  alerts: { level: 'warning' | 'fatal'; code: number; description: string }[];
}

export class TlsParser {
  public static parseHandshakeData(data: Uint8Array): ParsedTlsSession {
    const result: ParsedTlsSession = {
      clientHelloFound: false,
      serverHelloFound: false,
      clientOfferedVersions: [],
      clientCipherSuites: [],
      certificatesDer: [],
      isTls13: false,
      isHelloRetryRequest: false,
      alerts: [],
    };

    if (!data || data.length < 5) {
      return result;
    }

    let offset = 0;
    while (offset + 5 <= data.length) {
      const contentType = data[offset];
      const recordVerMajor = data[offset + 1];
      const recordVerMinor = data[offset + 2];
      const recordLen = (data[offset + 3] << 8) | data[offset + 4];

      const isValidTlsHeader =
        contentType >= 20 &&
        contentType <= 23 &&
        recordVerMajor === 3 &&
        recordVerMinor <= 4 &&
        recordLen > 0 &&
        recordLen <= 20000;

      if (!isValidTlsHeader) {
        // Not a TLS record header at this offset (e.g. preceding plaintext SMTP commands), advance 1 byte
        offset++;
        continue;
      }

      if (offset + 5 + recordLen > data.length) {
        // Truncated trailing record
        break;
      }

      const recordPayload = data.slice(offset + 5, offset + 5 + recordLen);
      offset += 5 + recordLen;

      // Handle Alerts (ContentType = 21)
      if (contentType === 21 && recordPayload.length >= 2) {
        const levelCode = recordPayload[0];
        const descCode = recordPayload[1];
        result.alerts.push({
          level: levelCode === 2 ? 'fatal' : 'warning',
          code: descCode,
          description: this.getAlertDescription(descCode),
        });
        continue;
      }

      // Handle Handshake (ContentType = 22)
      if (contentType === 22) {
        this.parseHandshakeRecords(recordPayload, result, recordVerMinor);
      }
    }

    return result;
  }

  private static parseHandshakeRecords(
    payload: Uint8Array,
    result: ParsedTlsSession,
    recordMinor: number
  ) {
    let pOffset = 0;
    while (pOffset + 4 <= payload.length) {
      const handshakeType = payload[pOffset];
      const length = (payload[pOffset + 1] << 16) | (payload[pOffset + 2] << 8) | payload[pOffset + 3];
      pOffset += 4;

      if (pOffset + length > payload.length) {
        break;
      }

      const msg = payload.slice(pOffset, pOffset + length);
      pOffset += length;

      if (handshakeType === 1) {
        // ClientHello
        result.clientHelloFound = true;
        this.parseClientHello(msg, result);
      } else if (handshakeType === 2) {
        // ServerHello
        result.serverHelloFound = true;
        this.parseServerHello(msg, result, recordMinor);
      } else if (handshakeType === 11) {
        // Certificate
        this.parseCertificateMessage(msg, result);
      }
    }
  }

  private static parseClientHello(msg: Uint8Array, result: ParsedTlsSession) {
    if (msg.length < 34) return;
    const clientVer = (msg[0] << 8) | msg[1];
    result.clientOfferedVersions.push(this.formatVersion(clientVer));

    // skip 32 bytes random
    let cursor = 34;
    if (cursor >= msg.length) return;

    const sessionIdLen = msg[cursor];
    cursor += 1 + sessionIdLen;
    if (cursor + 2 > msg.length) return;

    const cipherSuitesLen = (msg[cursor] << 8) | msg[cursor + 1];
    cursor += 2;
    if (cursor + cipherSuitesLen > msg.length) return;

    for (let i = 0; i < cipherSuitesLen; i += 2) {
      const c = (msg[cursor + i] << 8) | msg[cursor + i + 1];
      result.clientCipherSuites.push(CipherRegistry.lookup(c));
    }
    cursor += cipherSuitesLen;

    if (cursor >= msg.length) return;
    const compLen = msg[cursor];
    cursor += 1 + compLen;

    if (cursor + 2 > msg.length) return;
    const extLen = (msg[cursor] << 8) | msg[cursor + 1];
    cursor += 2;

    const extEnd = cursor + extLen;
    while (cursor + 4 <= extEnd && cursor + 4 <= msg.length) {
      const extType = (msg[cursor] << 8) | msg[cursor + 1];
      const eLen = (msg[cursor + 2] << 8) | msg[cursor + 3];
      cursor += 4;
      if (cursor + eLen > msg.length) break;

      const extData = msg.slice(cursor, cursor + eLen);
      cursor += eLen;

      // SNI extension (0x0000)
      if (extType === 0x0000 && extData.length >= 5) {
        const nameLen = (extData[3] << 8) | extData[4];
        if (5 + nameLen <= extData.length) {
          result.clientSni = new TextDecoder('utf-8').decode(extData.slice(5, 5 + nameLen));
        }
      }

      // Supported Versions extension (0x002b)
      if (extType === 0x002b && extData.length >= 1) {
        const vListLen = extData[0];
        for (let i = 1; i + 2 <= extData.length && i <= vListLen; i += 2) {
          const v = (extData[i] << 8) | extData[i + 1];
          const vStr = this.formatVersion(v);
          if (!result.clientOfferedVersions.includes(vStr)) {
            result.clientOfferedVersions.push(vStr);
          }
        }
      }
    }
  }

  private static parseServerHello(msg: Uint8Array, result: ParsedTlsSession, recordMinor: number) {
    if (msg.length < 38) return;
    const legacyVer = (msg[0] << 8) | msg[1];
    result.negotiatedVersion = this.formatVersion(legacyVer);

    // Check HelloRetryRequest random magic
    if (msg.length >= 34) {
      const randomBytes = msg.slice(2, 34);
      // HRR random SHA256("HelloRetryRequest"):
      // cf 21 ad 74 e5 9a 61 11 be 1d 8c 02 fe 63 29 cb ac c8 5e 9a a9 59 e0 87 23 be ef c7 e1 db bb 40
      if (randomBytes[0] === 0xcf && randomBytes[1] === 0x21 && randomBytes[2] === 0xad) {
        result.isHelloRetryRequest = true;
      }
    }

    let cursor = 34;
    const sessLen = msg[cursor];
    cursor += 1 + sessLen;
    if (cursor + 2 > msg.length) return;

    const selectedCipher = (msg[cursor] << 8) | msg[cursor + 1];
    result.selectedCipherSuite = CipherRegistry.lookup(selectedCipher);
    cursor += 2;

    if (cursor >= msg.length) return;
    const compMethod = msg[cursor];
    cursor += 1;

    // Server Extensions
    if (cursor + 2 <= msg.length) {
      const extLen = (msg[cursor] << 8) | msg[cursor + 1];
      cursor += 2;
      const extEnd = cursor + extLen;

      while (cursor + 4 <= extEnd && cursor + 4 <= msg.length) {
        const extType = (msg[cursor] << 8) | msg[cursor + 1];
        const eLen = (msg[cursor + 2] << 8) | msg[cursor + 3];
        cursor += 4;
        if (cursor + eLen > msg.length) break;

        const extData = msg.slice(cursor, cursor + eLen);
        cursor += eLen;

        // Supported Versions extension (0x002b) -> TLS 1.3 negotiated!
        if (extType === 0x002b && extData.length >= 2) {
          const actualVer = (extData[0] << 8) | extData[1];
          if (actualVer === 0x0304) {
            result.isTls13 = true;
            result.negotiatedVersion = 'TLSv1.3';
          } else {
            result.negotiatedVersion = this.formatVersion(actualVer);
          }
        }
      }
    }

    if (selectedCipher >= 0x1301 && selectedCipher <= 0x1305) {
      result.isTls13 = true;
      result.negotiatedVersion = 'TLSv1.3';
    }
  }

  private static parseCertificateMessage(msg: Uint8Array, result: ParsedTlsSession) {
    if (msg.length < 3) return;

    let cursor = 0;

    // TLS 1.3 Certificate message has 1-byte requestContextLen first
    if (result.isTls13) {
      const reqContextLen = msg[0];
      cursor = 1 + reqContextLen;
      if (cursor + 3 > msg.length) return;
    }

    const certListLen = (msg[cursor] << 16) | (msg[cursor + 1] << 8) | msg[cursor + 2];
    cursor += 3;
    const listEnd = cursor + certListLen;

    while (cursor + 3 <= listEnd && cursor + 3 <= msg.length) {
      const certLen = (msg[cursor] << 16) | (msg[cursor + 1] << 8) | msg[cursor + 2];
      cursor += 3;
      if (cursor + certLen > msg.length) break;

      const certDer = msg.slice(cursor, cursor + certLen);
      result.certificatesDer.push(certDer);
      cursor += certLen;

      // In TLS 1.3, each certificate in the list is followed by a 2-byte extensions length
      if (result.isTls13 && cursor + 2 <= msg.length) {
        const certExtLen = (msg[cursor] << 8) | msg[cursor + 1];
        cursor += 2 + certExtLen;
      }
    }
  }

  public static formatVersion(verCode: number): string {
    switch (verCode) {
      case 0x0200:
        return 'SSLv2.0';
      case 0x0300:
        return 'SSLv3.0';
      case 0x0301:
        return 'TLSv1.0';
      case 0x0302:
        return 'TLSv1.1';
      case 0x0303:
        return 'TLSv1.2';
      case 0x0304:
        return 'TLSv1.3';
      default:
        return `TLS_0x${verCode.toString(16).padStart(4, '0')}`;
    }
  }

  private static getAlertDescription(code: number): string {
    const alerts: Record<number, string> = {
      0: 'close_notify',
      10: 'unexpected_message',
      20: 'bad_record_mac',
      21: 'decryption_failed',
      22: 'record_overflow',
      30: 'decompression_failure',
      40: 'handshake_failure',
      42: 'bad_certificate',
      43: 'unsupported_certificate',
      44: 'certificate_revoked',
      45: 'certificate_expired',
      46: 'certificate_unknown',
      47: 'illegal_parameter',
      48: 'unknown_ca',
      49: 'access_denied',
      50: 'decode_error',
      51: 'decrypt_error',
      70: 'protocol_version',
      71: 'insufficient_security',
      80: 'internal_error',
      90: 'user_canceled',
      100: 'no_renegotiation',
      110: 'unsupported_extension',
      115: 'unknown_psk_identity',
    };
    return alerts[code] || `unknown_alert_${code}`;
  }
}
