import { RawPacket, PacketFlags } from '../../../shared/types.ts';
import { ParsedPacketHeader } from '../pcap/pcap-reader.ts';

export class LinkIpTcpParser {
  /**
   * Convert an array of parsed packet headers into typed RawPacket objects
   * resolving Ethernet/SLL/VLAN, IPv4/IPv6, and TCP transport layers.
   */
  public static parsePacket(parsed: ParsedPacketHeader): RawPacket | null {
    const data = parsed.payload;
    if (!data || data.length < 14) {
      return null;
    }

    let linkType = parsed.linkType;
    let offset = 0;
    let etherType = 0;
    let vlanId: number | undefined;
    let srcMac: string | undefined;
    let dstMac: string | undefined;

    // Link Layer Decoding
    if (linkType === 1) {
      // Standard Ethernet II
      dstMac = this.formatMac(data.slice(0, 6));
      srcMac = this.formatMac(data.slice(6, 12));
      etherType = (data[12] << 8) | data[13];
      offset = 14;

      // Check 802.1Q VLAN Tag
      if (etherType === 0x8100 && data.length >= offset + 4) {
        vlanId = ((data[offset] & 0x0f) << 8) | data[offset + 1];
        etherType = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
      }
    } else if (linkType === 113) {
      // Linux Cooked SLL
      if (data.length < 16) return null;
      etherType = (data[14] << 8) | data[15];
      offset = 16;
    } else if (linkType === 276) {
      // Linux Cooked SLL2
      if (data.length < 20) return null;
      etherType = (data[0] << 8) | data[1];
      offset = 20;
    } else if (linkType === 101 || linkType === 12) {
      // Raw IP
      const ver = data[0] >> 4;
      etherType = ver === 6 ? 0x86dd : 0x0800;
      offset = 0;
    } else {
      // Fallback try to sniff IPv4 or IPv6
      const ver = data[0] >> 4;
      if (ver === 4) {
        etherType = 0x0800;
        offset = 0;
      } else if (ver === 6) {
        etherType = 0x86dd;
        offset = 0;
      } else {
        return null;
      }
    }

    // Network Layer Decoding
    let ipVersion: 4 | 6 | 0 = 0;
    let srcIp = '';
    let dstIp = '';
    let transportProto: 'TCP' | 'UDP' | 'OTHER' = 'OTHER';
    let ipHeaderLength = 0;

    if (etherType === 0x0800) {
      // IPv4
      if (data.length < offset + 20) return null;
      ipVersion = 4;
      const ihl = (data[offset] & 0x0f) * 4;
      if (ihl < 20 || data.length < offset + ihl) return null;
      ipHeaderLength = ihl;

      const protoNum = data[offset + 9];
      if (protoNum === 6) transportProto = 'TCP';
      else if (protoNum === 17) transportProto = 'UDP';

      srcIp = `${data[offset + 12]}.${data[offset + 13]}.${data[offset + 14]}.${data[offset + 15]}`;
      dstIp = `${data[offset + 16]}.${data[offset + 17]}.${data[offset + 18]}.${data[offset + 19]}`;
      offset += ihl;
    } else if (etherType === 0x86dd) {
      // IPv6
      if (data.length < offset + 40) return null;
      ipVersion = 6;
      ipHeaderLength = 40;
      let nextHeader = data[offset + 6];

      srcIp = this.formatIpv6(data.slice(offset + 8, offset + 24));
      dstIp = this.formatIpv6(data.slice(offset + 24, offset + 40));
      offset += 40;

      // Handle common extension headers until TCP/UDP
      while (nextHeader !== 6 && nextHeader !== 17 && offset < data.length) {
        if (nextHeader === 0 || nextHeader === 43 || nextHeader === 60) {
          // Hop-by-Hop, Routing, Destination options
          const extLen = (data[offset + 1] + 1) * 8;
          nextHeader = data[offset];
          offset += extLen;
        } else {
          break;
        }
      }

      if (nextHeader === 6) transportProto = 'TCP';
      else if (nextHeader === 17) transportProto = 'UDP';
    } else {
      return null;
    }

    // Transport Layer (TCP)
    let srcPort = 0;
    let dstPort = 0;
    let tcpSeq: number | undefined;
    let tcpAck: number | undefined;
    let tcpFlags: PacketFlags | undefined;
    let tcpWindow: number | undefined;
    let payloadOffset = offset;
    let payloadLength = 0;

    if (transportProto === 'TCP') {
      if (data.length < offset + 20) return null;
      const tcpView = new DataView(data.buffer, data.byteOffset + offset, data.byteLength - offset);
      srcPort = tcpView.getUint16(0, false);
      dstPort = tcpView.getUint16(2, false);
      tcpSeq = tcpView.getUint32(4, false);
      tcpAck = tcpView.getUint32(8, false);

      const dataOffsetBytes = ((data[offset + 12] >> 4) & 0x0f) * 4;
      if (dataOffsetBytes < 20 || data.length < offset + dataOffsetBytes) {
        return null;
      }

      const flagsByte = data[offset + 13];
      tcpFlags = {
        urg: (flagsByte & 0x20) !== 0,
        ack: (flagsByte & 0x10) !== 0,
        psh: (flagsByte & 0x08) !== 0,
        rst: (flagsByte & 0x04) !== 0,
        syn: (flagsByte & 0x02) !== 0,
        fin: (flagsByte & 0x01) !== 0,
      };

      tcpWindow = tcpView.getUint16(14, false);
      payloadOffset = offset + dataOffsetBytes;
      payloadLength = Math.max(0, data.length - payloadOffset);
    } else if (transportProto === 'UDP') {
      if (data.length < offset + 8) return null;
      const udpView = new DataView(data.buffer, data.byteOffset + offset, 8);
      srcPort = udpView.getUint16(0, false);
      dstPort = udpView.getUint16(2, false);
      payloadOffset = offset + 8;
      payloadLength = Math.max(0, data.length - payloadOffset);
    }

    const payloadBytes = data.slice(payloadOffset, payloadOffset + payloadLength);
    const payloadHexSnippet = this.toHexSnippet(payloadBytes, 32);
    const payloadAsciiSnippet = this.toAsciiSnippet(payloadBytes, 64);

    return {
      frameNumber: parsed.frameNumber,
      timestampSec: parsed.timestampSec,
      timestampUsec: parsed.timestampUsec,
      timestampEpochMs: parsed.timestampEpochMs,
      linkType,
      capturedLength: parsed.capturedLength,
      originalLength: parsed.originalLength,
      srcMac,
      dstMac,
      vlanId,
      ipVersion,
      srcIp,
      dstIp,
      transportProto,
      srcPort,
      dstPort,
      tcpSeq,
      tcpAck,
      tcpFlags,
      tcpWindow,
      payloadOffset,
      payloadLength,
      payloadHexSnippet,
      payloadAsciiSnippet,
      data,
    };
  }

  private static formatMac(buf: Uint8Array): string {
    return Array.from(buf)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':');
  }

  private static formatIpv6(buf: Uint8Array): string {
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buf[i] << 8) | buf[i + 1]).toString(16));
    }
    return parts.join(':');
  }

  public static toHexSnippet(buf: Uint8Array, maxBytes = 32): string {
    const slice = buf.slice(0, maxBytes);
    return Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
  }

  public static toAsciiSnippet(buf: Uint8Array, maxBytes = 64): string {
    const slice = buf.slice(0, maxBytes);
    let str = '';
    for (let i = 0; i < slice.length; i++) {
      const code = slice[i];
      if (code >= 32 && code <= 126) {
        str += String.fromCharCode(code);
      } else if (code === 10 || code === 13) {
        str += ' ';
      } else {
        str += '.';
      }
    }
    return str.trim();
  }
}
