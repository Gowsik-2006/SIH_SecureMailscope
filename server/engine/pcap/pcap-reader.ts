/**
 * Robust binary reader for Classic PCAP (microsecond and nanosecond, big & little endian)
 * and PCAPNG files.
 */

export interface ParsedPacketHeader {
  frameNumber: number;
  timestampSec: number;
  timestampUsec: number;
  timestampEpochMs: number;
  capturedLength: number;
  originalLength: number;
  linkType: number;
  payload: Uint8Array;
}

export interface PcapFileMetadata {
  format: 'PCAP_CLASSIC' | 'PCAPNG';
  isLittleEndian: boolean;
  isNanosecond: boolean;
  linkType: number;
  snaplen: number;
  totalPackets: number;
}

export class PcapReader {
  /**
   * Parse an entire PCAP or PCAPNG buffer into individual packet records.
   */
  public static parse(buffer: Uint8Array): {
    metadata: PcapFileMetadata;
    packets: ParsedPacketHeader[];
  } {
    if (!buffer || buffer.length === 0) {
      throw new Error('Empty PCAP buffer: file contains 0 bytes.');
    }

    if (buffer.length < 24) {
      throw new Error(`Truncated PCAP header: buffer has only ${buffer.length} bytes.`);
    }

    // Check PCAPNG Section Header Block magic: 0x0A0D0D0A
    const isPcapNg =
      buffer[0] === 0x0a &&
      buffer[1] === 0x0d &&
      buffer[2] === 0x0d &&
      buffer[3] === 0x0a;

    if (isPcapNg) {
      return this.parsePcapNg(buffer);
    }

    return this.parseClassicPcap(buffer);
  }

  private static parseClassicPcap(buffer: Uint8Array): {
    metadata: PcapFileMetadata;
    packets: ParsedPacketHeader[];
  } {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const magic = view.getUint32(0, false);

    let isLittleEndian = false;
    let isNanosecond = false;

    if (magic === 0xa1b2c3d4) {
      isLittleEndian = false;
      isNanosecond = false;
    } else if (magic === 0xd4c3b2a1) {
      isLittleEndian = true;
      isNanosecond = false;
    } else if (magic === 0xa1b23c4d) {
      isLittleEndian = false;
      isNanosecond = true;
    } else if (magic === 0x4d3cb2a1) {
      isLittleEndian = true;
      isNanosecond = true;
    } else {
      throw new Error(
        `Invalid PCAP magic header: 0x${magic.toString(16).padStart(8, '0')}. Not a valid PCAP file.`
      );
    }

    const versionMajor = view.getUint16(4, isLittleEndian);
    const versionMinor = view.getUint16(6, isLittleEndian);
    const snaplen = view.getUint32(16, isLittleEndian);
    const linkType = view.getUint32(20, isLittleEndian);

    const packets: ParsedPacketHeader[] = [];
    let offset = 24;
    let frameNumber = 1;

    while (offset + 16 <= buffer.length) {
      const tsSec = view.getUint32(offset, isLittleEndian);
      const tsSubSec = view.getUint32(offset + 4, isLittleEndian);
      const capturedLength = view.getUint32(offset + 8, isLittleEndian);
      const originalLength = view.getUint32(offset + 12, isLittleEndian);
      offset += 16;

      if (capturedLength > 65535 * 4 || capturedLength < 0) {
        // Sanity check against corrupted length
        break;
      }

      if (offset + capturedLength > buffer.length) {
        // Truncated packet at end of capture
        break;
      }

      const packetData = buffer.slice(offset, offset + capturedLength);
      offset += capturedLength;

      const usec = isNanosecond ? Math.floor(tsSubSec / 1000) : tsSubSec;
      const timestampEpochMs = tsSec * 1000 + Math.floor(usec / 1000);

      packets.push({
        frameNumber,
        timestampSec: tsSec,
        timestampUsec: usec,
        timestampEpochMs,
        capturedLength,
        originalLength,
        linkType,
        payload: packetData,
      });

      frameNumber++;
    }

    return {
      metadata: {
        format: 'PCAP_CLASSIC',
        isLittleEndian,
        isNanosecond,
        linkType,
        snaplen,
        totalPackets: packets.length,
      },
      packets,
    };
  }

  private static parsePcapNg(buffer: Uint8Array): {
    metadata: PcapFileMetadata;
    packets: ParsedPacketHeader[];
  } {
    let offset = 0;
    let isLittleEndian = true;
    let defaultLinkType = 1; // Ethernet default
    const packets: ParsedPacketHeader[] = [];
    let frameNumber = 1;

    while (offset + 8 <= buffer.length) {
      const blockView = new DataView(buffer.buffer, buffer.byteOffset + offset, 8);
      let blockType = blockView.getUint32(0, isLittleEndian);
      let blockLen = blockView.getUint32(4, isLittleEndian);

      // Section Header Block (SHB)
      if (blockType === 0x0a0d0d0a) {
        if (offset + 16 <= buffer.length) {
          const byteOrderMagic = new DataView(
            buffer.buffer,
            buffer.byteOffset + offset + 8,
            4
          ).getUint32(0, false);
          if (byteOrderMagic === 0x1a2b3c4d) {
            isLittleEndian = false;
          } else {
            isLittleEndian = true;
          }
          // re-read blockLen with correct endianness
          blockLen = new DataView(buffer.buffer, buffer.byteOffset + offset + 4, 4).getUint32(
            0,
            isLittleEndian
          );
        }
      }

      if (blockLen < 12 || offset + blockLen > buffer.length) {
        break; // Corrupted block or reached end
      }

      // Interface Description Block (IDB: 0x00000001)
      if (blockType === 0x00000001 && blockLen >= 16) {
        const idbView = new DataView(buffer.buffer, buffer.byteOffset + offset + 8, 4);
        defaultLinkType = idbView.getUint16(0, isLittleEndian);
      }

      // Enhanced Packet Block (EPB: 0x00000006)
      if (blockType === 0x00000006 && blockLen >= 32) {
        const epbView = new DataView(buffer.buffer, buffer.byteOffset + offset + 8, 20);
        const ifaceId = epbView.getUint32(0, isLittleEndian);
        const tsHigh = epbView.getUint32(4, isLittleEndian);
        const tsLow = epbView.getUint32(8, isLittleEndian);
        const capturedLength = epbView.getUint32(12, isLittleEndian);
        const originalLength = epbView.getUint32(16, isLittleEndian);

        const packetDataOffset = offset + 28;
        if (packetDataOffset + capturedLength <= offset + blockLen - 4) {
          const packetData = buffer.slice(packetDataOffset, packetDataOffset + capturedLength);

          // Timestamp is 64-bit microsecond counter
          const tsBig = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
          const tsSec = Number(tsBig / 1000000n);
          const tsUsec = Number(tsBig % 1000000n);
          const timestampEpochMs = Math.floor(Number(tsBig) / 1000);

          packets.push({
            frameNumber,
            timestampSec: tsSec,
            timestampUsec: tsUsec,
            timestampEpochMs,
            capturedLength,
            originalLength,
            linkType: defaultLinkType,
            payload: packetData,
          });

          frameNumber++;
        }
      }

      offset += blockLen;
    }

    return {
      metadata: {
        format: 'PCAPNG',
        isLittleEndian,
        isNanosecond: false,
        linkType: defaultLinkType,
        snaplen: 65535,
        totalPackets: packets.length,
      },
      packets,
    };
  }
}
