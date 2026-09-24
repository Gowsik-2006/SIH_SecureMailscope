import { RawPacket, ConversationTurn } from '../../../shared/types.ts';

export interface StreamSegment {
  frameNumber: number;
  timestamp: number;
  direction: 'C2S' | 'S2C';
  seq: number;
  payload: Uint8Array;
  byteOffsetInDirection: number;
}

export interface ReassembledStream {
  streamKey: string;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  startTime: number;
  endTime: number;
  packets: RawPacket[];
  c2sData: Uint8Array;
  s2cData: Uint8Array;
  c2sSegments: StreamSegment[];
  s2cSegments: StreamSegment[];
  turns: ConversationTurn[];
}

export class TcpReassembler {
  /**
   * Group raw packets into TCP streams and reassemble payload streams bidirectionally.
   */
  public static process(packets: RawPacket[]): ReassembledStream[] {
    const streamMap = new Map<string, RawPacket[]>();

    for (const pkt of packets) {
      if (pkt.transportProto !== 'TCP') continue;
      const key = this.getStreamKey(pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort);
      let list = streamMap.get(key);
      if (!list) {
        list = [];
        streamMap.set(key, list);
      }
      list.push(pkt);
    }

    const reassembled: ReassembledStream[] = [];
    for (const [key, streamPackets] of streamMap.entries()) {
      const stream = this.reassembleStream(key, streamPackets);
      if (stream) {
        reassembled.push(stream);
      }
    }

    return reassembled;
  }

  private static getStreamKey(ip1: string, p1: number, ip2: string, p2: number): string {
    const end1 = `${ip1}:${p1}`;
    const end2 = `${ip2}:${p2}`;
    return end1 < end2 ? `${end1}<->${end2}` : `${end2}<->${end1}`;
  }

  private static reassembleStream(streamKey: string, packets: RawPacket[]): ReassembledStream | null {
    if (packets.length === 0) return null;

    // Sort chronologically by timestamp
    packets.sort((a, b) => a.timestampEpochMs - b.timestampEpochMs);

    // Determine Client vs Server
    let clientIp = packets[0].srcIp;
    let clientPort = packets[0].srcPort;
    let serverIp = packets[0].dstIp;
    let serverPort = packets[0].dstPort;

    // Check for standard email server ports
    const emailServerPorts = [25, 465, 587, 110, 995, 143, 993, 2525];
    const firstPkt = packets[0];

    // Priority 1: Check SYN packet
    const synPkt = packets.find((p) => p.tcpFlags?.syn && !p.tcpFlags?.ack);
    if (synPkt) {
      clientIp = synPkt.srcIp;
      clientPort = synPkt.srcPort;
      serverIp = synPkt.dstIp;
      serverPort = synPkt.dstPort;
    } else if (emailServerPorts.includes(firstPkt.dstPort)) {
      clientIp = firstPkt.srcIp;
      clientPort = firstPkt.srcPort;
      serverIp = firstPkt.dstIp;
      serverPort = firstPkt.dstPort;
    } else if (emailServerPorts.includes(firstPkt.srcPort)) {
      clientIp = firstPkt.dstIp;
      clientPort = firstPkt.dstPort;
      serverIp = firstPkt.srcIp;
      serverPort = firstPkt.srcPort;
    }

    // Split packets into C2S and S2C
    const c2sPackets: RawPacket[] = [];
    const s2cPackets: RawPacket[] = [];

    for (const pkt of packets) {
      if (pkt.srcIp === clientIp && pkt.srcPort === clientPort) {
        c2sPackets.push(pkt);
      } else {
        s2cPackets.push(pkt);
      }
    }

    const { data: c2sData, segments: c2sSegments } = this.reassembleDirection(c2sPackets, 'C2S');
    const { data: s2cData, segments: s2cSegments } = this.reassembleDirection(s2cPackets, 'S2C');

    // Extract chronological conversation turns
    const turns = this.extractTurns(packets, clientIp, clientPort);

    const startTime = packets[0].timestampEpochMs;
    const endTime = packets[packets.length - 1].timestampEpochMs;

    return {
      streamKey,
      clientIp,
      clientPort,
      serverIp,
      serverPort,
      startTime,
      endTime,
      packets,
      c2sData,
      s2cData,
      c2sSegments,
      s2cSegments,
      turns,
    };
  }

  /**
   * Reassemble directional TCP segments with sequence tracking, deduplication,
   * overlap resolution, and wraparound handling.
   */
  private static reassembleDirection(
    pkts: RawPacket[],
    direction: 'C2S' | 'S2C'
  ): { data: Uint8Array; segments: StreamSegment[] } {
    // Filter packets with actual payload
    const payloadPkts = pkts.filter((p) => p.payloadLength > 0 && p.tcpSeq !== undefined);
    if (payloadPkts.length === 0) {
      return { data: new Uint8Array(0), segments: [] };
    }

    // Sort by sequence number handling 32-bit wrapping
    // We establish the initial sequence number (ISN) from the earliest packet
    const isn = payloadPkts[0].tcpSeq!;

    const normalized = payloadPkts.map((p) => {
      // relative sequence offset
      let relSeq = (p.tcpSeq! - isn) >>> 0;
      return {
        pkt: p,
        relSeq,
        payload: p.data.slice(p.payloadOffset, p.payloadOffset + p.payloadLength),
      };
    });

    normalized.sort((a, b) => a.relSeq - b.relSeq);

    const chunks: Uint8Array[] = [];
    const segments: StreamSegment[] = [];
    let currentByteOffset = 0;
    let expectedNextSeq = 0;

    for (const item of normalized) {
      const payload = item.payload;
      const pkt = item.pkt;

      if (chunks.length === 0) {
        chunks.push(payload);
        segments.push({
          frameNumber: pkt.frameNumber,
          timestamp: pkt.timestampEpochMs,
          direction,
          seq: pkt.tcpSeq!,
          payload,
          byteOffsetInDirection: currentByteOffset,
        });
        currentByteOffset += payload.length;
        expectedNextSeq = item.relSeq + payload.length;
        continue;
      }

      // Check for duplicate or overlap
      if (item.relSeq < expectedNextSeq) {
        const overlap = expectedNextSeq - item.relSeq;
        if (overlap >= payload.length) {
          // Fully duplicate packet, ignore
          continue;
        }
        // Partial overlap: slice off overlapping bytes
        const freshPayload = payload.slice(overlap);
        chunks.push(freshPayload);
        segments.push({
          frameNumber: pkt.frameNumber,
          timestamp: pkt.timestampEpochMs,
          direction,
          seq: pkt.tcpSeq! + overlap,
          payload: freshPayload,
          byteOffsetInDirection: currentByteOffset,
        });
        currentByteOffset += freshPayload.length;
        expectedNextSeq += freshPayload.length;
      } else {
        // Gap or in-order
        chunks.push(payload);
        segments.push({
          frameNumber: pkt.frameNumber,
          timestamp: pkt.timestampEpochMs,
          direction,
          seq: pkt.tcpSeq!,
          payload,
          byteOffsetInDirection: currentByteOffset,
        });
        currentByteOffset += payload.length;
        expectedNextSeq = item.relSeq + payload.length;
      }
    }

    const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
    const combined = new Uint8Array(totalLen);
    let writePos = 0;
    for (const c of chunks) {
      combined.set(c, writePos);
      writePos += c.length;
    }

    return { data: combined, segments };
  }

  private static extractTurns(
    packets: RawPacket[],
    clientIp: string,
    clientPort: number
  ): ConversationTurn[] {
    const turns: ConversationTurn[] = [];

    for (const pkt of packets) {
      if (pkt.payloadLength === 0) continue;
      const isC2S = pkt.srcIp === clientIp && pkt.srcPort === clientPort;
      const payload = pkt.data.slice(pkt.payloadOffset, pkt.payloadOffset + pkt.payloadLength);

      // Check if this payload is TLS record
      let isTls = false;
      let tlsContentType: number | undefined;
      let tlsHandshakeType: number | undefined;

      if (payload.length >= 5) {
        const ct = payload[0];
        const major = payload[1];
        if ((ct >= 20 && ct <= 23) && (major === 3)) {
          isTls = true;
          tlsContentType = ct;
          if (ct === 22 && payload.length >= 6) {
            tlsHandshakeType = payload[5];
          }
        }
      }

      let text = '';
      if (isTls) {
        text = `[TLS Record Type 0x${tlsContentType?.toString(16).padStart(2, '0')}${
          tlsHandshakeType !== undefined ? ` HandshakeType 0x${tlsHandshakeType.toString(16)}` : ''
        }, Length: ${payload.length}B]`;
      } else {
        text = new TextDecoder('utf-8', { fatal: false }).decode(payload).trim();
        if (!text) {
          text = `[Binary Payload ${payload.length}B]`;
        }
      }

      turns.push({
        frameNumber: pkt.frameNumber,
        timestamp: pkt.timestampEpochMs,
        direction: isC2S ? 'C2S' : 'S2C',
        text,
        isTls,
        tlsContentType,
        tlsHandshakeType,
      });
    }

    return turns;
  }
}
