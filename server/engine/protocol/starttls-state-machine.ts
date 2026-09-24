import {
  EmailProtocol,
  StarttlsVerdict,
  ConversationTurn,
  EvidenceRef,
  SessionTimelineEvent,
} from '../../../shared/types.ts';
import { ReassembledStream } from '../reassembly/tcp-reassembler.ts';

export interface ProtocolAnalysisResult {
  protocol: EmailProtocol;
  starttlsVerdict: StarttlsVerdict;
  starttlsNegotiated: boolean;
  starttlsStripped: boolean;
  serverBanner?: string;
  credentialsExposed?: {
    type: string;
    username?: string;
    hasPlaintextPassword: boolean;
    evidence: EvidenceRef;
  };
  timeline: SessionTimelineEvent[];
}

export class StarttlsStateMachine {
  public static analyzeStream(stream: ReassembledStream): ProtocolAnalysisResult {
    const timeline: SessionTimelineEvent[] = [];
    let protocol: EmailProtocol = 'UNKNOWN';

    // 1. Port-based initial hint
    const serverPort = stream.serverPort;
    const clientPort = stream.clientPort;
    const isImplicitTlsPort = serverPort === 465 || serverPort === 993 || serverPort === 995;

    if (serverPort === 25 || serverPort === 587 || serverPort === 465 || serverPort === 2525) {
      protocol = 'SMTP';
    } else if (serverPort === 143 || serverPort === 993) {
      protocol = 'IMAP';
    } else if (serverPort === 110 || serverPort === 995) {
      protocol = 'POP3';
    }

    // 2. Decode text conversations
    const turns = stream.turns;
    let serverBanner: string | undefined;
    let clientCapabilitiesRequested = false;
    let serverAdvertisedStarttls = false;
    let clientSentStarttls = false;
    let starttlsFrameNumber = 0;
    let serverAcceptedStarttls = false;
    let starttlsAcceptFrameNumber = 0;
    let serverRejectedStarttls = false;
    let tlsClientHelloSeen = false;
    let plaintextCommandsAfterStarttls = false;
    let plaintextAuthFound = false;
    let exposedCreds:
      | { type: string; username?: string; hasPlaintextPassword: boolean; evidence: EvidenceRef }
      | undefined;

    // Check for direct implicit TLS handshake at start
    if (turns.length > 0 && turns[0].isTls && turns[0].direction === 'C2S') {
      timeline.push({
        timestamp: turns[0].timestamp,
        frameNumber: turns[0].frameNumber,
        stage: 'TLS_HANDSHAKE_INIT',
        description: 'Direct TLS ClientHello detected on connection initiation.',
      });
      return {
        protocol: protocol !== 'UNKNOWN' ? protocol : 'SMTP',
        starttlsVerdict: 'encrypted_implicit_tls',
        starttlsNegotiated: true,
        starttlsStripped: false,
        timeline,
      };
    }

    // Process plaintext stream turns
    for (const turn of turns) {
      if (turn.isTls) {
        if (turn.tlsContentType === 22 && turn.tlsHandshakeType === 1) {
          tlsClientHelloSeen = true;
          timeline.push({
            timestamp: turn.timestamp,
            frameNumber: turn.frameNumber,
            stage: 'TLS_CLIENT_HELLO',
            description: 'TLS ClientHello observed on the stream.',
          });
        }
        continue;
      }

      const text = turn.text;
      const upper = text.toUpperCase();

      // Check protocol signature from banners
      if (turn.direction === 'S2C') {
        if (!serverBanner && text.length > 0) {
          serverBanner = text.split('\r\n')[0].substring(0, 120);
          timeline.push({
            timestamp: turn.timestamp,
            frameNumber: turn.frameNumber,
            stage: 'SERVER_BANNER',
            description: `Server banner: "${serverBanner}"`,
          });
        }

        if (protocol === 'UNKNOWN') {
          if (text.startsWith('220 ') || text.includes('ESMTP') || text.includes('Postfix')) {
            protocol = 'SMTP';
          } else if (text.startsWith('* OK') || text.includes('IMAP4')) {
            protocol = 'IMAP';
          } else if (text.startsWith('+OK') || text.includes('POP3')) {
            protocol = 'POP3';
          }
        }

        // Check STARTTLS capability in server responses
        if (protocol === 'SMTP') {
          if (upper.includes('250-STARTTLS') || upper.includes('250 STARTTLS')) {
            serverAdvertisedStarttls = true;
            timeline.push({
              timestamp: turn.timestamp,
              frameNumber: turn.frameNumber,
              stage: 'CAPABILITY_ADVERTISEMENT',
              description: 'Server advertised 250 STARTTLS capability.',
            });
          }
          if (clientSentStarttls) {
            if (text.startsWith('220 ') || upper.includes('READY TO START TLS') || upper.includes('GO AHEAD')) {
              serverAcceptedStarttls = true;
              starttlsAcceptFrameNumber = turn.frameNumber;
              timeline.push({
                timestamp: turn.timestamp,
                frameNumber: turn.frameNumber,
                stage: 'STARTTLS_ACCEPTED',
                description: 'Server accepted STARTTLS with 220 confirmation.',
              });
            } else if (text.startsWith('454 ') || text.startsWith('500 ') || text.startsWith('502 ')) {
              serverRejectedStarttls = true;
              timeline.push({
                timestamp: turn.timestamp,
                frameNumber: turn.frameNumber,
                stage: 'STARTTLS_REJECTED',
                description: `Server rejected STARTTLS: ${text.substring(0, 80)}`,
                isError: true,
              });
            }
          }
        } else if (protocol === 'IMAP') {
          if (upper.includes('STARTTLS')) {
            serverAdvertisedStarttls = true;
          }
          if (clientSentStarttls && (upper.includes('OK BEGIN TLS') || upper.includes('OK COMPLETED'))) {
            serverAcceptedStarttls = true;
            starttlsAcceptFrameNumber = turn.frameNumber;
          }
        } else if (protocol === 'POP3') {
          if (upper.includes('STLS')) {
            serverAdvertisedStarttls = true;
          }
          if (clientSentStarttls && upper.startsWith('+OK')) {
            serverAcceptedStarttls = true;
            starttlsAcceptFrameNumber = turn.frameNumber;
          }
        }
      } else {
        // Client to Server
        const isGreeting =
          upper.startsWith('EHLO') ||
          upper.startsWith('HELO') ||
          upper.includes('CAPABILITY') ||
          upper.includes('CAPA');

        if (isGreeting) {
          clientCapabilitiesRequested = true;
          timeline.push({
            timestamp: turn.timestamp,
            frameNumber: turn.frameNumber,
            stage: 'CLIENT_GREETING',
            description: `Client requested capabilities: "${text.substring(0, 60)}"`,
          });
        }

        if (upper.startsWith('STARTTLS') || upper.startsWith('STLS') || upper.includes('STARTTLS') || upper.includes(' STLS')) {
          clientSentStarttls = true;
          starttlsFrameNumber = turn.frameNumber;
          timeline.push({
            timestamp: turn.timestamp,
            frameNumber: turn.frameNumber,
            stage: 'STARTTLS_REQUESTED',
            description: 'Client sent STARTTLS command to upgrade session to TLS.',
          });
        }

        // Check if client sends plaintext commands AFTER server accepted STARTTLS without TLS
        if (serverAcceptedStarttls && !tlsClientHelloSeen) {
          if (
            upper.startsWith('MAIL FROM:') ||
            upper.startsWith('RCPT TO:') ||
            upper.startsWith('AUTH ') ||
            upper.includes('LOGIN ') ||
            upper.startsWith('USER ')
          ) {
            plaintextCommandsAfterStarttls = true;
            timeline.push({
              timestamp: turn.timestamp,
              frameNumber: turn.frameNumber,
              stage: 'PLAINTEXT_LEAK_AFTER_STARTTLS',
              description: `Plaintext command sent despite STARTTLS acceptance: "${text.substring(0, 60)}"`,
              isSecurityWarning: true,
            });
          }
        }

        // Plaintext Credentials Inspection
        if (upper.startsWith('AUTH PLAIN') || upper.startsWith('AUTH LOGIN') || upper.startsWith('USER ') || upper.includes('LOGIN ')) {
          plaintextAuthFound = true;
          let username = 'redacted_user';
          if (upper.startsWith('USER ')) {
            username = text.substring(5).trim();
          } else if (upper.includes('LOGIN ')) {
            const loginPart = text.substring(text.indexOf('LOGIN ') + 6).trim();
            username = loginPart.split(' ')[0] || 'redacted_user';
          } else if (upper.startsWith('AUTH PLAIN ') && text.length > 11) {
            try {
              const b64 = text.substring(11).trim();
              const decoded = Buffer.from(b64, 'base64').toString('utf-8');
              const parts = decoded.split('\0').filter(Boolean);
              if (parts.length > 0) username = parts[0];
            } catch {
              // ignore decoding error
            }
          }

          exposedCreds = {
            type: upper.startsWith('AUTH PLAIN') ? 'AUTH_PLAIN' : upper.startsWith('AUTH LOGIN') ? 'AUTH_LOGIN' : 'POP3_IMAP_PLAINTEXT',
            username,
            hasPlaintextPassword: true,
            evidence: {
              frameNumber: turn.frameNumber,
              timestamp: turn.timestamp,
              streamKey: stream.streamKey,
              byteOffset: 0,
              length: text.length,
              snippetHex: Buffer.from(text.substring(0, 32)).toString('hex'),
              snippetAscii: text.substring(0, 48),
              description: `Cleartext authentication command transmitted over unencrypted connection.`,
            },
          };

          timeline.push({
            timestamp: turn.timestamp,
            frameNumber: turn.frameNumber,
            stage: 'CREDENTIAL_EXPOSURE',
            description: `Cleartext credential transmission detected (${exposedCreds.type}).`,
            isSecurityWarning: true,
          });
        }
      }
    }

    // Determine STARTTLS Verdict
    let starttlsVerdict: StarttlsVerdict = 'plaintext_unencrypted';
    let starttlsNegotiated = false;
    let starttlsStripped = false;

    if (serverAcceptedStarttls && tlsClientHelloSeen) {
      starttlsVerdict = 'clean_starttls';
      starttlsNegotiated = true;
      starttlsStripped = false;
    } else if (serverAcceptedStarttls && plaintextCommandsAfterStarttls) {
      // Server acknowledged STARTTLS with 220, but client or MITM stripped TLS and transmitted cleartext!
      starttlsVerdict = 'ack_without_tls';
      starttlsNegotiated = false;
      starttlsStripped = true;
    } else if (clientCapabilitiesRequested && !serverAdvertisedStarttls && (protocol === 'SMTP' || protocol === 'IMAP' || protocol === 'POP3')) {
      // Server capability response lacked STARTTLS (likely MITM stripping attack)
      starttlsVerdict = 'missing_starttls_in_caps';
      starttlsNegotiated = false;
      starttlsStripped = true;
    } else if (serverRejectedStarttls) {
      starttlsVerdict = 'rejected_starttls';
      starttlsNegotiated = false;
      starttlsStripped = false;
    } else if (clientSentStarttls && !serverAcceptedStarttls) {
      starttlsVerdict = 'fallback_to_plaintext';
      starttlsNegotiated = false;
      starttlsStripped = true;
    } else if (isImplicitTlsPort && tlsClientHelloSeen) {
      starttlsVerdict = 'encrypted_implicit_tls';
      starttlsNegotiated = true;
      starttlsStripped = false;
    } else {
      starttlsVerdict = 'plaintext_unencrypted';
      starttlsNegotiated = false;
      starttlsStripped = false;
    }

    return {
      protocol: protocol !== 'UNKNOWN' ? protocol : 'SMTP',
      starttlsVerdict,
      starttlsNegotiated,
      starttlsStripped,
      serverBanner,
      credentialsExposed: exposedCreds,
      timeline,
    };
  }
}
