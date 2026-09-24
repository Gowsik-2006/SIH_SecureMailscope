/**
 * Binary PCAP generator producing gold standard network captures
 * for all 5 forensic test scenarios.
 */

export class DemoPcapGenerator {
  public static generateFullDemoPcap(): Uint8Array {
    const builder = new PcapBuilder();
    let epochMs = 1774430000000; // Reference timestamp

    // ==========================================
    // SCENARIO 1: Modern Secure TLS 1.3 SMTP
    // Stream: 192.168.1.50:49201 <-> 10.0.0.25:587
    // ==========================================
    const s1ClientIp = '192.168.1.50';
    const s1ClientPort = 49201;
    const s1ServerIp = '10.0.0.25';
    const s1ServerPort = 587;

    // 1. Handshake TCP SYN, SYN-ACK, ACK
    builder.addTcpPacket(epochMs += 10, s1ClientIp, s1ClientPort, s1ServerIp, s1ServerPort, 1000, 0, { syn: true });
    builder.addTcpPacket(epochMs += 10, s1ServerIp, s1ServerPort, s1ClientIp, s1ClientPort, 5000, 1001, { syn: true, ack: true });
    builder.addTcpPacket(epochMs += 10, s1ClientIp, s1ClientPort, s1ServerIp, s1ServerPort, 1001, 5001, { ack: true });

    // 2. Server Banner
    const s1Banner = '220 mail.securebank.com ESMTP Postfix (Ubuntu)\r\n';
    builder.addTcpPayload(epochMs += 15, s1ServerIp, s1ServerPort, s1ClientIp, s1ClientPort, 5001, 1001, s1Banner);

    // 3. Client EHLO
    const s1Ehlo = 'EHLO mail-client.corp.local\r\n';
    builder.addTcpPayload(epochMs += 15, s1ClientIp, s1ClientPort, s1ServerIp, s1ServerPort, 1001, 5001 + s1Banner.length, s1Ehlo);

    // 4. Server 250 STARTTLS advertisement
    const s1Caps = '250-mail.securebank.com\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n';
    builder.addTcpPayload(epochMs += 15, s1ServerIp, s1ServerPort, s1ClientIp, s1ClientPort, 5001 + s1Banner.length, 1001 + s1Ehlo.length, s1Caps);

    // 5. Client STARTTLS
    const s1Starttls = 'STARTTLS\r\n';
    builder.addTcpPayload(epochMs += 15, s1ClientIp, s1ClientPort, s1ServerIp, s1ServerPort, 1001 + s1Ehlo.length, 5001 + s1Banner.length + s1Caps.length, s1Starttls);

    // 6. Server 220 Ready to start TLS
    const s1Ready = '220 2.0.0 Ready to start TLS\r\n';
    builder.addTcpPayload(epochMs += 15, s1ServerIp, s1ServerPort, s1ClientIp, s1ClientPort, 5001 + s1Banner.length + s1Caps.length, 1001 + s1Ehlo.length + s1Starttls.length, s1Ready);

    // 7. Client TLS 1.3 ClientHello (cipher: 0x1302 TLS_AES_256_GCM_SHA384, supported_versions: 0x0304)
    const clientHelloTls13 = this.buildTls13ClientHello('mail.securebank.com');
    builder.addTcpPayload(epochMs += 20, s1ClientIp, s1ClientPort, s1ServerIp, s1ServerPort, 2000, 6000, clientHelloTls13);

    // 8. Server TLS 1.3 ServerHello (selected: 0x1302, ext supported_versions: 0x0304) + Certificate
    const serverHelloTls13 = this.buildTls13ServerHello(0x1302, 'mail.securebank.com', 2048, false, false);
    builder.addTcpPayload(epochMs += 25, s1ServerIp, s1ServerPort, s1ClientIp, s1ClientPort, 6000, 2000 + clientHelloTls13.length, serverHelloTls13);

    // 9. Application Data (encrypted traffic)
    const appData = new Uint8Array([0x17, 0x03, 0x03, 0x00, 0x40, ...new Array(64).fill(0xaa)]);
    builder.addTcpPayload(epochMs += 20, s1ClientIp, s1ClientPort, s1ServerIp, s1ServerPort, 2000 + clientHelloTls13.length, 7000, appData);


    // ==========================================
    // SCENARIO 2: STARTTLS Stripped Attack (MITM)
    // Stream: 172.16.5.12:51442 <-> 198.51.100.25:25
    // ==========================================
    const s2ClientIp = '172.16.5.12';
    const s2ClientPort = 51442;
    const s2ServerIp = '198.51.100.25';
    const s2ServerPort = 25;

    builder.addTcpPacket(epochMs += 30, s2ClientIp, s2ClientPort, s2ServerIp, s2ServerPort, 12000, 0, { syn: true });
    builder.addTcpPacket(epochMs += 10, s2ServerIp, s2ServerPort, s2ClientIp, s2ClientPort, 24000, 12001, { syn: true, ack: true });

    // Server Greeting
    const s2Banner = '220 outbound.corp-mail.com ESMTP Service Ready\r\n';
    builder.addTcpPayload(epochMs += 10, s2ServerIp, s2ServerPort, s2ClientIp, s2ClientPort, 24001, 12001, s2Banner);

    // Client EHLO
    const s2Ehlo = 'EHLO victim-host.internal\r\n';
    builder.addTcpPayload(epochMs += 10, s2ClientIp, s2ClientPort, s2ServerIp, s2ServerPort, 12001, 24050, s2Ehlo);

    // Server announces 250 STARTTLS
    const s2Caps = '250-outbound.corp-mail.com\r\n250-SIZE 20971520\r\n250 STARTTLS\r\n';
    builder.addTcpPayload(epochMs += 10, s2ServerIp, s2ServerPort, s2ClientIp, s2ClientPort, 24050, 12025, s2Caps);

    // Client sends STARTTLS
    const s2Starttls = 'STARTTLS\r\n';
    builder.addTcpPayload(epochMs += 10, s2ClientIp, s2ClientPort, s2ServerIp, s2ServerPort, 12025, 24100, s2Starttls);

    // Server confirms: 220 2.0.0 Ready to start TLS
    const s2Ack = '220 2.0.0 Ready to start TLS\r\n';
    builder.addTcpPayload(epochMs += 10, s2ServerIp, s2ServerPort, s2ClientIp, s2ClientPort, 24100, 12035, s2Ack);

    // ATTACK ANOMALY: Instead of TLS ClientHello, MITM stripped TLS and client sends plaintext MAIL FROM and AUTH!
    const s2PlainMail = 'MAIL FROM:<finance-director@corp-mail.com>\r\n';
    builder.addTcpPayload(epochMs += 15, s2ClientIp, s2ClientPort, s2ServerIp, s2ServerPort, 12035, 24130, s2PlainMail);

    const s2PlainAuth = 'AUTH LOGIN\r\n';
    builder.addTcpPayload(epochMs += 15, s2ClientIp, s2ClientPort, s2ServerIp, s2ServerPort, 12075, 24130, s2PlainAuth);

    const s2UserB64 = Buffer.from('finance-director').toString('base64') + '\r\n';
    builder.addTcpPayload(epochMs += 15, s2ClientIp, s2ClientPort, s2ServerIp, s2ServerPort, 12090, 24130, s2UserB64);


    // ==========================================
    // SCENARIO 3: Deprecated TLS 1.0 + RC4 Weak Cipher + Expired Self-Signed Cert (1024-bit RSA)
    // Stream: 10.10.4.19:38112 <-> 10.10.4.1:465
    // ==========================================
    const s3ClientIp = '10.10.4.19';
    const s3ClientPort = 38112;
    const s3ServerIp = '10.10.4.1';
    const s3ServerPort = 465;

    builder.addTcpPacket(epochMs += 30, s3ClientIp, s3ClientPort, s3ServerIp, s3ServerPort, 31000, 0, { syn: true });
    builder.addTcpPacket(epochMs += 10, s3ServerIp, s3ServerPort, s3ClientIp, s3ClientPort, 45000, 31001, { syn: true, ack: true });

    // TLS 1.0 ClientHello (version 0x0301, ciphers: 0x0005 TLS_RSA_WITH_RC4_128_SHA)
    const clientHelloTls10 = this.buildTls10ClientHello([0x0005, 0x0004]);
    builder.addTcpPayload(epochMs += 20, s3ClientIp, s3ClientPort, s3ServerIp, s3ServerPort, 31001, 45001, clientHelloTls10);

    // TLS 1.0 ServerHello selecting RC4 0x0005 + Expired, Self-Signed, 1024-bit RSA Certificate!
    const serverHelloTls10 = this.buildTls10ServerHello(0x0005, 'legacy-mail.internal', 1024, true, true);
    builder.addTcpPayload(epochMs += 25, s3ServerIp, s3ServerPort, s3ClientIp, s3ClientPort, 45001, 31001 + clientHelloTls10.length, serverHelloTls10);


    // ==========================================
    // SCENARIO 4: Insecure IMAP Plaintext Login (Port 143)
    // Stream: 192.168.2.80:58102 <-> 10.0.1.143:143
    // ==========================================
    const s4ClientIp = '192.168.2.80';
    const s4ClientPort = 58102;
    const s4ServerIp = '10.0.1.143';
    const s4ServerPort = 143;

    builder.addTcpPacket(epochMs += 30, s4ClientIp, s4ClientPort, s4ServerIp, s4ServerPort, 61000, 0, { syn: true });
    builder.addTcpPacket(epochMs += 10, s4ServerIp, s4ServerPort, s4ClientIp, s4ClientPort, 82000, 61001, { syn: true, ack: true });

    // Server Greeting
    const s4Banner = '* OK [CAPABILITY IMAP4rev1 SASL-IR] IMAP4rev1 Service Ready\r\n';
    builder.addTcpPayload(epochMs += 10, s4ServerIp, s4ServerPort, s4ClientIp, s4ClientPort, 82001, 61001, s4Banner);

    // Client requests capability
    const s4Capa = 'A001 CAPABILITY\r\n';
    builder.addTcpPayload(epochMs += 10, s4ClientIp, s4ClientPort, s4ServerIp, s4ServerPort, 61001, 82060, s4Capa);

    // Server returns capabilities WITHOUT STARTTLS (Stripped/Missing STARTTLS)
    const s4CapaResp = '* CAPABILITY IMAP4rev1 IDLE NAMESPACE QUOTA\r\nA001 OK CAPABILITY completed\r\n';
    builder.addTcpPayload(epochMs += 10, s4ServerIp, s4ServerPort, s4ClientIp, s4ClientPort, 82060, 61018, s4CapaResp);

    // Client falls back to plaintext LOGIN with cleartext password!
    const s4Login = 'A002 LOGIN sysadmin@company.com SuperSecretPassword2026!\r\n';
    builder.addTcpPayload(epochMs += 15, s4ClientIp, s4ClientPort, s4ServerIp, s4ServerPort, 61018, 82130, s4Login);

    const s4LoginResp = 'A002 OK [READ-WRITE] Logged in successfully\r\n';
    builder.addTcpPayload(epochMs += 10, s4ServerIp, s4ServerPort, s4ClientIp, s4ClientPort, 82130, 61075, s4LoginResp);


    // ==========================================
    // SCENARIO 5: TLS Handshake Alert (Handshake Failure)
    // Stream: 192.168.3.11:44921 <-> 10.0.0.99:587
    // ==========================================
    const s5ClientIp = '192.168.3.11';
    const s5ClientPort = 44921;
    const s5ServerIp = '10.0.0.99';
    const s5ServerPort = 587;

    builder.addTcpPacket(epochMs += 30, s5ClientIp, s5ClientPort, s5ServerIp, s5ServerPort, 90000, 0, { syn: true });
    builder.addTcpPacket(epochMs += 10, s5ServerIp, s5ServerPort, s5ClientIp, s5ClientPort, 95000, 90001, { syn: true, ack: true });

    // SMTP STARTTLS negotiation
    builder.addTcpPayload(epochMs += 10, s5ServerIp, s5ServerPort, s5ClientIp, s5ClientPort, 95001, 90001, '220 alert-host ESMTP\r\n');
    builder.addTcpPayload(epochMs += 10, s5ClientIp, s5ClientPort, s5ServerIp, s5ServerPort, 90001, 95025, 'STARTTLS\r\n');
    builder.addTcpPayload(epochMs += 10, s5ServerIp, s5ServerPort, s5ClientIp, s5ClientPort, 95025, 90011, '220 Go ahead\r\n');

    // ClientHello TLS 1.2
    const clientHelloTls12 = this.buildTls12ClientHello();
    builder.addTcpPayload(epochMs += 15, s5ClientIp, s5ClientPort, s5ServerIp, s5ServerPort, 90011, 95040, clientHelloTls12);

    // Server responds with TLS Fatal Alert (Level 2, Description 40 = handshake_failure)
    const tlsAlertMsg = new Uint8Array([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
    builder.addTcpPayload(epochMs += 15, s5ServerIp, s5ServerPort, s5ClientIp, s5ClientPort, 95040, 90011 + clientHelloTls12.length, tlsAlertMsg);

    return builder.toBuffer();
  }

  // --- TLS Binary Constructors ---

  private static buildTls13ClientHello(sni: string): Uint8Array {
    const sniBytes = new TextEncoder().encode(sni);
    const sniExt = new Uint8Array([
      0x00, 0x00, // ext type SNI
      0x00, sniBytes.length + 5, // ext len
      0x00, sniBytes.length + 3, // list len
      0x00, // host_name
      0x00, sniBytes.length,
      ...sniBytes,
    ]);

    // supported_versions ext: 0x002b
    const supVerExt = new Uint8Array([
      0x00, 0x2b, // ext type
      0x00, 0x03, // ext len
      0x02, // list len
      0x03, 0x04, // TLS 1.3
    ]);

    const extensions = new Uint8Array([...sniExt, ...supVerExt]);

    const chBody = new Uint8Array([
      0x03, 0x03, // legacy client version TLS 1.2
      ...new Array(32).fill(0x11), // 32 bytes random
      0x00, // session id len 0
      0x00, 0x04, // cipher suites len (2 suites)
      0x13, 0x02, // TLS_AES_256_GCM_SHA384
      0x13, 0x01, // TLS_AES_128_GCM_SHA256
      0x01, 0x00, // compression methods (1 method: null)
      (extensions.length >> 8) & 0xff,
      extensions.length & 0xff,
      ...extensions,
    ]);

    const hsMsg = new Uint8Array([
      0x01, // ClientHello
      0x00, (chBody.length >> 8) & 0xff, chBody.length & 0xff,
      ...chBody,
    ]);

    return new Uint8Array([
      0x16, // Handshake
      0x03, 0x01, // TLS 1.0 record version
      (hsMsg.length >> 8) & 0xff, hsMsg.length & 0xff,
      ...hsMsg,
    ]);
  }

  private static buildTls13ServerHello(
    cipherCode: number,
    cn: string,
    keyBits: number,
    expired: boolean,
    selfSigned: boolean
  ): Uint8Array {
    // supported_versions extension 0x002b -> 0x0304
    const supVerExt = new Uint8Array([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

    const shBody = new Uint8Array([
      0x03, 0x03, // legacy version
      ...new Array(32).fill(0x22), // 32 bytes random
      0x00, // session id len 0
      (cipherCode >> 8) & 0xff, cipherCode & 0xff, // selected cipher
      0x00, // compression null
      0x00, supVerExt.length,
      ...supVerExt,
    ]);

    const shRecord = new Uint8Array([
      0x16, 0x03, 0x03,
      0x00, shBody.length + 4,
      0x02, 0x00, (shBody.length >> 8) & 0xff, shBody.length & 0xff,
      ...shBody,
    ]);

    // Certificate Record
    const certDer = this.generateSyntheticCertDer(cn, keyBits, expired, selfSigned);
    // In TLS 1.3: Cert message has requestContextLen(1) + certListLen(3) + cert(3 len + der + 2 extLen)
    const certPayloadLen = 1 + 3 + (3 + certDer.length + 2);
    const certMsg = new Uint8Array([
      0x0b, // Certificate
      (certPayloadLen >> 16) & 0xff, (certPayloadLen >> 8) & 0xff, certPayloadLen & 0xff,
      0x00, // request context len 0
      ((3 + certDer.length + 2) >> 16) & 0xff, ((3 + certDer.length + 2) >> 8) & 0xff, (3 + certDer.length + 2) & 0xff,
      (certDer.length >> 16) & 0xff, (certDer.length >> 8) & 0xff, certDer.length & 0xff,
      ...certDer,
      0x00, 0x00, // 0 extensions for cert
    ]);

    const certRecord = new Uint8Array([
      0x16, 0x03, 0x03,
      (certMsg.length >> 8) & 0xff, certMsg.length & 0xff,
      ...certMsg,
    ]);

    return new Uint8Array([...shRecord, ...certRecord]);
  }

  private static buildTls10ClientHello(ciphers: number[]): Uint8Array {
    const cipherBytes: number[] = [];
    for (const c of ciphers) {
      cipherBytes.push((c >> 8) & 0xff, c & 0xff);
    }

    const chBody = new Uint8Array([
      0x03, 0x01, // TLS 1.0 client version
      ...new Array(32).fill(0x33), // random
      0x00, // session id len 0
      (cipherBytes.length >> 8) & 0xff, cipherBytes.length & 0xff,
      ...cipherBytes,
      0x01, 0x00, // compression null
    ]);

    const hsMsg = new Uint8Array([
      0x01, // ClientHello
      0x00, (chBody.length >> 8) & 0xff, chBody.length & 0xff,
      ...chBody,
    ]);

    return new Uint8Array([
      0x16, 0x03, 0x01,
      (hsMsg.length >> 8) & 0xff, hsMsg.length & 0xff,
      ...hsMsg,
    ]);
  }

  private static buildTls10ServerHello(
    cipherCode: number,
    cn: string,
    keyBits: number,
    expired: boolean,
    selfSigned: boolean
  ): Uint8Array {
    const shBody = new Uint8Array([
      0x03, 0x01, // TLS 1.0
      ...new Array(32).fill(0x44), // random
      0x00, // session id len 0
      (cipherCode >> 8) & 0xff, cipherCode & 0xff,
      0x00, // compression
    ]);

    const shRecord = new Uint8Array([
      0x16, 0x03, 0x01,
      0x00, shBody.length + 4,
      0x02, 0x00, (shBody.length >> 8) & 0xff, shBody.length & 0xff,
      ...shBody,
    ]);

    // TLS 1.0/1.2 Certificate format (3 bytes cert list len + 3 bytes cert len + certDer)
    const certDer = this.generateSyntheticCertDer(cn, keyBits, expired, selfSigned);
    const certMsgLen = 3 + 3 + certDer.length;
    const certMsg = new Uint8Array([
      0x0b, // Certificate
      (certMsgLen >> 16) & 0xff, (certMsgLen >> 8) & 0xff, certMsgLen & 0xff,
      ((3 + certDer.length) >> 16) & 0xff, ((3 + certDer.length) >> 8) & 0xff, (3 + certDer.length) & 0xff,
      (certDer.length >> 16) & 0xff, (certDer.length >> 8) & 0xff, certDer.length & 0xff,
      ...certDer,
    ]);

    const certRecord = new Uint8Array([
      0x16, 0x03, 0x01,
      (certMsg.length >> 8) & 0xff, certMsg.length & 0xff,
      ...certMsg,
    ]);

    return new Uint8Array([...shRecord, ...certRecord]);
  }

  private static buildTls12ClientHello(): Uint8Array {
    const chBody = new Uint8Array([
      0x03, 0x03, // TLS 1.2
      ...new Array(32).fill(0x55),
      0x00,
      0x00, 0x02, 0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      0x01, 0x00,
    ]);
    const hsMsg = new Uint8Array([0x01, 0x00, (chBody.length >> 8) & 0xff, chBody.length & 0xff, ...chBody]);
    return new Uint8Array([0x16, 0x03, 0x03, (hsMsg.length >> 8) & 0xff, hsMsg.length & 0xff, ...hsMsg]);
  }

  /**
   * Constructs valid ASN.1 DER X.509 certificate with controlled parameters
   */
  private static generateSyntheticCertDer(
    cn: string,
    keyBits: number,
    expired: boolean,
    selfSigned: boolean
  ): Uint8Array {
    // 1. Subject & Issuer Names
    const subjectName = this.buildAsn1Dn(cn, 'CyberSec Labs', 'IN');
    const issuerName = selfSigned
      ? subjectName
      : this.buildAsn1Dn('DigiTrust Global Root CA', 'DigiTrust Inc.', 'US');

    // 2. Validity Dates (UTCTime: YYMMDDHHMMSSZ)
    // 2026 reference
    let notBefore = '240101000000Z';
    let notAfter = '270101000000Z';
    if (expired) {
      notBefore = '200101000000Z';
      notAfter = '220101000000Z'; // Expired in 2022
    }
    const validitySeq = this.buildAsn1Sequence([
      this.buildAsn1Node(0x17, new TextEncoder().encode(notBefore)),
      this.buildAsn1Node(0x17, new TextEncoder().encode(notAfter)),
    ]);

    // 3. Serial Number
    const serial = this.buildAsn1Node(0x02, new Uint8Array([0x4a, 0x9b, 0x12, 0x88, 0xfa]));

    // 4. AlgorithmIdentifier (SHA256 with RSA: 1.2.840.113549.1.1.11, or SHA1: 1.2.840.113549.1.1.5 if expired)
    const sigOid = expired
      ? new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]) // sha1WithRSAEncryption
      : new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]); // sha256WithRSAEncryption

    const sigAlgoId = this.buildAsn1Sequence([
      this.buildAsn1Node(0x06, sigOid),
      this.buildAsn1Node(0x05, new Uint8Array(0)), // NULL
    ]);

    // 5. SubjectPublicKeyInfo
    // RSA modulus of keyBits length
    const modulusByteLen = Math.floor(keyBits / 8);
    const modulus = new Uint8Array([0x00, ...new Array(modulusByteLen).fill(0xee)]);
    const exponent = new Uint8Array([0x01, 0x00, 0x01]); // 65537
    const rsaPublicKey = this.buildAsn1Sequence([
      this.buildAsn1Node(0x02, modulus),
      this.buildAsn1Node(0x02, exponent),
    ]);

    // Bit string wrapping RSA PublicKey
    const pubKeyBitString = this.buildAsn1Node(
      0x03,
      new Uint8Array([0x00, ...rsaPublicKey])
    );

    const rsaOid = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]); // rsaEncryption
    const spki = this.buildAsn1Sequence([
      this.buildAsn1Sequence([
        this.buildAsn1Node(0x06, rsaOid),
        this.buildAsn1Node(0x05, new Uint8Array(0)),
      ]),
      pubKeyBitString,
    ]);

    // 6. SAN Extension (2.5.29.17)
    const sanDns = this.buildAsn1Node(0x82, new TextEncoder().encode(cn));
    const sanSeq = this.buildAsn1Sequence([sanDns]);
    const sanOctet = this.buildAsn1Node(0x04, sanSeq);
    const sanOid = new Uint8Array([0x55, 0x1d, 0x11]); // 2.5.29.17
    const sanExt = this.buildAsn1Sequence([
      this.buildAsn1Node(0x06, sanOid),
      sanOctet,
    ]);
    const extList = this.buildAsn1Sequence([sanExt]);
    const extTag3 = this.buildAsn1Node(0xa3, extList);

    // Assemble TBSCertificate
    const tbsCert = this.buildAsn1Sequence([
      serial,
      sigAlgoId,
      issuerName,
      validitySeq,
      subjectName,
      spki,
      extTag3,
    ]);

    // Certificate = SEQUENCE { TBSCertificate, AlgorithmIdentifier, SignatureBitString }
    const dummySignature = this.buildAsn1Node(0x03, new Uint8Array([0x00, ...new Array(128).fill(0xcc)]));
    return this.buildAsn1Sequence([tbsCert, sigAlgoId, dummySignature]);
  }

  private static buildAsn1Dn(cn: string, org: string, country: string): Uint8Array {
    const cnAttr = this.buildAsn1Set([
      this.buildAsn1Sequence([
        this.buildAsn1Node(0x06, new Uint8Array([0x55, 0x04, 0x03])), // 2.5.4.3 CN
        this.buildAsn1Node(0x0c, new TextEncoder().encode(cn)), // UTF8String
      ]),
    ]);

    const orgAttr = this.buildAsn1Set([
      this.buildAsn1Sequence([
        this.buildAsn1Node(0x06, new Uint8Array([0x55, 0x04, 0x0a])), // 2.5.4.10 O
        this.buildAsn1Node(0x0c, new TextEncoder().encode(org)),
      ]),
    ]);

    const cAttr = this.buildAsn1Set([
      this.buildAsn1Sequence([
        this.buildAsn1Node(0x06, new Uint8Array([0x55, 0x04, 0x06])), // 2.5.4.6 C
        this.buildAsn1Node(0x13, new TextEncoder().encode(country)), // PrintableString
      ]),
    ]);

    return this.buildAsn1Sequence([cAttr, orgAttr, cnAttr]);
  }

  private static buildAsn1Node(tag: number, data: Uint8Array): Uint8Array {
    const len = data.length;
    let lenBytes: number[] = [];
    if (len < 128) {
      lenBytes = [len];
    } else if (len < 256) {
      lenBytes = [0x81, len];
    } else {
      lenBytes = [0x82, (len >> 8) & 0xff, len & 0xff];
    }
    return new Uint8Array([tag, ...lenBytes, ...data]);
  }

  private static buildAsn1Sequence(children: Uint8Array[]): Uint8Array {
    const totalLen = children.reduce((acc, c) => acc + c.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of children) {
      combined.set(c, offset);
      offset += c.length;
    }
    return this.buildAsn1Node(0x30, combined);
  }

  private static buildAsn1Set(children: Uint8Array[]): Uint8Array {
    const totalLen = children.reduce((acc, c) => acc + c.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of children) {
      combined.set(c, offset);
      offset += c.length;
    }
    return this.buildAsn1Node(0x31, combined);
  }
}

/**
 * Low-level binary PCAP stream writer
 */
class PcapBuilder {
  private packets: { tsEpochMs: number; frameData: Uint8Array }[] = [];

  public addTcpPacket(
    tsEpochMs: number,
    srcIp: string,
    srcPort: number,
    dstIp: string,
    dstPort: number,
    seq: number,
    ack: number,
    flags: { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean; psh?: boolean; urg?: boolean }
  ) {
    this.addTcpPayload(tsEpochMs, srcIp, srcPort, dstIp, dstPort, seq, ack, new Uint8Array(0), flags);
  }

  public addTcpPayload(
    tsEpochMs: number,
    srcIp: string,
    srcPort: number,
    dstIp: string,
    dstPort: number,
    seq: number,
    ack: number,
    payload: string | Uint8Array,
    customFlags?: { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean; psh?: boolean; urg?: boolean }
  ) {
    const payloadBytes = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;

    // 1. Ethernet Header (14 bytes)
    const ethHeader = new Uint8Array([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
      0x00, 0x66, 0x77, 0x88, 0x99, 0xaa, // src mac
      0x08, 0x00, // EtherType IPv4
    ]);

    // 2. IPv4 Header (20 bytes)
    const srcIpParts = srcIp.split('.').map((p) => parseInt(p, 10));
    const dstIpParts = dstIp.split('.').map((p) => parseInt(p, 10));
    const ipTotalLen = 20 + 20 + payloadBytes.length;

    const ipHeader = new Uint8Array([
      0x45, // Ver 4, IHL 5
      0x00, // DSCP/ECN
      (ipTotalLen >> 8) & 0xff, ipTotalLen & 0xff,
      0x1a, 0x2b, // ID
      0x40, 0x00, // Don't fragment
      0x40, // TTL 64
      0x06, // Protocol TCP
      0x00, 0x00, // Checksum placeholder
      srcIpParts[0], srcIpParts[1], srcIpParts[2], srcIpParts[3],
      dstIpParts[0], dstIpParts[1], dstIpParts[2], dstIpParts[3],
    ]);

    // 3. TCP Header (20 bytes)
    let flagByte = 0x10; // ACK by default
    if (customFlags) {
      flagByte = 0;
      if (customFlags.urg) flagByte |= 0x20;
      if (customFlags.ack) flagByte |= 0x10;
      if (customFlags.psh) flagByte |= 0x08;
      if (customFlags.rst) flagByte |= 0x04;
      if (customFlags.syn) flagByte |= 0x02;
      if (customFlags.fin) flagByte |= 0x01;
    } else if (payloadBytes.length > 0) {
      flagByte = 0x18; // ACK + PSH
    }

    const tcpHeader = new Uint8Array([
      (srcPort >> 8) & 0xff, srcPort & 0xff,
      (dstPort >> 8) & 0xff, dstPort & 0xff,
      (seq >> 24) & 0xff, (seq >> 16) & 0xff, (seq >> 8) & 0xff, seq & 0xff,
      (ack >> 24) & 0xff, (ack >> 16) & 0xff, (ack >> 8) & 0xff, ack & 0xff,
      0x50, // Data offset 5 (20 bytes)
      flagByte,
      0x72, 0x10, // Window size 29200
      0x00, 0x00, // Checksum placeholder
      0x00, 0x00, // Urgent pointer
    ]);

    const frameData = new Uint8Array(ethHeader.length + ipHeader.length + tcpHeader.length + payloadBytes.length);
    frameData.set(ethHeader, 0);
    frameData.set(ipHeader, ethHeader.length);
    frameData.set(tcpHeader, ethHeader.length + ipHeader.length);
    frameData.set(payloadBytes, ethHeader.length + ipHeader.length + tcpHeader.length);

    this.packets.push({ tsEpochMs, frameData });
  }

  public toBuffer(): Uint8Array {
    // Global Header: 24 bytes (magic 0xa1b2c3d4, ver 2.4, snaplen 65535, linkType 1)
    const globalHeader = new Uint8Array([
      0xa1, 0xb2, 0xc3, 0xd4, // magic
      0x00, 0x02, // ver major 2
      0x00, 0x04, // ver minor 4
      0x00, 0x00, 0x00, 0x00, // thiszone
      0x00, 0x00, 0x00, 0x00, // sigfigs
      0x00, 0x00, 0xff, 0xff, // snaplen 65535
      0x00, 0x00, 0x00, 0x01, // linktype 1 (Ethernet)
    ]);

    let totalLen = globalHeader.length;
    for (const pkt of this.packets) {
      totalLen += 16 + pkt.frameData.length;
    }

    const out = new Uint8Array(totalLen);
    out.set(globalHeader, 0);
    let offset = globalHeader.length;

    for (const pkt of this.packets) {
      const tsSec = Math.floor(pkt.tsEpochMs / 1000);
      const tsUsec = (pkt.tsEpochMs % 1000) * 1000;
      const len = pkt.frameData.length;

      const pHeader = new Uint8Array([
        (tsSec >> 24) & 0xff, (tsSec >> 16) & 0xff, (tsSec >> 8) & 0xff, tsSec & 0xff,
        (tsUsec >> 24) & 0xff, (tsUsec >> 16) & 0xff, (tsUsec >> 8) & 0xff, tsUsec & 0xff,
        (len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff,
        (len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff,
      ]);

      out.set(pHeader, offset);
      offset += 16;
      out.set(pkt.frameData, offset);
      offset += len;
    }

    return out;
  }
}
