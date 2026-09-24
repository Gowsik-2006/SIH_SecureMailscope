import test from 'node:test';
import assert from 'node:assert';
import { SensorCollectorManager } from '../server/engine/collector/collector.ts';
import { ActiveScanner } from '../server/engine/scanner/active-scanner.ts';
import { DemoPcapGenerator } from '../server/engine/datalab/demo-pcap-generator.ts';

test('Active Network Scanner & Remote Sensor Collector Verification', async (t) => {
  await t.test('SensorCollectorManager returns valid configuration, shell command, and script', () => {
    const config = SensorCollectorManager.getConfig('https://security.corp.internal');
    assert.strictEqual(config.apiKey.length > 5, true);
    assert.strictEqual(config.endpointUrl, 'https://security.corp.internal/api/collector/ingest');
    assert.strictEqual(config.curlExample.includes('POST'), true);
    assert.strictEqual(config.pythonSnippet.includes('tcpdump'), true);
  });

  await t.test('SensorCollectorManager rejects unauthenticated ingest attempts', () => {
    const fakePcap = DemoPcapGenerator.generateFullDemoPcap();
    const res = SensorCollectorManager.ingest(fakePcap, 'wrong-api-key', '10.0.0.1');
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.message.includes('Invalid or missing'), true);
  });

  await t.test('SensorCollectorManager successfully ingests valid PCAP with correct API key', () => {
    const validPcap = DemoPcapGenerator.generateFullDemoPcap();
    const config = SensorCollectorManager.getConfig('http://localhost:3000');
    const res = SensorCollectorManager.ingest(validPcap, config.apiKey, '192.168.1.50');
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.case !== undefined, true);
    assert.strictEqual(res.case?.name.includes('Sensor Ingest'), true);
    assert.strictEqual(res.case!.packetCount > 0, true);
    assert.strictEqual(res.case!.status, 'COMPLETED');
  });

  await t.test('ActiveScanner safely handles unreachable or non-mail hosts without uncaught exceptions', async () => {
    // Scan localhost on an unlikely closed port with short timeout
    const scan = await ActiveScanner.scan({
      target: '127.0.0.1',
      port: 59999,
      protocol: 'SMTP',
      checkMtaSts: false,
      checkDane: false,
    });

    assert.strictEqual(scan.targetHost, '127.0.0.1');
    assert.strictEqual(scan.port, 59999);
    assert.strictEqual(scan.starttlsSupported, false);
    assert.strictEqual(scan.starttlsNegotiated, false);
    assert.strictEqual(scan.threats.length > 0, true);
    assert.strictEqual(scan.riskScore >= 70, true);
  });
});
