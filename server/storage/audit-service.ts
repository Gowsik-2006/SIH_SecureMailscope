import crypto from 'crypto';
import { AuditRecord } from '../../shared/types.ts';

export class AuditService {
  private static records: AuditRecord[] = [];
  private static sequenceCounter = 0;
  private static readonly GENESIS_HASH =
    '0000000000000000000000000000000000000000000000000000000000000000';

  public static log(
    actor: string,
    role: string,
    action: string,
    details: string,
    targetId?: string
  ): AuditRecord {
    const timestamp = Date.now();
    const sequence = ++this.sequenceCounter;
    const prevHash =
      this.records.length > 0
        ? this.records[this.records.length - 1].currentHash
        : this.GENESIS_HASH;

    const payloadToHash = `${prevHash}:${sequence}:${timestamp}:${actor}:${role}:${action}:${details}:${
      targetId || ''
    }`;
    const currentHash = crypto.createHash('sha256').update(payloadToHash).digest('hex');

    const entry: AuditRecord = {
      id: `audit-${sequence}-${crypto.randomBytes(4).toString('hex')}`,
      sequence,
      timestamp,
      actor,
      role,
      action,
      details,
      targetId,
      prevHash,
      currentHash,
    };

    this.records.push(entry);
    return entry;
  }

  public static getRecords(): AuditRecord[] {
    return [...this.records];
  }

  /**
   * Cryptographically verifies the unbroken integrity of the entire audit chain.
   */
  public static verifyChain(): { valid: boolean; errorIndex?: number; message: string } {
    if (this.records.length === 0) {
      return { valid: true, message: 'Audit log is empty.' };
    }

    let expectedPrevHash = this.GENESIS_HASH;

    for (let i = 0; i < this.records.length; i++) {
      const entry = this.records[i];

      // 1. Verify previous hash pointer
      if (entry.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          errorIndex: i,
          message: `Audit chain broken at sequence ${entry.sequence}: prevHash mismatch. Expected ${expectedPrevHash}, got ${entry.prevHash}.`,
        };
      }

      // 2. Recompute current hash
      const payloadToHash = `${entry.prevHash}:${entry.sequence}:${entry.timestamp}:${entry.actor}:${entry.role}:${entry.action}:${entry.details}:${
        entry.targetId || ''
      }`;
      const recomputedHash = crypto.createHash('sha256').update(payloadToHash).digest('hex');

      if (entry.currentHash !== recomputedHash) {
        return {
          valid: false,
          errorIndex: i,
          message: `Audit entry tampered at sequence ${entry.sequence}: hash mismatch. Record has been altered!`,
        };
      }

      expectedPrevHash = entry.currentHash;
    }

    return {
      valid: true,
      message: `Audit chain verified intact: ${this.records.length} records cryptographically validated.`,
    };
  }

  /**
   * For testing tampering detection
   */
  public static _tamperRecordForTest(index: number, newDetails: string) {
    if (index >= 0 && index < this.records.length) {
      this.records[index].details = newDetails;
    }
  }

  public static clear() {
    this.records = [];
    this.sequenceCounter = 0;
  }
}
