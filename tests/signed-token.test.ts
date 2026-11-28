import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  generateSignedToken,
  verifySignedToken,
  isValidCalendarIsoString,
  type SignedTokenPayload,
} from '../src/lib/security/signed-token';

describe('HMAC-SHA256 Signed Verification Token Generator (signed-token.ts)', () => {
  const validSecret = 'super-secure-verification-secret-key-32chars!';
  const weakSecret = 'too-short';

  const mockPayload: SignedTokenPayload = {
    pactId: 'pact-uuid-1234-abcd',
    verifierId: 'user-verifier-9988',
    action: 'approve',
    expiresAtIso: '2027-01-01T00:00:00.000Z',
    customData: { note: 'Accountability milestone verified' },
  };

  it('generates a URL-safe composite token format <payload>.<signature>', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    assert.ok(token);
    assert.strictEqual(typeof token, 'string');

    const parts = token.split('.');
    assert.strictEqual(parts.length, 2);
    assert.ok(parts[0].length > 0);
    assert.ok(parts[1].length > 0);
  });

  it('verifies a valid token successfully with expected payload', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    const result = verifySignedToken(token, validSecret, '2026-11-23T00:00:00.000Z');

    assert.strictEqual(result.isValid, true);
    assert.strictEqual(result.isExpired, false);
    assert.strictEqual(result.error, null);
    assert.deepStrictEqual(result.payload, mockPayload);
  });

  it('rejects verification if any character in payload is tampered with', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    const [payloadB64, sigB64] = token.split('.');

    const decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    decoded.action = 'reject'; // Tampering action
    const tamperedPayloadB64 = Buffer.from(JSON.stringify(decoded), 'utf-8').toString('base64url');

    const tamperedToken = `${tamperedPayloadB64}.${sigB64}`;
    const result = verifySignedToken(tamperedToken, validSecret);

    assert.strictEqual(result.isValid, false);
    assert.strictEqual(result.payload, null);
    assert.strictEqual(result.error, 'Invalid token signature.');
  });

  it('rejects verification if signature is tampered with', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    const [payloadB64, sigB64] = token.split('.');

    const tamperedSig = sigB64.slice(0, -1) + (sigB64.endsWith('a') ? 'b' : 'a');
    const tamperedToken = `${payloadB64}.${tamperedSig}`;

    const result = verifySignedToken(tamperedToken, validSecret);
    assert.strictEqual(result.isValid, false);
    assert.strictEqual(result.payload, null);
    assert.strictEqual(result.error, 'Invalid token signature.');
  });

  it('returns isValid: false and isExpired: true for expired tokens', () => {
    const expiredPayload: SignedTokenPayload = {
      ...mockPayload,
      expiresAtIso: '2026-10-01T00:00:00.000Z',
    };

    const token = generateSignedToken(expiredPayload, validSecret);
    const result = verifySignedToken(token, validSecret, '2026-11-23T00:00:00.000Z');

    assert.strictEqual(result.isValid, false);
    assert.strictEqual(result.isExpired, true);
    assert.strictEqual(result.error, 'Token has expired.');
    assert.strictEqual(result.payload?.pactId, expiredPayload.pactId);
  });

  it('throws descriptive validation error for weak secret keys (< 16 characters)', () => {
    assert.throws(
      () => generateSignedToken(mockPayload, weakSecret),
      /Secret key must be at least 16 characters long/
    );

    const token = generateSignedToken(mockPayload, validSecret);
    assert.throws(
      () => verifySignedToken(token, weakSecret),
      /Secret key must be at least 16 characters long/
    );
  });

  it('protects against malformed token inputs gracefully', () => {
    assert.strictEqual(verifySignedToken('', validSecret).isValid, false);
    assert.strictEqual(verifySignedToken('no-dot-token', validSecret).isValid, false);
    assert.strictEqual(verifySignedToken('part1.part2.part3', validSecret).isValid, false);
  });

  describe('Security Hardening & Edge-Case Validations (CodeRabbit Review)', () => {
    it('rejects correctly signed tokens whose root payload is null or an array', () => {
      // Craft a signed token where payload JSON is null
      const nullPayloadB64 = Buffer.from('null', 'utf-8').toString('base64url');
      const nullSig = createHmac('sha256', validSecret).update(nullPayloadB64).digest('base64url');
      const nullToken = `${nullPayloadB64}.${nullSig}`;

      const nullResult = verifySignedToken(nullToken, validSecret);
      assert.strictEqual(nullResult.isValid, false);
      assert.strictEqual(nullResult.payload, null);
      assert.match(nullResult.error ?? '', /expected a non-null object/i);

      // Craft a signed token where payload JSON is an array
      const arrPayloadB64 = Buffer.from('["pact-1", "user-1"]', 'utf-8').toString('base64url');
      const arrSig = createHmac('sha256', validSecret).update(arrPayloadB64).digest('base64url');
      const arrToken = `${arrPayloadB64}.${arrSig}`;

      const arrResult = verifySignedToken(arrToken, validSecret);
      assert.strictEqual(arrResult.isValid, false);
      assert.strictEqual(arrResult.payload, null);
      assert.match(arrResult.error ?? '', /expected a non-null object/i);
    });

    it('independently validates and rejects invalid pactId', () => {
      // Number pactId
      const payloadWithNumericPactId = {
        pactId: 12345,
        verifierId: 'user-verifier-9988',
        action: 'approve',
        expiresAtIso: '2027-01-01T00:00:00.000Z',
      };
      const b64Num = Buffer.from(JSON.stringify(payloadWithNumericPactId), 'utf-8').toString('base64url');
      const sigNum = createHmac('sha256', validSecret).update(b64Num).digest('base64url');
      const resultNum = verifySignedToken(`${b64Num}.${sigNum}`, validSecret);
      assert.strictEqual(resultNum.isValid, false);
      assert.match(resultNum.error ?? '', /pactId/i);

      // Empty string pactId
      const payloadWithEmptyPactId = {
        pactId: '   ',
        verifierId: 'user-verifier-9988',
        action: 'approve',
        expiresAtIso: '2027-01-01T00:00:00.000Z',
      };
      const b64Empty = Buffer.from(JSON.stringify(payloadWithEmptyPactId), 'utf-8').toString('base64url');
      const sigEmpty = createHmac('sha256', validSecret).update(b64Empty).digest('base64url');
      const resultEmpty = verifySignedToken(`${b64Empty}.${sigEmpty}`, validSecret);
      assert.strictEqual(resultEmpty.isValid, false);
      assert.match(resultEmpty.error ?? '', /pactId/i);
    });

    it('independently validates and rejects invalid verifierId', () => {
      // Boolean verifierId
      const payloadWithBoolVerifierId = {
        pactId: 'pact-uuid-1234-abcd',
        verifierId: true,
        action: 'approve',
        expiresAtIso: '2027-01-01T00:00:00.000Z',
      };
      const b64Bool = Buffer.from(JSON.stringify(payloadWithBoolVerifierId), 'utf-8').toString('base64url');
      const sigBool = createHmac('sha256', validSecret).update(b64Bool).digest('base64url');
      const resultBool = verifySignedToken(`${b64Bool}.${sigBool}`, validSecret);
      assert.strictEqual(resultBool.isValid, false);
      assert.match(resultBool.error ?? '', /verifierId/i);

      // Empty string verifierId
      const payloadWithEmptyVerifierId = {
        pactId: 'pact-uuid-1234-abcd',
        verifierId: '',
        action: 'approve',
        expiresAtIso: '2027-01-01T00:00:00.000Z',
      };
      const b64Empty = Buffer.from(JSON.stringify(payloadWithEmptyVerifierId), 'utf-8').toString('base64url');
      const sigEmpty = createHmac('sha256', validSecret).update(b64Empty).digest('base64url');
      const resultEmpty = verifySignedToken(`${b64Empty}.${sigEmpty}`, validSecret);
      assert.strictEqual(resultEmpty.isValid, false);
      assert.match(resultEmpty.error ?? '', /verifierId/i);
    });

    it('independently validates and rejects unlisted action', () => {
      const payloadWithInvalidAction = {
        pactId: 'pact-uuid-1234-abcd',
        verifierId: 'user-verifier-9988',
        action: 'delete',
        expiresAtIso: '2027-01-01T00:00:00.000Z',
      };
      const b64 = Buffer.from(JSON.stringify(payloadWithInvalidAction), 'utf-8').toString('base64url');
      const sig = createHmac('sha256', validSecret).update(b64).digest('base64url');
      const result = verifySignedToken(`${b64}.${sig}`, validSecret);
      assert.strictEqual(result.isValid, false);
      assert.match(result.error ?? '', /action/i);
    });

    it('rejects signed payloads with invalid customData type (e.g. array or primitive)', () => {
      const invalidCustomData = {
        pactId: 'pact-1',
        verifierId: 'ver-1',
        action: 'approve',
        expiresAtIso: '2027-01-01T00:00:00.000Z',
        customData: ['not', 'a', 'record'],
      };
      const b64 = Buffer.from(JSON.stringify(invalidCustomData), 'utf-8').toString('base64url');
      const sig = createHmac('sha256', validSecret).update(b64).digest('base64url');
      const token = `${b64}.${sig}`;

      const result = verifySignedToken(token, validSecret);
      assert.strictEqual(result.isValid, false);
      assert.strictEqual(result.payload, null);
      assert.match(result.error ?? '', /customData: must be a record object/i);
    });

    it('rejects invalid or unparseable injected nowClockIso dates', () => {
      const token = generateSignedToken(mockPayload, validSecret);
      const result = verifySignedToken(token, validSecret, 'invalid-clock-string');

      assert.strictEqual(result.isValid, false);
      assert.strictEqual(result.payload, null);
      assert.match(result.error ?? '', /nowClockIso/i);
    });

    it('rejects timezone-free date-time values to ensure unambiguous absolute instant', () => {
      const timezoneFreeIso = '2027-01-01T12:00:00';

      // Rejection in generator
      const timezoneFreePayload = {
        ...mockPayload,
        expiresAtIso: timezoneFreeIso,
      };
      assert.throws(
        () => generateSignedToken(timezoneFreePayload, validSecret),
        /explicit timezone offset/i
      );

      // Rejection in verifier
      const b64 = Buffer.from(JSON.stringify(timezoneFreePayload), 'utf-8').toString('base64url');
      const sig = createHmac('sha256', validSecret).update(b64).digest('base64url');
      const token = `${b64}.${sig}`;

      const result = verifySignedToken(token, validSecret);
      assert.strictEqual(result.isValid, false);
      assert.match(result.error ?? '', /explicit timezone offset/i);

      // Rejection in helper
      assert.strictEqual(isValidCalendarIsoString(timezoneFreeIso), false);
    });

    it('correctly accepts and handles explicit timezone offsets (e.g. +05:30, -08:00)', () => {
      const explicitOffsetPayload: SignedTokenPayload = {
        ...mockPayload,
        expiresAtIso: '2027-01-01T12:00:00+05:30',
      };

      const token = generateSignedToken(explicitOffsetPayload, validSecret);
      const result = verifySignedToken(token, validSecret, '2026-12-31T00:00:00Z');

      assert.strictEqual(result.isValid, true);
      assert.strictEqual(result.isExpired, false);
      assert.deepStrictEqual(result.payload, explicitOffsetPayload);

      assert.strictEqual(isValidCalendarIsoString('2027-01-01T12:00:00+05:30'), true);
      assert.strictEqual(isValidCalendarIsoString('2027-01-01T12:00:00-08:00'), true);
    });

    it('rejects impossible calendar dates like February 30 (e.g. 2027-02-30)', () => {
      const impossibleDatePayload = {
        pactId: 'pact-123',
        verifierId: 'ver-456',
        action: 'approve',
        expiresAtIso: '2027-02-30T00:00:00.000Z',
      };
      const b64 = Buffer.from(JSON.stringify(impossibleDatePayload), 'utf-8').toString('base64url');
      const sig = createHmac('sha256', validSecret).update(b64).digest('base64url');
      const token = `${b64}.${sig}`;

      const result = verifySignedToken(token, validSecret, '2027-01-01T00:00:00.000Z');
      assert.strictEqual(result.isValid, false);
      assert.strictEqual(result.payload, null);
      assert.match(result.error ?? '', /expiresAtIso/i);

      // Also ensure generator throws on impossible dates
      assert.throws(
        () =>
          generateSignedToken(
            impossibleDatePayload as unknown as SignedTokenPayload,
            validSecret
          ),
        /expiresAtIso must be a valid calendar ISO date string/i
      );
    });

    it('rejects tokens containing non-base64url characters in payload or signature', () => {
      const token = generateSignedToken(mockPayload, validSecret);
      const [payloadB64, sigB64] = token.split('.');

      assert.strictEqual(verifySignedToken(`${payloadB64}+==.${sigB64}`, validSecret).isValid, false);
      assert.strictEqual(verifySignedToken(`${payloadB64}.${sigB64}==`, validSecret).isValid, false);
      assert.strictEqual(verifySignedToken(`${payloadB64} .${sigB64}`, validSecret).isValid, false);
      assert.strictEqual(verifySignedToken(`${payloadB64}.${sigB64}/`, validSecret).isValid, false);
    });

    it('correctly handles leap year dates (2024-02-29 vs 2023-02-29)', () => {
      assert.strictEqual(isValidCalendarIsoString('2024-02-29T00:00:00.000Z'), true);
      assert.strictEqual(isValidCalendarIsoString('2023-02-29T00:00:00.000Z'), false);
      assert.strictEqual(isValidCalendarIsoString('2026-04-31T00:00:00.000Z'), false);
    });

    it('correctly serializes and verifies payloads backed by class prototype getters', () => {
      class GetterPayload implements SignedTokenPayload {
        get pactId() {
          return 'pact-uuid-class-123';
        }
        get verifierId() {
          return 'verifier-user-456';
        }
        get action(): 'approve' {
          return 'approve';
        }
        get expiresAtIso() {
          return '2027-01-01T00:00:00.000Z';
        }
        get customData() {
          return { role: 'mentor' };
        }
      }

      const instance = new GetterPayload();
      const token = generateSignedToken(instance, validSecret);
      const result = verifySignedToken(token, validSecret, '2026-11-23T00:00:00.000Z');

      assert.strictEqual(result.isValid, true);
      assert.strictEqual(result.isExpired, false);
      assert.strictEqual(result.payload?.pactId, 'pact-uuid-class-123');
      assert.strictEqual(result.payload?.verifierId, 'verifier-user-456');
      assert.strictEqual(result.payload?.action, 'approve');
      assert.deepStrictEqual(result.payload?.customData, { role: 'mentor' });
    });
  });
});
