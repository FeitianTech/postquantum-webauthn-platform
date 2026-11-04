import { describe, expect, it } from 'vitest';

import { responseParts } from './response-parts.js';
import {
  advancedAuthentications,
  advancedRegistrations,
  recordedAssertion,
  recordedCredential,
} from '@/test/logic/advanced/advanced-answers.js';

// The parts of a ceremony's response the Advanced result hands the Codec (advanced/response-parts.js).

describe('responseParts', () => {
  it('gives a registration\'s whole response, then its attestation object and client data, as the browser wrote them', () => {
    const json = recordedCredential(advancedRegistrations()[1]).toJSON();
    const parts = responseParts(json);

    expect(parts.map(({ part, label }) => [part, label])).toEqual([
      ['response', 'Response'],
      ['attestation object', 'Attestation object'],
      ['client data', 'Client data'],
    ]);
    expect(JSON.parse(parts[0].payload)).toEqual(json);
    expect(parts[0].payload).toContain('\n  "response": {');
    expect(parts[1].payload).toBe(json.response.attestationObject);
    expect(parts[2].payload).toBe(json.response.clientDataJSON);
  });

  it('gives an authentication\'s client data and authenticator data, and neither its signature nor its user handle', () => {
    const json = recordedAssertion(advancedAuthentications().first).toJSON();
    json.response.userHandle = 'dXNlcg';
    const parts = responseParts(json);

    expect(parts.map(({ part }) => part)).toEqual(['response', 'client data', 'authenticator data']);
    expect(parts[2].payload).toBe(json.response.authenticatorData);
    expect(parts.some(({ payload }) => payload === json.response.signature)).toBe(false);
  });

  it('gives a registration\'s authenticator data when the browser wrote it, trimmed', () => {
    const parts = responseParts({ response: { attestationObject: ' o2Nm ', authenticatorData: 'SZYN', clientDataJSON: '' } });
    expect(parts.map(({ part, payload }) => [part, payload]).slice(1)).toEqual([
      ['attestation object', 'o2Nm'],
      ['authenticator data', 'SZYN'],
    ]);
  });

  it('gives nothing for no response, or one without its parts', () => {
    expect(responseParts(null)).toEqual([]);
    expect(responseParts({ id: 'AQID' })).toEqual([]);
    expect(responseParts({ response: 'o2Nm' })).toEqual([]);
    expect(responseParts({ response: { attestationObject: 7 } })).toEqual([{ part: 'response', label: 'Response', payload: '{\n  "response": {\n    "attestationObject": 7\n  }\n}' }]);
  });
});
