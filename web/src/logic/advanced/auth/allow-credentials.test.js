import { describe, expect, it } from 'vitest';

import {
  ALLOW_CREDENTIALS_TEXT,
  allowCredentialChoices,
  authenticationCredentials,
  keptChoice,
} from './allow-credentials.js';
import { describeCoseAlgorithm } from '../cose-labels.js';
import { describeCredentialAlgorithmWith } from '../credentials/algorithm-tag.js';
import {
  getCredentialIdHex,
  getStoredCredentialAttachment,
} from '../credentials/utils.js';

// The Allow Credentials select of the Advanced tab's authentication, with no
// page (advanced/auth/allow-credentials.js), over the real credential helpers.

const HELPERS = {
  getCredentialIdHex,
  getStoredCredentialAttachment,
  describeAlgorithm: (credential) => describeCredentialAlgorithmWith(credential, describeCoseAlgorithm),
};

const PLATFORM = { credentialIdHex: 'aa01', userName: 'alice', authenticatorAttachment: 'platform', publicKeyAlgorithm: -7 };
const ROAMING = { credentialId: 'uwI', username: 'bob', properties: { authenticatorAttachment: ' Cross-Platform ' }, publicKeyAlgorithm: -8 };
const UNATTACHED = { credentialIdHex: 'cc03', email: 'carol@example.com', publicKeyAlgorithm: -48 };
const UNNAMED = { credentialIdHex: 'dd04', authenticatorAttachment: 'usb', publicKeyAlgorithm: -7 };
const NO_ID = { userName: 'nobody' };
const STORED = [PLATFORM, ROAMING, UNATTACHED, UNNAMED, NO_ID];

const offered = (attachments) => allowCredentialChoices(STORED, { attachments, ...HELPERS });

describe('the Allow Credentials choices', () => {
  it('begin with All and Empty', () => {
    expect(ALLOW_CREDENTIALS_TEXT).toEqual({ all: 'All credentials', empty: 'Empty (resident key only)' });
  });

  it('offer every saved credential with an ID, named, with its algorithm and attachment', () => {
    expect(offered([])).toEqual([
      { value: 'aa01', label: 'alice (ES256 (-7)) • Platform (Client device)', attachment: 'platform' },
      { value: 'bb02', label: 'bob (EdDSA (-8)) • Cross-platform (Security key / Hybrid)', attachment: 'cross-platform' },
      { value: 'cc03', label: 'carol@example.com (ML-DSA-44 (PQC) (-48))', attachment: '' },
      { value: 'dd04', label: 'Credential 4 (ES256 (-7)) • usb', attachment: 'usb' },
    ]);
  });

  it('offer only the credentials whose attachment the filter names', () => {
    expect(offered(['platform']).map((choice) => choice.value)).toEqual(['aa01']);
    expect(offered(['cross-platform']).map((choice) => choice.value)).toEqual(['bb02']);
    expect(allowCredentialChoices(undefined, { attachments: [], ...HELPERS })).toEqual([]);
  });

  it('are made from the advanced credentials only, which the ceremony sends', () => {
    const simple = { ...PLATFORM, type: 'simple' };
    const advanced = { ...ROAMING, type: 'advanced' };
    expect(authenticationCredentials([simple, advanced, null, { ...UNATTACHED }])).toEqual([advanced]);
    expect(authenticationCredentials(undefined)).toEqual([]);
  });

  it('keep the choice while it is offered, else fall back to All', () => {
    const choices = offered([]);
    expect(keptChoice(choices, 'all')).toBe('all');
    expect(keptChoice(choices, 'empty')).toBe('empty');
    expect(keptChoice(choices, 'bb02')).toBe('bb02');
    expect(keptChoice(offered(['platform']), 'bb02')).toBe('all');
  });
});
