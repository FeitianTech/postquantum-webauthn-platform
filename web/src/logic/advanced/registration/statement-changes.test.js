import { describe, expect, it } from 'vitest';

import { statementChanges } from './statement-changes.js';
import { registrationDefaults } from './request.js';

// The Advanced registration's changes for an MDS statement (advanced/registration/statement-changes.js).

const settings = (hints = []) => ({ ...registrationDefaults(), userId: '', userName: '', displayName: '', challenge: '', hints });

describe('statementChanges', () => {
  it('sets each setting the statement gives, as the form\'s setter takes it', () => {
    expect(statementChanges(settings(), { algorithms: [-8, -7], userVerification: 'required', attachment: 'cross-platform' })).toEqual([
      ['algorithms', [-8, -7]],
      ['userVerification', 'required'],
      ['attachment', 'cross-platform'],
    ]);
    expect(statementChanges(settings(), { userVerification: 'discouraged' })).toEqual([['userVerification', 'discouraged']]);
  });

  it('drops the hints an attachment contradicts, and keeps those that agree', () => {
    expect(statementChanges(settings(['client-device', 'security-key', 'hybrid']), { attachment: 'platform' })).toEqual([
      ['attachment', 'platform'],
      ['hints', ['client-device']],
    ]);
    expect(statementChanges(settings(['security-key', 'hybrid']), { attachment: 'cross-platform' })).toEqual([['attachment', 'cross-platform']]);
  });
});
