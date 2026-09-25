import { describe, expect, it, vi } from 'vitest';

import {
  FailedResponseError,
  readFailedResponse,
  throwFailedResponse,
} from '../../../../frontend/static/scripts/shared/api/failed-response.js';

const WERKZEUG_400 = '<!doctype html>\n<html lang=en>\n<title>400 Bad Request</title>\n<h1>Bad Request</h1>\n';

function response(status, body, contentType = 'application/json') {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return new Response(text, { status, headers: { 'Content-Type': contentType } });
}

describe('readFailedResponse', () => {
  it.each([
    [
      '409 from the credential store',
      response(409, { error: 'The stored credentials changed while this one was being saved, too many times, so the registration was not saved. Please try again.' }),
      'The stored credentials changed while this one was being saved, too many times, so the registration was not saved. Please try again.',
    ],
    [
      '503 from the credential store',
      response(503, { error: 'The stored credentials could not be read. Please try again.' }),
      'The stored credentials could not be read. Please try again.',
    ],
    [
      '503 for the stored counter',
      response(503, { error: 'The stored signature counter could not be read, so authentication was rejected. Please try again.' }),
      'The stored signature counter could not be read, so authentication was rejected. Please try again.',
    ],
    [
      '413',
      response(413, { error: 'The request is larger than the limit of 8388608 bytes this server accepts.' }),
      'The request is larger than the limit of 8388608 bytes this server accepts. Send a smaller request.',
    ],
    [
      '400 with an expired ceremony state',
      response(400, { error: 'Registration state not found or has expired. Please restart the registration process.' }),
      'Registration state not found or has expired. Please restart the registration process.',
    ],
    [
      '400 whose challenge was used before',
      response(400, { error: 'The challenge was not accepted.', challengeStatus: 'replayed' }),
      'The challenge was not accepted. Start the ceremony again.',
    ],
    [
      '400 rejecting the assertion',
      response(400, { error: 'Invalid signature.' }),
      'Invalid signature.',
    ],
    [
      '400 answered as HTML',
      response(400, WERKZEUG_400, 'text/html; charset=utf-8'),
      'The server could not accept the request. Start the ceremony again.',
    ],
    [
      '503 answered as HTML by a proxy',
      response(503, '<html><body>Service Unavailable</body></html>', 'text/html'),
      'The server is unavailable. Try again in a moment.',
    ],
    [
      '409 with no message',
      response(409, ''),
      'The stored credentials changed while the request was handled. Try again.',
    ],
    [
      '500 answered as plain text',
      response(500, 'backend down', 'text/plain'),
      'backend down',
    ],
    [
      'an unlisted status with no body',
      response(418, ''),
      'The server answered with status 418.',
    ],
  ])('%s', async (_label, failed, expected) => {
    expect((await readFailedResponse(failed)).text).toBe(expected);
  });

  it('keeps the fields the UI acts on, and the body', async () => {
    const failure = await readFailedResponse(response(400, {
      error: 'Signature counter did not increase (stored 7, received 7). This authenticator may have been cloned, so authentication was rejected.',
      failedCredentialId: 'AQID',
      signCountStatus: 'regressed',
      challengeSource: 'server-session',
      challengeStatus: 'fresh',
    }));

    expect(failure).toMatchObject({
      status: 400,
      advice: '',
      failedCredentialId: 'AQID',
      signCountStatus: 'regressed',
      challengeSource: 'server-session',
      challengeStatus: 'fresh',
    });
    expect(failure.body.failedCredentialId).toBe('AQID');
  });

  it('does not show a long plain-text body', async () => {
    const failure = await readFailedResponse(response(500, 'x'.repeat(301), 'text/plain'));

    expect(failure.text).toBe('The server failed while handling the request.');
  });

  it('ignores a JSON body that is not an object', async () => {
    const failure = await readFailedResponse(response(409, '["not", "an", "object"]'));

    expect(failure.body).toBeNull();
    expect(failure.text).toBe('The stored credentials changed while the request was handled. Try again.');
  });

  it('reads a response that only offers json()', async () => {
    const failure = await readFailedResponse({ status: 422, json: vi.fn().mockResolvedValue({ error: 'bad payload' }) });

    expect(failure.text).toBe('bad payload');
  });

  it('copes with a body that cannot be read, or no response at all', async () => {
    const unreadable = {
      status: 502,
      headers: { get: () => { throw new Error('no headers'); } },
      text: vi.fn().mockRejectedValue(new Error('network')),
      json: vi.fn().mockRejectedValue(new Error('network')),
    };

    expect((await readFailedResponse(unreadable)).text).toBe('The server could not be reached.');
    expect((await readFailedResponse(undefined)).text).toBe('The server did not answer.');
  });
});

describe('throwFailedResponse', () => {
  it('throws the reading as a FailedResponseError', async () => {
    const error = await throwFailedResponse(response(413, { error: 'Too large.' })).catch((thrown) => thrown);

    expect(error).toBeInstanceOf(FailedResponseError);
    expect(error.name).toBe('FailedResponseError');
    expect(error.message).toBe('Too large. Send a smaller request.');
    expect(error.failure.status).toBe(413);
  });

  it('names the step that failed when told it', async () => {
    const error = await throwFailedResponse(response(409, ''), 'Registration failed').catch((thrown) => thrown);

    expect(error.message).toBe('Registration failed: The stored credentials changed while the request was handled. Try again.');
  });
});
