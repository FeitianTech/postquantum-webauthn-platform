// Read a response the server answered with an error, and say what it means.
//
// The server answers errors as JSON: {"error": "..."} plus, depending on the
// route, failedCredentialId, signCountStatus, challengeSource and
// challengeStatus. A few answers are not JSON (Werkzeug's HTML for abort(),
// a proxy's error page); those are described by their status instead of shown
// as markup. Where the server's message does not already say what to do, a
// sentence for the status is added.

const MAX_PLAIN_TEXT = 300;

// When the body carries no message of its own.
const STATUS_MESSAGES = {
    400: 'The server could not accept the request.',
    404: 'The server has nothing at that address.',
    409: 'The stored credentials changed while the request was handled.',
    413: 'The request is larger than the server accepts.',
    500: 'The server failed while handling the request.',
    502: 'The server could not be reached.',
    503: 'The server is unavailable.',
    504: 'The server did not answer in time.',
};

const STATUS_ADVICE = {
    409: 'Try again.',
    413: 'Send a smaller request.',
    503: 'Try again in a moment.',
};

const START_AGAIN = 'Start the ceremony again.';
const CEREMONY_STATE = /state not found|has expired|already been used/i;
const SAYS_WHAT_TO_DO = /\b(try again|restart|start (?:it|the [a-z]+) again)\b/i;

// `context` names the step that failed ("Registration failed"); the message is
// then "context: text".
export class FailedResponseError extends Error {
    constructor(failure, context = '') {
        super(context ? `${context}: ${failure.text}` : failure.text);
        this.name = 'FailedResponseError';
        this.failure = failure;
    }
}

async function readBody(response) {
    let text = '';
    try {
        if (typeof response?.text === 'function') {
            text = String(await response.text() ?? '');
        }
    } catch (error) {
        text = '';
    }

    let parsed;
    try {
        if (text) {
            parsed = JSON.parse(text);
        } else if (typeof response?.json === 'function') {
            parsed = await response.json();
        }
    } catch (error) {
        parsed = undefined;
    }

    const body = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    return { text, body, isJson: parsed !== undefined };
}

function contentTypeOf(response) {
    try {
        return String(response?.headers?.get?.('content-type') || '');
    } catch (error) {
        return '';
    }
}

function looksLikeMarkup(text, contentType) {
    return /html|xml/i.test(contentType) || /^\s*</.test(text);
}

function stringField(body, key) {
    return body && typeof body[key] === 'string' && body[key].trim() ? body[key].trim() : null;
}

function adviceFor(status, message, { body, hasServerMessage }) {
    if (SAYS_WHAT_TO_DO.test(message)) {
        return '';
    }
    if (status === 400) {
        // A 400 about the ceremony's state, or one the server answered without a
        // message of its own (the simple flow's abort(400) when its session holds
        // no ceremony), is answered by starting over.
        const aboutState = CEREMONY_STATE.test(message)
            || ['expired', 'replayed'].includes(stringField(body, 'challengeStatus'));
        return aboutState || !hasServerMessage ? START_AGAIN : '';
    }
    return STATUS_ADVICE[status] || '';
}

/**
 * What a failed response says: the server's message (or a sentence for its
 * status), advice where the message gives none, the fields the UI acts on, and
 * the parsed body. `text` is what to show.
 */
export async function readFailedResponse(response) {
    const status = Number(response?.status) || 0;
    const { text, body, isJson } = await readBody(response);

    const serverMessage = stringField(body, 'error');
    const plainText = !isJson && text.trim() && !looksLikeMarkup(text, contentTypeOf(response))
        && text.trim().length <= MAX_PLAIN_TEXT
        ? text.trim()
        : null;
    const hasServerMessage = Boolean(serverMessage || plainText);
    const message = serverMessage
        || plainText
        || STATUS_MESSAGES[status]
        || (status ? `The server answered with status ${status}.` : 'The server did not answer.');
    const advice = adviceFor(status, message, { body, hasServerMessage });

    return {
        status,
        message,
        advice,
        text: advice ? `${message} ${advice}` : message,
        body,
        failedCredentialId: stringField(body, 'failedCredentialId'),
        signCountStatus: stringField(body, 'signCountStatus'),
        challengeSource: stringField(body, 'challengeSource'),
        challengeStatus: stringField(body, 'challengeStatus'),
    };
}

/** Read `response` and throw it as a FailedResponseError. */
export async function throwFailedResponse(response, context = '') {
    throw new FailedResponseError(await readFailedResponse(response), context);
}
