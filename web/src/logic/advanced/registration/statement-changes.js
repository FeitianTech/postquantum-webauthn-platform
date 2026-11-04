// The Advanced registration form's changes for what an MDS statement says
// (statement-settings.js), field by field as the form's own setter takes them:
// each setting the statement gives and, with an attachment, the form's hints
// that agree with it. The page lets the hints win over the attachment, and the
// server would only refuse the response, so a hint the attachment contradicts
// is dropped. DOM-free: the Advanced tab sets each one.
import { deriveAllowedAttachmentsFromHints } from '../hints.js';

/** @import { RegistrationField, RegistrationSettings } from './request.js' */
/** @import { StatementSettings } from './statement-settings.js' */

/**
 * @param {RegistrationSettings} settings The form's settings now.
 * @param {StatementSettings} statement
 * @returns {Array<[RegistrationField, any]>}
 */
export function statementChanges(settings, statement) {
    /** @type {Array<[RegistrationField, any]>} */
    const changes = [];
    if (statement.algorithms) {
        changes.push(['algorithms', statement.algorithms]);
    }
    if (statement.userVerification) {
        changes.push(['userVerification', statement.userVerification]);
    }
    if (statement.attachment) {
        const { attachment } = statement;
        changes.push(['attachment', attachment]);
        const agreeing = settings.hints.filter(hint => deriveAllowedAttachmentsFromHints([hint]).includes(attachment));
        if (agreeing.length !== settings.hints.length) {
            changes.push(['hints', agreeing]);
        }
    }
    return changes;
}
