// The Allow Credentials select of the Advanced tab's authentication, with no
// page: its first two choices' words, the saved credentials an authentication
// can use (the advanced ones), those it offers (with an ID whose attachment the
// authentication's hints allow, the attachments given), each one's words, and
// the choice kept when the offer changes. What the credential helpers say of a
// record is given, as is the algorithm's name. DOM-free.
import { ATTACHMENT_LABELS } from '../constants.js';

export const ALLOW_CREDENTIALS_TEXT = {
    all: 'All credentials',
    empty: 'Empty (resident key only)',
};

/**
 * The saved credentials an authentication can use: the advanced ones, which its
 * ceremony sends the server. A simple credential is the Simple tab's: the server
 * keeps it for that tab's own sign-in, and refuses it here.
 */
export function authenticationCredentials(storedCredentials) {
    return (storedCredentials || []).filter(cred => cred && cred.type === 'advanced');
}

/**
 * The saved credentials offered, in the list's order: each its ID (hex, the
 * choice's value), its words (`${name} (${algorithm})`, then ` • ${attachment}`)
 * and its attachment. `attachments` limits the offer; `getCredentialIdHex`,
 * `getStoredCredentialAttachment` and `describeAlgorithm` read a record.
 */
export function allowCredentialChoices(storedCredentials, {
    attachments,
    getCredentialIdHex,
    getStoredCredentialAttachment,
    describeAlgorithm,
}) {
    const allowed = attachmentValue => {
        if (!attachments.length) {
            return true;
        }
        if (typeof attachmentValue !== 'string' || !attachmentValue.trim()) {
            return false;
        }
        return attachments.includes(attachmentValue.trim().toLowerCase());
    };

    const choices = [];
    (storedCredentials || []).forEach((cred, index) => {
        const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
        if (!credentialIdHex) {
            return;
        }
        const attachmentValue = getStoredCredentialAttachment(cred);
        if (!allowed(attachmentValue)) {
            return;
        }
        const name = cred.userName || cred.username || cred.email || `Credential ${index + 1}`;
        const attachmentLabel = attachmentValue ? (ATTACHMENT_LABELS[attachmentValue] || attachmentValue) : '';
        const suffix = attachmentLabel ? ` • ${attachmentLabel}` : '';
        choices.push({
            value: credentialIdHex,
            label: `${name} (${describeAlgorithm(cred)})${suffix}`,
            attachment: attachmentValue || '',
        });
    });
    return choices;
}

/** The choice the select keeps when its offer changes: the same one if it is still offered, else All. */
export function keptChoice(choices, value) {
    const offered = value === 'all' || value === 'empty' || choices.some(choice => choice.value === value);
    return offered ? value : 'all';
}
