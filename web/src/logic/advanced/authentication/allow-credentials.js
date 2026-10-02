// The Allow Credentials select of the Advanced tab's authentication, with no
// page: its first two choices' words, the saved credentials an authentication
// can use (the advanced ones), those it offers (with an ID whose attachment the
// authentication's hints allow), each one's words, and the choice kept when the
// offer changes. DOM-free.
import { describeCredentialAlgorithmWith } from '../../credentials/algorithm-tag.js';
import { describeCoseAlgorithm } from '../../credentials/cose-labels.js';
import { getCredentialIdHex, getStoredCredentialAttachment } from '../../credentials/record-fields.js';
import { deriveAllowedAttachmentsFromHints } from '../hints.js';

/** @import { SavedCredential } from '../../credentials/saved-list.js' */

/**
 * A saved credential Allow Credentials offers: its ID (hex), its words and its attachment.
 * @typedef {{ value: string, label: string, attachment: string }} AllowChoice
 */

const ATTACHMENT_LABELS = {
    'cross-platform': 'Cross-platform (Security key / Hybrid)',
    'platform': 'Platform (Client device)',
};

export const ALLOW_CREDENTIALS_TEXT = {
    all: 'All credentials',
    empty: 'Empty (resident key only)',
};

/**
 * The saved credentials an authentication can use: the advanced ones, which its
 * ceremony sends the server. A simple credential is the Simple tab's: the server
 * keeps it for that tab's own sign-in, and refuses it here.
 * @param {SavedCredential[] | null | undefined} storedCredentials
 * @returns {SavedCredential[]}
 */
export function authenticationCredentials(storedCredentials) {
    return (storedCredentials || []).filter(cred => cred && cred.type === 'advanced');
}

/**
 * The saved credentials offered, in the list's order: each its ID (hex, the
 * choice's value), its words (`${name} (${algorithm})`, then ` • ${attachment}`)
 * and its attachment. Only those whose attachment the authentication's hints
 * allow are offered (every one without hints).
 * @param {Array<Record<string, any>> | null | undefined} storedCredentials
 * @param {string[]} hints
 * @returns {AllowChoice[]}
 */
export function allowCredentialChoices(storedCredentials, hints) {
    const attachments = deriveAllowedAttachmentsFromHints(hints);
    const allowed = attachmentValue => {
        if (!attachments.length) {
            return true;
        }
        if (typeof attachmentValue !== 'string' || !attachmentValue.trim()) {
            return false;
        }
        return attachments.includes(attachmentValue.trim().toLowerCase());
    };

    /** @type {AllowChoice[]} */
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
            label: `${name} (${describeCredentialAlgorithmWith(cred, describeCoseAlgorithm)})${suffix}`,
            attachment: attachmentValue || '',
        });
    });
    return choices;
}

/**
 * The choice the select keeps when its offer changes: the same one if it is still offered, else All.
 * @param {AllowChoice[]} choices
 * @param {string} value
 * @returns {string}
 */
export function keptChoice(choices, value) {
    const offered = value === 'all' || value === 'empty' || choices.some(choice => choice.value === value);
    return offered ? value : 'all';
}
