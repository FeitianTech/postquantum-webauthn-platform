// A form change applied to the request the JSON editor holds, with no page: what
// the form's request changed, from before the change to after it, is written
// over the request as typed, and everything else stays as typed: the keys the
// form does not hold (rp.id, rpId, the keys beside publicKey), the values it
// holds that the change left alone, however they are spelled, and the members
// of a list it neither added nor dropped, in their place and with whatever else
// they carry (transports, another user's credential, the order typed).
// DOM-free.
import { extractHexFromJsonFormat } from './byte-values.js';
import { requestText } from './model.js';
import { isPlainObject } from './schema.js';

function same(left, right) {
    if (left === right) {
        return true;
    }
    if (Array.isArray(left) && Array.isArray(right)) {
        return left.length === right.length && left.every((item, index) => same(item, right[index]));
    }
    if (isPlainObject(left) && isPlainObject(right)) {
        const keys = Object.keys(left);
        return keys.length === Object.keys(right).length
            && keys.every(key => Object.hasOwn(right, key) && same(left[key], right[key]));
    }
    return false;
}

// A byte value ({"$hex": …}, {"$base64url": …}): one value, however it is spelled.
function isByteValue(value) {
    const keys = Object.keys(value);
    return keys.length > 0 && keys.every(key => key.startsWith('$'));
}

// A list member's identity: a credential by its ID (as hex, lower case), an
// algorithm by its number, a hint by its value; none for anything else.
function memberKey(member) {
    if (typeof member === 'string') {
        return `value:${member}`;
    }
    if (!isPlainObject(member)) {
        return null;
    }
    if (Object.hasOwn(member, 'alg')) {
        return `alg:${member.alg}`;
    }
    try {
        const hexValue = extractHexFromJsonFormat(member.id);
        return hexValue ? `id:${hexValue.toLowerCase()}` : null;
    } catch (error) {
        return null;
    }
}

// The typed list with the members the form dropped taken out and those it
// added put in, each after the nearest member before it in the form's list
// that the typed list holds (else first); the rest as typed.
function patchMembers(typed, before, after) {
    const beforeKeys = new Set(before.map(memberKey));
    const afterKeys = after.map(memberKey);
    const result = typed.filter(member => {
        const key = memberKey(member);
        return !(beforeKeys.has(key) && !afterKeys.includes(key));
    });
    const place = key => result.findIndex(member => memberKey(member) === key);
    after.forEach((member, index) => {
        // Only what the form added: a member it kept that the typed list lacks stays out.
        if (beforeKeys.has(afterKeys[index]) || place(afterKeys[index]) >= 0) {
            return;
        }
        let position = 0;
        for (let earlier = index - 1; earlier >= 0; earlier -= 1) {
            const found = place(afterKeys[earlier]);
            if (found >= 0) {
                position = found + 1;
                break;
            }
        }
        result.splice(position, 0, member);
    });
    return result;
}

const identified = list => list.every(member => memberKey(member) !== null);

/**
 * The typed request (any JSON value) after the form's request went from
 * `before` to `after`: what the change left alone stays as typed (absent
 * included); what the typed value spells as `before` does becomes `after`'s;
 * an object follows key by key, a list of credentials, algorithms or hints
 * member by member; anything else takes `after`'s value (undefined: none).
 */
export function patchRequest(typed, before, after) {
    if (same(before, after)) {
        return typed;
    }
    if (same(typed, before)) {
        return after;
    }
    if (isPlainObject(typed) && isPlainObject(before) && isPlainObject(after)
        && !isByteValue(before) && !isByteValue(after) && !isByteValue(typed)) {
        const result = { ...typed };
        new Set([...Object.keys(before), ...Object.keys(after)]).forEach(key => {
            const next = patchRequest(typed[key], before[key], after[key]);
            if (next === undefined) {
                delete result[key];
            } else {
                result[key] = next;
            }
        });
        return result;
    }
    if (Array.isArray(typed) && Array.isArray(before) && Array.isArray(after) && identified(before) && identified(after)) {
        return patchMembers(typed, before, after);
    }
    return after;
}

/**
 * The editor's text after a form change, the form's request having gone from
 * `before` to `after` (both `{ publicKey }`): the text patched when it is an
 * object holding a publicKey object; otherwise the form's request, with the
 * keys (`extras`) an edit last held beside publicKey.
 */
export function followForm(text, before, after, extras = {}) {
    let root = null;
    try {
        root = JSON.parse(text);
    } catch (error) {
        root = null;
    }
    if (isPlainObject(root) && isPlainObject(root.publicKey)) {
        return requestText(patchRequest(root, before, after));
    }
    return requestText({ ...extras, ...after });
}
