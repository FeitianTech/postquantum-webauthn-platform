// Build DOM from data without parsing markup. A string becomes a text node or an
// attribute value set with setAttribute; nothing given to el() is ever read as
// HTML, so a value cannot open an element or an attribute of its own.
//
// Event handlers are attached in code with addEventListener, never through an
// attribute: el() refuses any attribute whose name starts with "on", and the
// markup-bearing ones (innerHTML, outerHTML, srcdoc).

const MARKUP_ATTRIBUTES = new Set(['innerhtml', 'outerhtml', 'srcdoc']);

function assertPlainAttribute(name) {
    const lowered = String(name).toLowerCase();
    if (lowered.startsWith('on') || MARKUP_ATTRIBUTES.has(lowered)) {
        throw new Error(`el() does not set the "${name}" attribute: handlers are added in code and markup is never parsed.`);
    }
}

function appendChildren(parent, children) {
    for (const child of children) {
        if (child === null || child === undefined || child === false || child === true) {
            continue;
        }
        if (Array.isArray(child)) {
            appendChildren(parent, child);
        } else if (child instanceof Node) {
            parent.appendChild(child);
        } else {
            parent.appendChild(document.createTextNode(String(child)));
        }
    }
}

/**
 * Create an element.
 *
 * options: className, attrs (name -> value; true sets an empty attribute, false,
 * null and undefined leave it out), dataset, style (a literal from code, applied
 * through CSSOM: the CSP's style-src has no 'unsafe-inline', which refuses a style
 * attribute but not element.style) and text.
 * Children are appended after text: strings and numbers as text nodes, Nodes as
 * they are, arrays flattened, null / undefined / booleans skipped.
 */
export function el(tag, options = {}, ...children) {
    const node = document.createElement(tag);
    const {
        className,
        attrs,
        dataset,
        style,
        text,
    } = options || {};

    if (className) {
        node.className = className;
    }
    if (attrs) {
        for (const [name, value] of Object.entries(attrs)) {
            assertPlainAttribute(name);
            if (value === null || value === undefined || value === false) {
                continue;
            }
            node.setAttribute(name, value === true ? '' : String(value));
        }
    }
    if (dataset) {
        for (const [key, value] of Object.entries(dataset)) {
            if (value !== null && value !== undefined) {
                node.dataset[key] = String(value);
            }
        }
    }
    if (style) {
        node.style.cssText = style;
    }
    if (text !== null && text !== undefined) {
        node.textContent = String(text);
    }
    appendChildren(node, children);
    return node;
}

/** A DocumentFragment of the given children, appended as el() appends them. */
export function fragment(...children) {
    const node = document.createDocumentFragment();
    appendChildren(node, children);
    return node;
}
