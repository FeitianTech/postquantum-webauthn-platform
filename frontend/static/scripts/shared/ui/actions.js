// What a control does is named in the markup, never written there: the template
// gives it data-action="name" (with any argument in another data-* attribute),
// and the module that owns the behaviour binds one listener on the root of the
// area holding its controls, with a table from those names to what they do.
// Templates therefore carry no code, which is what lets the CSP's script-src
// leave out 'unsafe-inline'. Names are local to their area, as they are for the
// Analyze Browser panel's "close" and "copy-report".
//
// A table value is a function, called for a click, or an object with click,
// mouseenter and mouseleave handlers. Each is called as handler(control, event)
// and looked up when the event arrives. callWith() makes the usual handler: call
// a function with some of the control's data-* values, and nothing else.

const HOVER_EVENTS = ['mouseenter', 'mouseleave'];

/**
 * A handler that calls fn with the control's data-* values named by names, in
 * order, and with nothing else: callWith(switchTab, 'tab') calls
 * switchTab(control.dataset.tab), callWith(simpleRegister) calls simpleRegister().
 */
export function callWith(fn, ...names) {
    return control => fn(...names.map(name => control.dataset[name]));
}

function handlerFor(table, name, type) {
    if (!name || !Object.hasOwn(table, name)) {
        return null;
    }
    const entry = table[name];
    if (typeof entry === 'function') {
        return type === 'click' ? entry : null;
    }
    const handler = entry && typeof entry === 'object' ? entry[type] : null;
    return typeof handler === 'function' ? handler : null;
}

function usesEvent(table, type) {
    return Object.values(table).some(entry => (
        type === 'click'
            ? typeof entry === 'function' || typeof entry?.click === 'function'
            : typeof entry?.[type] === 'function'
    ));
}

/**
 * Bind a table of actions to the controls under root. Returns a function that
 * removes the listeners again; a missing root binds nothing.
 */
export function bindActions(root, table) {
    if (!root || typeof root.addEventListener !== 'function') {
        return () => {};
    }

    const removers = [];

    if (usesEvent(table, 'click')) {
        // A click bubbles: the control is the nearest element naming an action,
        // which may be an ancestor of the target (an icon inside a button).
        const onClick = event => {
            const target = event.target instanceof Element ? event.target : null;
            const control = target ? target.closest('[data-action]') : null;
            if (!control || !root.contains(control) || control.matches(':disabled')) {
                return;
            }
            const handler = handlerFor(table, control.dataset.action, 'click');
            if (handler) {
                handler(control, event);
            }
        };
        root.addEventListener('click', onClick);
        removers.push(() => root.removeEventListener('click', onClick));
    }

    HOVER_EVENTS.forEach(type => {
        if (!usesEvent(table, type)) {
            return;
        }
        // mouseenter and mouseleave do not bubble, but an ancestor sees them in
        // the capture phase; only the element that names the action counts, as
        // it would for an onmouseenter attribute on that element.
        const onHover = event => {
            const control = event.target instanceof Element ? event.target : null;
            if (!control || !control.hasAttribute('data-action') || !root.contains(control)) {
                return;
            }
            const handler = handlerFor(table, control.dataset.action, type);
            if (handler) {
                handler(control, event);
            }
        };
        root.addEventListener(type, onHover, true);
        removers.push(() => root.removeEventListener(type, onHover, true));
    });

    return () => removers.forEach(remove => remove());
}
