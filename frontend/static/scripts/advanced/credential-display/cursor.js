import {
    getGlobalCursorApplyCount,
    getGlobalCursorPreviousValues,
    setGlobalCursorApplyCount,
    setGlobalCursorPreviousValues,
} from './state.js';

const GLOBAL_CURSOR_CLASS_MAP = new Map([
    ['progress', 'global-cursor--progress'],
    ['wait', 'global-cursor--wait'],
]);

export function applyGlobalCursor(cursorStyle) {
    if (typeof document === 'undefined') {
        return () => {};
    }

    const desiredCursor = typeof cursorStyle === 'string' ? cursorStyle.trim() : '';
    if (!desiredCursor) {
        return () => {};
    }

    const elements = [document.body, document.documentElement]
        .filter(element => element instanceof HTMLElement);
    if (!elements.length) {
        return () => {};
    }

    if (getGlobalCursorApplyCount() === 0) {
        setGlobalCursorPreviousValues(elements.map(element => ({
            cursor: element.style.cursor || '',
            classes: new Set(Array.from(element.classList || [])),
        })));
    }

    setGlobalCursorApplyCount(getGlobalCursorApplyCount() + 1);
    const className = GLOBAL_CURSOR_CLASS_MAP.get(desiredCursor) || null;

    elements.forEach(element => {
        element.style.cursor = desiredCursor === 'progress' ? 'wait' : desiredCursor;
        if (className) {
            element.classList.add(className);
        }
    });

    let restored = false;
    return () => {
        if (restored) {
            return;
        }
        restored = true;

        setGlobalCursorApplyCount(Math.max(0, getGlobalCursorApplyCount() - 1));
        if (getGlobalCursorApplyCount() === 0) {
            const previousValues = getGlobalCursorPreviousValues();
            elements.forEach((element, index) => {
                const previousValue = previousValues[index] || {};
                if (typeof previousValue.cursor === 'string' && previousValue.cursor) {
                    element.style.cursor = previousValue.cursor;
                } else {
                    element.style.removeProperty('cursor');
                }
                const previousClasses = previousValue?.classes;
                GLOBAL_CURSOR_CLASS_MAP.forEach(candidateClass => {
                    if (!candidateClass) {
                        return;
                    }
                    const previouslyHadClass = previousClasses instanceof Set && previousClasses.has(candidateClass);
                    if (!previouslyHadClass) {
                        element.classList.remove(candidateClass);
                    }
                });
            });
            setGlobalCursorPreviousValues([]);
        }
    };
}
