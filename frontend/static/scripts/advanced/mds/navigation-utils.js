export function nextAnimationFrame() {
    return new Promise(resolve => {
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => resolve());
        } else {
            setTimeout(() => resolve(), 16);
        }
    });
}

export async function waitForLayoutSettled() {
    await nextAnimationFrame();
    await nextAnimationFrame();
}

export function waitForStateReady(getState, { timeout = 5000 } = {}) {
    if (getState()) {
        return Promise.resolve(true);
    }

    return new Promise(resolve => {
        const start = Date.now();
        const check = () => {
            if (getState()) {
                resolve(true);
                return;
            }
            if (Date.now() - start >= timeout) {
                resolve(false);
                return;
            }
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(check);
            } else {
                setTimeout(check, 32);
            }
        };
        check();
    });
}

export function waitForRowByKey(key, {
    getState,
    findRowByKey,
    attempts = 60,
} = {}) {
    if (!key) {
        return Promise.resolve(null);
    }

    return new Promise(resolve => {
        const attemptLookup = attempt => {
            const state = getState();
            if (!state || state.highlightedRowKey !== key) {
                resolve(null);
                return;
            }
            const row = findRowByKey(key);
            if (row) {
                resolve(row);
                return;
            }
            if (attempt >= attempts) {
                resolve(null);
                return;
            }
            const schedule = () => attemptLookup(attempt + 1);
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(schedule);
            } else {
                setTimeout(schedule, attempt < 20 ? 16 : 64);
            }
        };
        attemptLookup(0);
    });
}

export function scrollRowIntoView(row, { behavior = 'smooth' } = {}) {
    if (!(row instanceof HTMLElement)) {
        return;
    }

    if (typeof window === 'undefined' || typeof window.scrollTo !== 'function') {
        if (typeof row.scrollIntoView === 'function') {
            row.scrollIntoView({ behavior, block: 'center' });
        }
        return;
    }

    const rect = row.getBoundingClientRect();
    const viewportHeight = window.innerHeight || document.documentElement?.clientHeight || 0;
    const rowHeight = rect.height || row.offsetHeight || 0;
    const centerOffset = Math.max((viewportHeight - rowHeight) / 2, 0);
    const targetTop = rect.top + window.pageYOffset - centerOffset;
    const top = Math.max(Math.round(targetTop), 0);

    try {
        window.scrollTo({ top, behavior });
    } catch (error) {
        window.scrollTo(0, top);
    }
}

export function focusRowButton(row) {
    if (!(row instanceof HTMLElement)) {
        return;
    }
    const button = row.querySelector('.mds-name-button');
    if (!(button instanceof HTMLElement) || typeof button.focus !== 'function') {
        return;
    }

    const focusButton = () => {
        try {
            button.focus({ preventScroll: true });
        } catch (error) {
            button.focus();
        }
    };

    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(focusButton);
    } else {
        setTimeout(focusButton, 0);
    }
}
