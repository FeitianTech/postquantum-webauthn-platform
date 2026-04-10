import { initializeStickyHeaderForElement } from '../../shared/ui/core.js';

export function createDetailStickyHeader(page, header, options = {}) {
    if (!(page instanceof HTMLElement) || !(header instanceof HTMLElement)) {
        return null;
    }

    const { defaultTitle = '', type = 'detail', onBack = null } = options || {};

    const backSource = header.querySelector('.mds-detail-page__back');
    const titleSource = header.querySelector('.mds-detail-page__title');
    const subtitleSource = header.querySelector('.mds-detail-page__subtitle');
    const actionsSource = header.querySelector('.mds-detail-page__actions');

    const controller = initializeStickyHeaderForElement(header, {
        root: document.body instanceof HTMLElement ? document.body : header.parentElement,
        scrollTarget: page,
        miniClass: 'mds-detail-mini',
        miniInnerClass: 'mds-detail-mini__inner',
        activeClass: 'mds-detail-mini--active',
        measuringClass: 'mds-detail-mini--measuring',
        createContent: () => {
            const wrapper = document.createElement('div');
            wrapper.className = 'mds-detail-mini__content';

            if (backSource instanceof HTMLElement) {
                const backButton = backSource.cloneNode(true);
                backButton.removeAttribute('id');
                backButton.classList.add('mds-detail-mini__back');
                wrapper.appendChild(backButton);
            }

            const heading = document.createElement('div');
            heading.className = 'mds-detail-mini__heading';

            const title = document.createElement('h3');
            title.className = 'mds-detail-page__title mds-detail-mini__title';
            title.textContent = titleSource?.textContent?.trim() || defaultTitle;
            heading.appendChild(title);

            const subtitle = document.createElement('p');
            subtitle.className = 'mds-detail-page__subtitle mds-detail-mini__subtitle';
            const subtitleText = subtitleSource?.textContent?.trim() || '';
            if (subtitleText) {
                subtitle.textContent = subtitleText;
            } else {
                subtitle.textContent = '';
                subtitle.hidden = true;
                subtitle.setAttribute('aria-hidden', 'true');
            }
            heading.appendChild(subtitle);

            wrapper.appendChild(heading);

            if (actionsSource instanceof HTMLElement && actionsSource.children.length > 0) {
                const actions = actionsSource.cloneNode(true);
                actions.removeAttribute('id');
                actions.classList.add('mds-detail-mini__actions');
                const buttons = actions.querySelectorAll('button');
                buttons.forEach(button => {
                    button.classList.add('mds-detail-mini__action');
                    button.removeAttribute('id');
                });
                wrapper.appendChild(actions);
            }

            return wrapper;
        },
    });

    if (!controller) {
        return null;
    }

    const miniHeader = controller.miniHeader;
    const miniInner = controller.miniInner;
    miniHeader.hidden = true;
    miniHeader.setAttribute('aria-hidden', 'true');
    miniHeader.dataset.mdsStickyType = type;

    const backTarget = miniHeader.querySelector('.mds-detail-mini__back');
    if (backTarget instanceof HTMLElement && backSource instanceof HTMLElement) {
        backTarget.addEventListener('click', event => {
            event.preventDefault();
            if (typeof onBack === 'function') {
                onBack();
            } else if (typeof backSource.click === 'function') {
                backSource.click();
            }
        });
    }

    const titleTarget = miniHeader.querySelector('.mds-detail-mini__title');
    const subtitleTarget = miniHeader.querySelector('.mds-detail-mini__subtitle');
    const actionsTarget = miniHeader.querySelector('.mds-detail-mini__actions');

    const actionPairs = [];
    if (actionsSource instanceof HTMLElement && actionsTarget instanceof HTMLElement) {
        const sourceButtons = Array.from(actionsSource.querySelectorAll('button'));
        const targetButtons = Array.from(actionsTarget.querySelectorAll('button'));
        targetButtons.forEach((button, index) => {
            const sourceButton = sourceButtons[index] || null;
            button.addEventListener('click', event => {
                event.preventDefault();
                if (sourceButton && typeof sourceButton.click === 'function') {
                    sourceButton.click();
                }
            });
            actionPairs.push({ source: sourceButton, target: button });
        });
    }

    let restoreAnimationCancel = null;

    const cancelRestoreAnimation = () => {
        if (typeof restoreAnimationCancel === 'function') {
            try {
                restoreAnimationCancel();
            } catch (error) {
                // Ignore cleanup errors.
            }
            restoreAnimationCancel = null;
        }
    };

    const startRestoreAnimation = () => {
        if (!miniHeader || miniHeader.hidden || !(miniInner instanceof HTMLElement)) {
            return null;
        }

        const scheduleTimeout =
            typeof window !== 'undefined' && typeof window.setTimeout === 'function'
                ? window.setTimeout.bind(window)
                : setTimeout;
        const cancelTimeout =
            typeof window !== 'undefined' && typeof window.clearTimeout === 'function'
                ? window.clearTimeout.bind(window)
                : clearTimeout;

        let timeoutId = null;
        let finished = false;

        const handleTransitionEnd = event => {
            if (!event || (event.target !== miniHeader && event.target !== miniInner)) {
                return;
            }
            cleanup();
        };

        function cleanup() {
            if (finished) {
                return;
            }
            finished = true;
            miniHeader.classList.remove('mds-detail-mini--restoring');
            miniInner.classList.remove('mds-detail-mini__inner--restoring');
            miniHeader.removeEventListener('transitionend', handleTransitionEnd);
            miniInner.removeEventListener('transitionend', handleTransitionEnd);
            if (timeoutId !== null) {
                cancelTimeout(timeoutId);
                timeoutId = null;
            }
            restoreAnimationCancel = null;
        }

        miniHeader.classList.add('mds-detail-mini--restoring');
        miniInner.classList.add('mds-detail-mini__inner--restoring');
        miniHeader.addEventListener('transitionend', handleTransitionEnd);
        miniInner.addEventListener('transitionend', handleTransitionEnd);

        timeoutId = scheduleTimeout(() => {
            cleanup();
        }, 360);

        return cleanup;
    };

    const sync = () => {
        if (titleTarget) {
            const titleText = titleSource?.textContent?.trim() || defaultTitle;
            titleTarget.textContent = titleText;
            titleTarget.setAttribute('title', titleText);
        }

        if (subtitleTarget) {
            const subtitleText = subtitleSource?.textContent?.trim() || '';
            if (subtitleText) {
                subtitleTarget.textContent = subtitleText;
                subtitleTarget.hidden = false;
                subtitleTarget.setAttribute('aria-hidden', 'false');
            } else {
                subtitleTarget.textContent = '';
                subtitleTarget.hidden = true;
                subtitleTarget.setAttribute('aria-hidden', 'true');
            }
        }

        actionPairs.forEach(({ source, target }) => {
            if (!target) {
                return;
            }
            if (!source) {
                target.disabled = true;
                target.setAttribute('aria-disabled', 'true');
                target.setAttribute('tabindex', '-1');
                return;
            }

            target.disabled = source.disabled;
            if (source.hasAttribute('aria-disabled')) {
                target.setAttribute('aria-disabled', source.getAttribute('aria-disabled'));
            } else {
                target.setAttribute('aria-disabled', source.disabled ? 'true' : 'false');
            }

            if (source.hasAttribute('title')) {
                target.setAttribute('title', source.getAttribute('title'));
            } else {
                target.removeAttribute('title');
            }

            if (source.hasAttribute('aria-label')) {
                target.setAttribute('aria-label', source.getAttribute('aria-label'));
            } else {
                target.removeAttribute('aria-label');
            }

            if (source.hasAttribute('data-tooltip')) {
                target.setAttribute('data-tooltip', source.getAttribute('data-tooltip'));
            } else {
                target.removeAttribute('data-tooltip');
            }

            const textContent = source.textContent || '';
            target.textContent = textContent;

            if (source.hasAttribute('tabindex')) {
                target.setAttribute('tabindex', source.getAttribute('tabindex'));
            } else {
                target.removeAttribute('tabindex');
            }
        });
    };

    const show = () => {
        miniHeader.hidden = false;
        miniHeader.setAttribute('aria-hidden', 'false');
        cancelRestoreAnimation();
        controller.reset();
        restoreAnimationCancel = startRestoreAnimation();
        controller.refreshGeometry();
        controller.evaluate();
        sync();
    };

    const prepareForClose = () => {
        cancelRestoreAnimation();
        controller.reset();
    };

    const hide = () => {
        cancelRestoreAnimation();
        miniHeader.hidden = true;
        miniHeader.setAttribute('aria-hidden', 'true');
    };

    return {
        controller,
        header,
        page,
        show,
        hide,
        sync,
        prepareForClose,
        miniHeader,
    };
}
