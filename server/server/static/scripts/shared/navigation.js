import { state } from './state.js';
import { updateJsonEditor } from '../advanced/json-editor.js';

export function switchTab(tab) {
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tab}-tab`);
    });

    document.querySelectorAll('.nav-tab').forEach(navTab => {
        navTab.classList.toggle('active', navTab.dataset.tab === tab);
    });

    if (tab === 'advanced') {
        updateJsonEditor();
    }

    document.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab } }));
}

export function switchSubTab(subTab) {
    state.currentSubTab = subTab;

    document.querySelectorAll('.sub-tab').forEach(btn => {
        btn.classList.remove('active');
    });
    const button = document.getElementById(subTab + '-tab-btn');
    if (button) {
        button.classList.add('active');
    }

    document.querySelectorAll('.sub-tab-content').forEach(content => {
        content.classList.remove('active');
    });
    const form = document.getElementById(subTab + '-form');
    if (form) {
        form.classList.add('active');
    }

    updateJsonEditor();
}

export function toggleSection(sectionId, eventOrElement) {
    const content = document.getElementById(sectionId);
    if (!content) {
        return;
    }

    let header = null;

    if (eventOrElement) {
        if (eventOrElement.currentTarget instanceof HTMLElement) {
            header = eventOrElement.currentTarget;
        } else if (eventOrElement.target instanceof Element) {
            header = eventOrElement.target.closest('.section-header');
        } else if (eventOrElement instanceof HTMLElement) {
            header = eventOrElement;
        }
    }

    if (!header) {
        const previous = content.previousElementSibling;
        if (previous instanceof HTMLElement && previous.classList.contains('section-header')) {
            header = previous;
        }
    }

    if (!header && content.parentElement) {
        const candidate = content.parentElement.querySelector('.section-header');
        if (candidate instanceof HTMLElement) {
            header = candidate;
        }
    }

    if (!header) {
        const headers = document.querySelectorAll('.section-header');
        for (const element of headers) {
            const handler = element.getAttribute('onclick') || '';
            if (handler.includes(`toggleSection('${sectionId}'`) || handler.includes(`toggleSection("${sectionId}"`)) {
                header = element;
                break;
            }
        }
    }

    const icon = header ? header.querySelector('.expand-icon') : null;

    if (content.classList.contains('expanded')) {
        content.classList.remove('expanded');
        if (header) {
            header.classList.remove('expanded');
        }
        if (icon) {
            icon.classList.remove('rotated');
        }
    } else {
        content.classList.add('expanded');
        if (header) {
            header.classList.add('expanded');
        }
        if (icon) {
            icon.classList.add('rotated');
        }
    }
}
