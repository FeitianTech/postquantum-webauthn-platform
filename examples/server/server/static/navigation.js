import { state } from './state.js';
import { updateJsonEditor } from './json-editor.js';

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

export function toggleSection(sectionId, event) {
    const header = event?.currentTarget || event;
    const content = document.getElementById(sectionId);
    if (!header || !content) {
        return;
    }
    const icon = header.querySelector('.expand-icon');

    if (content.classList.contains('expanded')) {
        content.classList.remove('expanded');
        header.classList.remove('expanded');
        if (icon) {
            icon.classList.remove('rotated');
        }
    } else {
        content.classList.add('expanded');
        header.classList.add('expanded');
        if (icon) {
            icon.classList.add('rotated');
        }
    }
}
