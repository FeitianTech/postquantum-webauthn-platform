import { describe, expect, it } from 'vitest';

import { renderPageBody } from '../../page-template.js';

describe('header', () => {
  it('links the GitHub icon to the repository itself, not through a redirect', () => {
    document.body.innerHTML = renderPageBody().markup;
    const link = document.querySelector('a[aria-label="View project on GitHub"]');
    expect(link?.getAttribute('href')).toBe('https://github.com/FeitianTech/postquantum-webauthn-platform');
    expect(link?.getAttribute('target')).toBe('_blank');
    expect(link?.getAttribute('rel')).toBe('noopener noreferrer');
  });
});
