import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { FindingsList } from './FindingsList';

// A registration's attestation findings in words (shared/attestation-findings.js).
const items = () => Array.from(document.querySelectorAll<HTMLElement>('[data-finding]'));
const shownText = (item: HTMLElement) => item.querySelector('p')!.textContent;

describe('the attestation findings', () => {
  it('list the errors first, each with its word and mark, then its sentence', () => {
    render(
      <FindingsList
        findings={{ errors: ['metadata_entry_missing'], warnings: ['metadata_not_available'] }}
        titled
      />,
    );

    expect(screen.getByText('Verification findings')).toBeVisible();
    expect(items().map((item) => [item.dataset.severity, item.dataset.finding])).toEqual([
      ['error', 'metadata_entry_missing'],
      ['warning', 'metadata_not_available'],
    ]);
    const [error, warning] = items();
    expect(within(error).getByText('Error')).toBeVisible();
    expect(error.textContent).toContain('✕');
    expect(within(error).getByText('The metadata has no entry for this authenticator')).toBeVisible();
    expect(within(warning).getByText('Warning')).toBeVisible();
    expect(within(warning).getByText('No FIDO metadata was available to check the authenticator against')).toBeVisible();
  });

  it('gives the server\'s reason after the sentence, and a finding it does not know as sent', () => {
    render(
      <FindingsList
        findings={{ errors: ['No root found for Authenticator'], warnings: ['certificate_out_of_validity: CN=Leaf'] }}
        titled
      />,
    );
    const [unknown, reasoned] = items();
    expect(shownText(unknown)).toBe('No root found for Authenticator');
    expect(unknown.querySelector('[lang]')).toBeNull();
    expect(within(reasoned).getByText('A certificate in the attestation\'s chain is outside its validity period: CN=Leaf')).toBeVisible();
  });

  it('switches its sentences between English and 中文, the other language kept hidden', async () => {
    render(<FindingsList findings={{ errors: ['challenge_mismatch'], warnings: [] }} titled />);
    const english = screen.getByText('The client data\'s challenge is not the one this server issued');
    const chinese = screen.getByText('客户端数据中的挑战（challenge）不是本服务器签发的挑战');
    expect(chinese).toHaveAttribute('lang', 'zh');
    expect(chinese).not.toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: 'ENG, show in Chinese' }));
    expect(chinese).toBeVisible();
    expect(english).not.toBeVisible();
    expect(screen.getByText('Error')).toBeVisible();

    await userEvent.click(screen.getByRole('button', { name: '中, show in English' }));
    expect(english).toBeVisible();
  });

  it('leaves the title to its section in a credential\'s details, and takes its place from its parent', () => {
    render(<FindingsList findings={{ errors: [], warnings: ['trust_path_missing'] }} titled={false} className="mt-3" />);
    expect(screen.queryByText('Verification findings')).toBeNull();
    expect(document.querySelector('[data-findings]')!.className).toContain('mt-3');
    expect(screen.getByRole('button', { name: 'ENG, show in Chinese' })).toBeVisible();
  });
});
