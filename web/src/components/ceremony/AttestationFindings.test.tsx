import { render, screen } from '@testing-library/react';

import { AttestationFindings } from './AttestationFindings';

// The findings list's loader: its chunk (the list and the findings' sentences)
// is fetched ahead, and shown once it has arrived and there are findings.
describe('the attestation findings\' loader', () => {
  it('shows the list once its chunk has arrived', async () => {
    render(<AttestationFindings findings={{ errors: ['origin_mismatch'], warnings: [] }} className="mt-3" />);
    expect(await screen.findByText('The client data\'s origin is not the origin this server expects')).toBeVisible();
    expect(screen.getByText('Verification findings')).toBeVisible();
    expect(document.querySelector('[data-findings]')!.className).toContain('mt-3');
  });

  it('leaves the title to the section around it when asked', async () => {
    render(<AttestationFindings findings={{ errors: [], warnings: ['metadata_not_available'] }} titled={false} />);
    expect(await screen.findByText('No FIDO metadata was available to check the authenticator against')).toBeVisible();
    expect(screen.queryByText('Verification findings')).toBeNull();
  });

  it('shows nothing without findings', () => {
    const { container, rerender } = render(<AttestationFindings findings={null} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<AttestationFindings findings={{ errors: [], warnings: [] }} />);
    expect(container).toBeEmptyDOMElement();
  });
});
