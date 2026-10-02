import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SectionPlaceholder } from './SectionPlaceholder';

describe('a section\'s panel while its chunk loads', () => {
  it('is the panel the section\'s tab controls, empty and busy', () => {
    render(<SectionPlaceholder id="codec" active failed={false} onRetry={() => {}} />);
    const panel = screen.getByRole('tabpanel');

    expect(panel).toHaveAttribute('id', 'nav-panel-codec');
    expect(panel).toHaveAttribute('aria-labelledby', 'nav-tab-codec');
    expect(panel).toHaveAttribute('aria-busy', 'true');
    expect(panel).toBeEmptyDOMElement();
  });

  it('is hidden while another section is shown', () => {
    render(<SectionPlaceholder id="mds" active={false} failed={false} onRetry={() => {}} />);

    expect(screen.getByRole('tabpanel', { hidden: true })).not.toBeVisible();
  });

  it('says the chunk could not be loaded, and loads it again on Try again', async () => {
    const onRetry = vi.fn();
    render(<SectionPlaceholder id="advanced" active failed onRetry={onRetry} />);

    expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-busy', 'false');
    expect(screen.getByRole('alert')).toHaveTextContent('This section could not be loaded. Check the connection, then try again.');
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
