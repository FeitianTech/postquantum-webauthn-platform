import { render, screen, within } from '@testing-library/react';

import { Card, CardHeader } from './Card';

describe('Card', () => {
  it('is a white section with a hairline, a title, a description and actions', () => {
    render(
      <Card aria-labelledby="card-title">
        <CardHeader titleId="card-title" title="Saved Credentials" description="Stored in this browser" actions={<button type="button">Clear All</button>} />
        <p>Body</p>
      </Card>,
    );
    const card = screen.getByRole('region', { name: 'Saved Credentials' });
    expect(card.className).toContain('bg-surface');
    expect(card.className).toContain('border-line');
    expect(card.className).not.toMatch(/shadow/);
    expect(within(card).getByRole('heading', { level: 3 })).toHaveTextContent('Saved Credentials');
    expect(within(card).getByText('Stored in this browser')).toBeInTheDocument();
    expect(within(card).getByRole('button', { name: 'Clear All' })).toBeInTheDocument();
  });

  it('can be another element with a level-two title and no extras', () => {
    const { container } = render(
      <Card as="div">
        <CardHeader title="Plain" titleAs="h2" />
      </Card>,
    );
    expect(container.firstElementChild?.tagName).toBe('DIV');
    expect(screen.getByRole('heading', { level: 2, name: 'Plain' })).toBeInTheDocument();
  });
});
