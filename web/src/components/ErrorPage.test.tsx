import { render, screen } from '@testing-library/react';

import { ErrorPage } from './ErrorPage';

describe('ErrorPage', () => {
  it('says what went wrong and links to the home page', () => {
    render(<ErrorPage title="Page not found" message="There is no page at this address." />);

    expect(screen.getByRole('heading', { level: 1, name: 'Page not found' })).toBeInTheDocument();
    expect(screen.getByText('There is no page at this address.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to the home page' })).toHaveAttribute('href', '/');
    expect(screen.getAllByRole('link')).toHaveLength(1);
  });
});
