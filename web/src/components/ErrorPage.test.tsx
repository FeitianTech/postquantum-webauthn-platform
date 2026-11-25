import { render, screen } from '@testing-library/react';
import type { NextPageContext } from 'next';

import AppError from '@/pages/_error';

import { ErrorPage } from './ErrorPage';

// _error: what the browser shows when a page throws.
function renderAppError(context: Partial<NextPageContext>) {
  render(<AppError {...AppError.getInitialProps(context as NextPageContext)} />);
}

describe('ErrorPage', () => {
  it('says what went wrong and links to the home page', () => {
    render(<ErrorPage title="Page not found" message="There is no page at this address." />);

    expect(screen.getByRole('heading', { level: 1, name: 'Page not found' })).toBeInTheDocument();
    expect(screen.getByText('There is no page at this address.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to the home page' })).toHaveAttribute('href', '/');
    expect(screen.getAllByRole('link')).toHaveLength(1);
  });

  it('says an error when there is no status code, as in the browser', () => {
    renderAppError({});

    expect(screen.getByRole('heading', { level: 1, name: 'Something went wrong' })).toBeInTheDocument();
    expect(screen.getByText('The page could not be shown.')).toBeInTheDocument();
  });

  it('says not found for a 404', () => {
    renderAppError({ res: { statusCode: 404 } as NextPageContext['res'] });

    expect(screen.getByRole('heading', { level: 1, name: 'Page not found' })).toBeInTheDocument();
  });
});
