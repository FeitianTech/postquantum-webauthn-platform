import type { NextPageContext } from 'next';

import { ErrorPage } from '@/components/ErrorPage';

type Props = { statusCode: number };

// Rendered in the browser when a page throws, in place of Next's default, whose
// inline styles the CSP would block.
function AppError({ statusCode }: Props) {
  return statusCode === 404 ? (
    <ErrorPage title="Page not found" message="There is no page at this address." />
  ) : (
    <ErrorPage title="Something went wrong" message="The page could not be shown." />
  );
}

AppError.getInitialProps = ({ res, err }: NextPageContext): Props => ({
  statusCode: res?.statusCode ?? err?.statusCode ?? 404,
});

export default AppError;
