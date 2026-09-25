import { ErrorPage } from '@/components/ErrorPage';

export default function NotFound() {
  return <ErrorPage title="Page not found" message="There is no page at this address." />;
}
