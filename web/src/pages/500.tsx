import { ErrorPage } from '@/components/ErrorPage';

export default function ServerError() {
  return <ErrorPage title="Something went wrong" message="The page could not be shown." />;
}
