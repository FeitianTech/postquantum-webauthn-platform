import Link from 'next/link';

type ErrorPageProps = {
  title: string;
  message: string;
};

// Next's own error pages are styled with style attributes, which the CSP
// refuses; the export ships these instead.
export function ErrorPage({ title, message }: ErrorPageProps) {
  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-4 px-4">
      <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
      <p>{message}</p>
      <p className="flex flex-wrap gap-4">
        <Link href="/">Go to the new interface</Link>
        {/* A plain link: next/link would add the /beta base path. */}
        <a href="/">Open the current interface</a>
      </p>
    </main>
  );
}
