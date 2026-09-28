type ErrorPageProps = {
  title: string;
  message: string;
};

// Next's own error pages are styled with style attributes, which the CSP
// refuses; the export ships these instead. The link is plain: following
// next/link makes Next's router add page scripts (which the Trusted Types
// policy reports) and leaves the browser's Back on the app with this page's URL.
export function ErrorPage({ title, message }: ErrorPageProps) {
  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-4 px-4">
      <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
      <p>{message}</p>
      <p className="flex flex-wrap gap-4">
        <a href="/beta">Go to the new interface</a>
      </p>
    </main>
  );
}
