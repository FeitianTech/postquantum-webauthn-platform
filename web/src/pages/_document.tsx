import { Head, Html, Main, NextScript } from 'next/document';

export default function Document() {
  return (
    <Html lang="en">
      <Head>
        {/* Unlisted while the migration runs (docs/UI_MIGRATION.md). */}
        <meta name="robots" content="noindex" />
        <meta name="color-scheme" content="light" />
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
