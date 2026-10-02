import type { AppProps } from 'next/app';
import localFont from 'next/font/local';
import Head from 'next/head';

import '@/styles/globals.css';

// The geist package's own faces and settings (geist/dist/sans.js and mono.js),
// called here so the page preloads only what its first view sets: Geist. Geist
// Mono, for data, is fetched when mono text first shows.
const GeistSans = localFont({
  src: '../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2',
  variable: '--font-geist-sans',
  weight: '100 900',
});

const GeistMono = localFont({
  src: '../../node_modules/geist/dist/fonts/geist-mono/GeistMono-Variable.woff2',
  variable: '--font-geist-mono',
  adjustFontFallback: false,
  fallback: [
    'ui-monospace',
    'SFMono-Regular',
    'Roboto Mono',
    'Menlo',
    'Monaco',
    'Liberation Mono',
    'DejaVu Sans Mono',
    'Courier New',
    'monospace',
  ],
  weight: '100 900',
  preload: false,
});

export default function App({ Component, pageProps }: AppProps) {
  return (
    <>
      <Head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>FIDO2/WebAuthn PQC Testing Platform and Developer Tools</title>
      </Head>
      {/* The font variables sit on a wrapper that also holds the overlay layer,
          so dialogs rendered through a portal inherit them. */}
      <div className={`${GeistSans.variable} ${GeistMono.variable} font-sans`}>
        <div id="app-root">
          <Component {...pageProps} />
        </div>
        <div id="overlay-root" />
      </div>
    </>
  );
}
