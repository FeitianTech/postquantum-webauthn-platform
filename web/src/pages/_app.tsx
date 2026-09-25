import { GeistMono } from 'geist/font/mono';
import { GeistSans } from 'geist/font/sans';
import type { AppProps } from 'next/app';
import Head from 'next/head';

import '@/styles/globals.css';

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
