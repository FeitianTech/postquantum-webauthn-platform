import type { AppProps } from 'next/app';
import localFont from 'next/font/local';
import Head from 'next/head';

import '@/styles/globals.css';

// Geist in two faces of one family, cut from the geist package's file by
// tools/subset_geist.sh: the Latin face the first view sets, preloaded, and the
// rest, fetched only for a character in its range. Geist Mono, for data, is
// the package's own file, fetched when mono text first shows.
const GeistSans = localFont({
  src: '../fonts/Geist-Latin.woff2',
  variable: '--font-geist-sans',
  weight: '100 900',
  declarations: [
    { prop: 'font-family', value: 'Geist' },
    {
      prop: 'unicode-range',
      value:
        'U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2190-2199, U+2212, U+2215, U+FEFF, U+FFFD',
    },
  ],
});

const GeistSansRest = localFont({
  src: '../fonts/Geist-Rest.woff2',
  variable: '--font-geist-sans-rest',
  weight: '100 900',
  declarations: [
    { prop: 'font-family', value: 'Geist' },
    {
      prop: 'unicode-range',
      value:
        'U+0100-0113, U+0116-012B, U+012E-0130, U+0132-0137, U+0139-013E, U+0141-0148, U+014A-014D, U+0150-0151, U+0154-017E, U+018F, U+0192, U+01A0-01A1, U+01AF-01B0, U+01CD-01CE, U+01E4-01E9, U+0218-021B, U+0237, U+0259, U+02B9, U+02C7-02C8, U+02D8-02D9, U+02DB, U+02DD, U+0300-0303, U+0306-0307, U+0309-030C, U+0312, U+031B, U+0323, U+0326-0328, U+0335-0338, U+039B, U+03A9, U+03BB-03BC, U+03C0, U+03C9, U+0400-045F, U+0462-0463, U+046A-046B, U+0472-0475, U+0490-0493, U+0496-0497, U+049A-049B, U+04A2-04A3, U+04AE-04B3, U+04B6-04B7, U+04BA-04BB, U+04C0, U+04CF, U+04D8-04D9, U+04E2-04E3, U+04E8-04E9, U+04EE-04EF, U+0E3F, U+1E20-1E21, U+1E80-1E85, U+1E9E, U+1EA0-1EF9, U+2070, U+2074-2079, U+2080-2089, U+20AA, U+20B1, U+20B4, U+20B9, U+20BD, U+2116-2117, U+2153-2155, U+215B-215E, U+219D, U+21A9-21AA, U+21B0-21B1, U+21B3-21B5, U+21E4-21E5, U+21E7, U+2202, U+2206, U+220F, U+2211, U+221A, U+221E, U+222B, U+2236, U+2248, U+2260, U+2264-2265, U+2460-2468, U+24EA, U+24FF, U+25B2-25B3, U+25B6-25B7, U+25BC-25BD, U+25C0-25C1, U+25CA-25CC, U+25CF, U+2639-263A, U+2776-277E, U+3003, U+301C, U+A78B-A78C, U+F8FF, U+FB01-FB02',
    },
  ],
  adjustFontFallback: false,
  preload: false,
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
      <div className={`${GeistSans.variable} ${GeistSansRest.variable} ${GeistMono.variable} font-sans`}>
        <div id="app-root">
          <Component {...pageProps} />
        </div>
        <div id="overlay-root" />
      </div>
    </>
  );
}
