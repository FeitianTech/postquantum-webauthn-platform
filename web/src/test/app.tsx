// The whole app as the page renders it, at a URL.
//
// The shell loads its sections, the Analyze Browser panel and the credential
// dialog with import(), and each test file starts with none of them loaded:
// the first test to render the shell paid for fetching and running every chunk
// as well as for the render, under the Cloud Build gate's load as much again
// (a certificate page test, 2026-10-03: 39 s, against 26 s with them imported
// first). They are imported here instead, while the file is collected, before
// any test and outside every timeout; the shell's own import() then finds them
// loaded. Its first render is still the placeholder.
import '@/components/advanced/AdvancedSection';
import '@/components/analyze-browser/AnalyzeBrowserDialog';
import '@/components/codec/CodecSection';
import '@/components/credentials/CredentialDetailDialog';
import '@/components/mds/MdsSection';
import '@/logic/browser/report.js';

import { AppShell } from '@/components/shell/AppShell';
import { ToastProvider } from '@/components/ui/Toast';

import { renderPage } from './page';

/** Renders the page at `hash` ('' for the default section). */
export function renderApp(hash = '') {
  window.history.replaceState({ fromNext: true }, '', `/${hash}`);
  return renderPage(
    <ToastProvider>
      <AppShell />
    </ToastProvider>,
  );
}
