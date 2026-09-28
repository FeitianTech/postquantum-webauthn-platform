import { useState } from 'react';

import { AdvancedSection } from '@/components/advanced/AdvancedSection';
import { AnalyzeBrowserDialog, type CopyResult } from '@/components/analyze-browser/AnalyzeBrowserDialog';
import { CodecSection } from '@/components/codec/CodecSection';
import { SavedCredentialsProvider } from '@/components/credentials/useSavedCredentials';
import { MdsSection } from '@/components/mds/MdsSection';
import { useBrowserAnalysis } from '@/components/analyze-browser/useBrowserAnalysis';
import { SimpleSection } from '@/components/simple/SimpleSection';
import { SECTIONS, type SectionId } from '@/lib/sections';
import { CLOSED_ROUTE, SectionNavigationProvider, useSection } from '@/lib/useSection';

import { Footer } from './Footer';
import { Header } from './Header';

// The page: the header, the chosen section, the footer, and the Analyze
// Browser panel, which floats above everything. The saved credentials are
// the sections' shared list. A section opens something in
// another through useSectionNavigation().
export function AppShell() {
  const [section, setSection, route, go] = useSection();
  const browser = useBrowserAnalysis();
  const [copy, setCopy] = useState<CopyResult | null>(null);
  // What is open belongs to the section shown; the others see nothing open.
  const routeOf = (id: SectionId) => (id === section ? route : CLOSED_ROUTE);

  return (
    <SectionNavigationProvider value={go}>
      <div className="flex min-h-dvh flex-col">
        <Header section={section} onSection={setSection} onAnalyze={browser.request} analyzing={browser.running} />
        <main className="mx-auto w-full max-w-page flex-1 px-4 pt-10 pb-16 sm:px-6 sm:pt-14 lg:px-8">
          <SavedCredentialsProvider>
            {SECTIONS.map((option) =>
              option.id === 'simple' ? (
                <SimpleSection key={option.id} active={option.id === section} route={routeOf('simple')} />
              ) : option.id === 'advanced' ? (
                <AdvancedSection key={option.id} active={option.id === section} route={routeOf('advanced')} />
              ) : option.id === 'codec' ? (
                <CodecSection key={option.id} active={option.id === section} />
              ) : (
                <MdsSection key={option.id} active={option.id === section} route={routeOf('mds')} />
              ),
            )}
          </SavedCredentialsProvider>
        </main>
        <Footer />
        <AnalyzeBrowserDialog
          open={browser.open}
          onClose={browser.close}
          analysis={browser.analysis}
          returnFocusTo={browser.returnFocusTo}
          copy={copy}
          onCopied={setCopy}
        />
      </div>
    </SectionNavigationProvider>
  );
}
