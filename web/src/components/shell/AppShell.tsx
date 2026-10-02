import { useEffect, useState } from 'react';

import type { CopyResult } from '@/components/analyze-browser/AnalyzeBrowserDialog';
import { SavedCredentialsProvider } from '@/components/credentials/useSavedCredentials';
import { useBrowserAnalysis } from '@/components/analyze-browser/useBrowserAnalysis';
import { SimpleSection } from '@/components/simple/SimpleSection';
import { type LazyModule, lazyModule, useLazyModule, whenInteractive } from '@/lib/lazyModule';
import { SECTIONS, type SectionId } from '@/lib/sections';
import { useIsomorphicLayoutEffect } from '@/lib/useIsomorphicLayoutEffect';
import { CLOSED_ROUTE, SectionNavigationProvider, useSection } from '@/lib/useSection';

import { Footer } from './Footer';
import { Header } from './Header';
import { SectionPlaceholder } from './SectionPlaceholder';

// The sections that load as chunks of their own: the page's own chunk holds
// the shell and Simple, the default section, so Register works as soon as the
// page does. The section the URL names loads at once; until it arrives its panel
// is a placeholder. The others load once the first view is interactive and
// wait, hidden, so choosing one shows it at once.
const ADVANCED = lazyModule(() => import(/* webpackChunkName: "section-advanced" */ '@/components/advanced/AdvancedSection'));
const CODEC = lazyModule(() => import(/* webpackChunkName: "section-codec" */ '@/components/codec/CodecSection'));
const MDS = lazyModule(() => import(/* webpackChunkName: "section-mds" */ '@/components/mds/MdsSection'));
// The Analyze Browser panel, in the chunk of the questions it shows the answers to.
const ANALYZE_PANEL = lazyModule(() => import(/* webpackChunkName: "analyze-browser" */ '@/components/analyze-browser/AnalyzeBrowserDialog'));
const LAZY_SECTIONS: Partial<Record<SectionId, LazyModule<unknown>>> = { advanced: ADVANCED, codec: CODEC, mds: MDS };

// The page: the header, the chosen section, the footer, and the Analyze
// Browser panel, which floats above everything. The saved credentials are
// the sections' shared list. A section opens something in
// another through useSectionNavigation().
export function AppShell() {
  const [section, setSection, route, go] = useSection();
  const [interactive, setInteractive] = useState(false);
  useEffect(() => whenInteractive(() => setInteractive(true)), []);
  const advanced = useLazyModule(ADVANCED, interactive || section === 'advanced');
  const codec = useLazyModule(CODEC, interactive || section === 'codec');
  const mds = useLazyModule(MDS, interactive || section === 'mds');
  // Ask for the shown section's chunk before the frame is painted.
  useIsomorphicLayoutEffect(() => {
    if (section) void LAZY_SECTIONS[section]?.load().catch(() => {});
  }, [section]);
  const browser = useBrowserAnalysis();
  const panel = useLazyModule(ANALYZE_PANEL, interactive || browser.running || browser.open);
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
                advanced.module ? (
                  <advanced.module.AdvancedSection
                    key={option.id}
                    active={option.id === section}
                    route={routeOf('advanced')}
                  />
                ) : (
                  <SectionPlaceholder key={option.id} id="advanced" active={option.id === section} failed={advanced.failed} onRetry={advanced.retry} />
                )
              ) : option.id === 'codec' ? (
                codec.module ? (
                  <codec.module.CodecSection key={option.id} active={option.id === section} />
                ) : (
                  <SectionPlaceholder key={option.id} id="codec" active={option.id === section} failed={codec.failed} onRetry={codec.retry} />
                )
              ) : mds.module ? (
                <mds.module.MdsSection key={option.id} active={option.id === section} route={routeOf('mds')} />
              ) : (
                <SectionPlaceholder key={option.id} id="mds" active={option.id === section} failed={mds.failed} onRetry={mds.retry} />
              ),
            )}
          </SavedCredentialsProvider>
        </main>
        <Footer />
        {panel.module ? (
          <panel.module.AnalyzeBrowserDialog
            open={browser.open}
            onClose={browser.close}
            analysis={browser.analysis}
            returnFocusTo={browser.returnFocusTo}
            copy={copy}
            onCopied={setCopy}
          />
        ) : null}
      </div>
    </SectionNavigationProvider>
  );
}
