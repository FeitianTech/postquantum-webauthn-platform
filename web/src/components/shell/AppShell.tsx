import { useState } from 'react';

import { AnalyzeBrowserDialog, type CopyResult } from '@/components/analyze-browser/AnalyzeBrowserDialog';
import { useBrowserAnalysis } from '@/components/analyze-browser/useBrowserAnalysis';
import { SECTIONS } from '@/lib/sections';
import { useSection } from '@/lib/useSection';

import { Footer } from './Footer';
import { Header } from './Header';
import { SectionPanel } from './SectionPanel';

// The page: the header, the chosen section, the footer, and the Analyze
// Browser panel, which floats above everything.
export function AppShell() {
  const [section, setSection] = useSection();
  const browser = useBrowserAnalysis();
  const [copy, setCopy] = useState<CopyResult | null>(null);

  return (
    <div className="flex min-h-dvh flex-col">
      <Header section={section} onSection={setSection} onAnalyze={browser.request} analyzing={browser.running} />
      <main className="mx-auto w-full max-w-page flex-1 px-4 pt-10 pb-16 sm:px-6 sm:pt-14 lg:px-8">
        {SECTIONS.map((option) => (
          <SectionPanel key={option.id} id={option.id} active={option.id === section} />
        ))}
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
  );
}
