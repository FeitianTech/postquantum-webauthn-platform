import { SECTIONS } from '@/lib/sections';
import { useSection } from '@/lib/useSection';

import { Footer } from './Footer';
import { Header } from './Header';
import { SectionPanel } from './SectionPanel';

// The page: the header, the chosen section and the footer.
export function AppShell() {
  const [section, setSection] = useSection();

  return (
    <div className="flex min-h-dvh flex-col">
      <Header section={section} onSection={setSection} onAnalyze={() => {}} analyzing={false} />
      <main className="mx-auto w-full max-w-page flex-1 px-4 pt-10 pb-16 sm:px-6 sm:pt-14 lg:px-8">
        {SECTIONS.map((option) => (
          <SectionPanel key={option.id} id={option.id} active={option.id === section} />
        ))}
      </main>
      <Footer />
    </div>
  );
}
