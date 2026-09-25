import { type Ref, useRef, useState } from 'react';

import { Button, buttonClassName } from '@/components/ui/Button';
import { GitHubIcon, MenuIcon } from '@/components/ui/icons';
import { Sheet } from '@/components/ui/Overlay';
import { SegmentedControl } from '@/components/ui/SegmentedControl';
import { cx } from '@/lib/cx';
import { SECTIONS, SECTION_OPTIONS, type SectionId } from '@/lib/sections';

import { NAV_ID } from './SectionPanel';

export const GITHUB_URL = 'https://github.com/rainzhang05/python-fido2-webauthn-test';
export const ANALYZE_PANEL_ID = 'analyze-browser-panel';

type HeaderProps = {
  section: SectionId;
  onSection: (section: SectionId) => void;
  /** Opens the Analyze Browser panel; focus returns to `from` when it closes. */
  onAnalyze: (from: HTMLElement | null) => void;
  analyzing: boolean;
  analyzeButtonRef?: Ref<HTMLButtonElement>;
};

// The top bar: the title, the four sections (a segmented control whose highlight
// slides), Analyze Browser and GitHub. On a wide screen it is one row; between
// 900 and 1280 px the sections take a second row; on a phone they move into a
// menu sheet with Analyze Browser and GitHub.
export function Header({ section, onSection, onAnalyze, analyzing, analyzeButtonRef }: HeaderProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-white/85 backdrop-blur-xl backdrop-saturate-150">
      <div className="mx-auto flex min-h-(--header-height) w-full max-w-page flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5 sm:px-6 lg:px-8">
        <h1 className="min-w-0 flex-1 text-title-sm font-semibold text-ink wide:flex-none">
          FIDO2/WebAuthn PQC Developer Tools
        </h1>
        <nav
          aria-label="Section navigation"
          className="order-last hidden w-full min-w-0 overflow-x-auto menu:flex wide:order-none wide:w-auto wide:flex-1 wide:justify-center"
        >
          <SegmentedControl label="Sections" idBase={NAV_ID} options={SECTION_OPTIONS} value={section} onChange={onSection} />
        </nav>
        <div className="ml-auto flex shrink-0 items-center gap-2">
          {/* On a phone Analyze Browser is in the menu sheet. The wrapper hides
              it: a class on the button itself would lose to its inline-flex. */}
          <span className="hidden menu:inline-flex">
            <Button
              ref={analyzeButtonRef}
              variant="secondary"
              size="sm"
              aria-haspopup="dialog"
              aria-controls={ANALYZE_PANEL_ID}
              disabled={analyzing}
              onClick={(event) => onAnalyze(event.currentTarget)}
            >
              Analyze Browser
            </Button>
          </span>
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="View project on GitHub"
            title="View project on GitHub"
            className={cx(
              'hidden size-9 items-center justify-center rounded-full text-ink transition-colors menu:inline-flex',
              'hover-or-demo:bg-accent-tint hover-or-demo:text-accent-ink',
            )}
          >
            <GitHubIcon />
          </a>
          <Button
            ref={menuButton}
            variant="secondary"
            size="sm"
            icon={<MenuIcon />}
            className="menu:hidden"
            aria-haspopup="dialog"
            aria-expanded={menuOpen}
            aria-controls="menu-sheet"
            onClick={() => setMenuOpen(true)}
          >
            Menu
          </Button>
        </div>
      </div>
      <Sheet id="menu-sheet" open={menuOpen} onClose={() => setMenuOpen(false)} labelledBy="menu-sheet-title">
        <div className="flex items-center justify-between border-b border-line py-2.5 pr-2.5 pl-5">
          <h2 id="menu-sheet-title" className="text-title-sm font-semibold text-ink">
            Menu
          </h2>
          <Button variant="quiet" size="sm" onClick={() => setMenuOpen(false)}>
            Close
          </Button>
        </div>
        <div className="overflow-y-auto p-2">
          <ul aria-label="Sections" className="flex flex-col gap-0.5">
            {SECTIONS.map((option) => (
              <li key={option.id}>
                <button
                  type="button"
                  aria-current={option.id === section ? 'true' : undefined}
                  onClick={() => {
                    onSection(option.id);
                    setMenuOpen(false);
                  }}
                  className={cx(
                    'flex h-11 w-full items-center rounded-md px-3.5 text-left text-body-lg text-ink transition-colors',
                    'hover-or-demo:bg-accent-tint aria-[current]:bg-accent-tint aria-[current]:font-semibold aria-[current]:text-accent-ink',
                  )}
                >
                  {option.label}
                </button>
              </li>
            ))}
          </ul>
          <div className="mt-2 flex flex-col gap-2 border-t border-line p-2 pt-4">
            <Button
              variant="secondary"
              aria-haspopup="dialog"
              aria-controls={ANALYZE_PANEL_ID}
              disabled={analyzing}
              onClick={() => {
                setMenuOpen(false);
                onAnalyze(menuButton.current);
              }}
            >
              Analyze Browser
            </Button>
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={buttonClassName({ variant: 'quiet' })}
            >
              <GitHubIcon />
              View project on GitHub
            </a>
          </div>
        </div>
      </Sheet>
    </header>
  );
}
