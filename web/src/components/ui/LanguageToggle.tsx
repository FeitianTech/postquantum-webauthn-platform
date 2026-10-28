import { cx } from '@/lib/cx';

export type Language = 'en' | 'zh';

type LanguageToggleProps = {
  language: Language;
  onToggle: () => void;
  /** Where it sits, as its parent places it. */
  className?: string;
};

// The switch between English and 中文 that text in both languages carries: it
// reads "ENG" or "中", the language shown, and its name says which way it switches.
export function LanguageToggle({ language, onToggle, className }: LanguageToggleProps) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-label={language === 'en' ? 'ENG, show in Chinese' : '中, show in English'}
      className={cx(
        'h-6 rounded-full border border-line-strong bg-surface px-2 text-caption font-semibold',
        'text-ink-muted transition-colors hover:border-line-hover hover:text-ink',
        className,
      )}
    >
      {language === 'en' ? 'ENG' : '中'}
    </button>
  );
}
