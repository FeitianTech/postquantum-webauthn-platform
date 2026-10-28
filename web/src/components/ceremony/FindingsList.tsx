import { useState } from 'react';

import { StatusChip } from '@/components/ui/Badge';
import { type Language, LanguageToggle } from '@/components/ui/LanguageToggle';
import { cx } from '@/lib/cx';
import { describeFindings } from '@/logic/shared/attestation-findings.js';
import { type AttestationFindings, FINDINGS_TITLE } from '@/logic/shared/registration-findings.js';

type Props = { findings: AttestationFindings; titled: boolean; className?: string };

// A registration's attestation findings in words, the errors first: each with
// its word and mark, then its sentence in English or 中文, the server's reason
// after it. The toggle switches the sentences; the other language stays in the
// page, hidden. A finding the sentences do not know reads as the server sent it.
// Titled in the result panel; in a credential's details its section is.
export function FindingsList({ findings, titled, className }: Props) {
  const [language, setLanguage] = useState<Language>('en');
  const items = describeFindings(findings);
  return (
    <div data-findings="" className={cx('flex flex-col gap-2', className)}>
      <div className="flex items-center justify-between gap-3">
        {titled ? <p className="text-label font-semibold text-ink">{FINDINGS_TITLE}</p> : <span />}
        <LanguageToggle language={language} onToggle={() => setLanguage(language === 'en' ? 'zh' : 'en')} />
      </div>
      <ul className="flex flex-col gap-2">
        {items.map((item, index) => (
          <li key={index} className="flex items-start gap-2" data-finding={item.code} data-severity={item.severity}>
            <StatusChip tone={item.severity === 'error' ? 'danger' : 'warning'} className="mt-px">
              {item.label}
            </StatusChip>
            <p className="min-w-0 pt-0.5 text-body text-ink wrap-anywhere">
              {item.known ? (
                <>
                  <span lang="en" hidden={language !== 'en'}>
                    {item.en}
                  </span>
                  <span lang="zh" hidden={language !== 'zh'}>
                    {item.zh}
                  </span>
                </>
              ) : (
                item.en
              )}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
