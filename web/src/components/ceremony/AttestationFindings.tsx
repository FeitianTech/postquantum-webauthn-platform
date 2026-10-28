import { useEffect, useState } from 'react';

import { lazyModule, useLazyModule, whenInteractive } from '@/lib/lazyModule';
import { type AttestationFindings as Findings, hasFindings } from '@/logic/shared/registration-findings.js';

// The findings list, with the sentences of every finding in two languages, loads
// as a chunk of its own: ahead once the first view is interactive, and at once
// when there are findings to show. Until it has arrived, and without findings,
// nothing shows; kept in the page, so the chunk is fetched ahead.
const LIST = lazyModule(() => import(/* webpackChunkName: "attestation-findings" */ './FindingsList'));

type Props = {
  findings: Findings | null;
  /** Whether the list gives its own title (the details' section has one). */
  titled?: boolean;
  /** Its place in its parent, when it shows. */
  className?: string;
};

export function AttestationFindings({ findings, titled = true, className }: Props) {
  const [interactive, setInteractive] = useState(false);
  useEffect(() => whenInteractive(() => setInteractive(true)), []);
  const shown = hasFindings(findings) ? findings : null;
  const { module } = useLazyModule(LIST, interactive, shown !== null);
  return module && shown ? <module.FindingsList findings={shown} titled={titled} className={className} /> : null;
}
