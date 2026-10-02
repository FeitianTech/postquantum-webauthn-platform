import { type ComponentProps, useEffect, useState } from 'react';

import { lazyModule, useLazyModule, whenInteractive } from '@/lib/lazyModule';

// The credential details dialog (its levels, the registration's views, the
// certificates' summaries) loads as a chunk of its own: the first time a
// credential's details are asked for, or once the first view is interactive.
const DIALOG = lazyModule(() => import(/* webpackChunkName: "credential-details" */ './CredentialDetailDialog'));

type Props = ComponentProps<typeof import('./CredentialDetailDialog').CredentialDetailDialog>;

export function CredentialDetails(props: Props) {
  const [interactive, setInteractive] = useState(false);
  useEffect(() => whenInteractive(() => setInteractive(true)), []);
  const { module } = useLazyModule(DIALOG, interactive || props.route.path[0] === 'credential');
  return module ? <module.CredentialDetailDialog {...props} /> : null;
}
