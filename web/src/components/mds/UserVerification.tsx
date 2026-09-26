import type { Combination } from './entryModel';

// The user-verification section: each combination under its title, its methods as
// published, and under a method what it says of its accuracy (the code accuracy
// the current page shows, and the biometric and pattern accuracy it leaves out).
// A list with hairlines, not cards.
export function UserVerification({ combinations }: { combinations: Combination[] }) {
  return (
    <ul className="grid grid-cols-1 gap-x-8 gap-y-5 sm:grid-cols-2 xl:grid-cols-3">
      {combinations.map((combination) => (
        <li key={combination.title} data-combination="" className="min-w-0 border-l border-line pl-4">
          <p className="text-caption text-ink-muted">{combination.title}</p>
          <ul className="mt-1.5 space-y-2">
            {combination.methods.map((method, index) => (
              <li key={`${method.method}-${index}`} className="min-w-0">
                {method.method ? <p className="font-mono text-label break-words text-ink">{method.method}</p> : null}
                {[method.codeAccuracy, method.biometricAccuracy, method.patternAccuracy]
                  .filter(Boolean)
                  .map((line) => (
                    <p key={line} className="mt-0.5 text-caption break-words text-ink-muted">
                      {line}
                    </p>
                  ))}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
