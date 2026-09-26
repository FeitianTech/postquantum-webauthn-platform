import type { CodecFailure } from './model';

// Why the last run showed no answer, where it stays until the next run or Clear:
// the sentence as the current panel says it, and, when the server named them,
// the offset and path where the input stops being well-formed, in mono.
export function FailureNotice({ failure }: { failure: CodecFailure }) {
  return (
    <div role="alert" className="rounded-sm border border-danger-line bg-danger-tint px-4 py-3" data-role="failure">
      <p className="text-body text-danger wrap-anywhere" data-role="failure-text">
        {failure.text}
      </p>
      {failure.offset !== null || failure.path !== null ? (
        <p className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-label text-danger">
          {failure.offset !== null ? (
            <span>
              offset{' '}
              <code className="font-mono" data-role="offset">
                {failure.offset}
              </code>
            </span>
          ) : null}
          {failure.path !== null ? (
            <span>
              path{' '}
              <code className="font-mono wrap-anywhere" data-role="path">
                {failure.path}
              </code>
            </span>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}
