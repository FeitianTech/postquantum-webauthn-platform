import { Badge } from '@/components/ui/Badge';

// The formats the decoder reads, as the current panel lists them.
const SUPPORTED_INPUTS: { name: string; kinds: string[] }[] = [
  {
    name: 'JSON',
    kinds: ['PublicKeyCredential (registration)', 'PublicKeyCredential (authentication)', 'Generic JSON payloads'],
  },
  { name: 'JSON (binary)', kinds: ['clientDataJSON', 'Generic JSON payloads'] },
  {
    name: 'CBOR',
    kinds: [
      'Attestation objects',
      'CTAP makeCredential request',
      'CTAP makeCredential response',
      'CTAP getAssertion request',
      'CTAP getAssertion response',
      'CTAP getInfo response',
      'Generic CBOR payloads',
    ],
  },
  { name: 'Binary', kinds: ['Authenticator data', 'Signature fields'] },
  { name: 'PEM', kinds: ['X.509 certificates', 'Certificate chains'] },
  { name: 'DER', kinds: ['X.509 certificates'] },
];

// Shown where the output goes while there is none.
export function SupportedInputs() {
  return (
    <section aria-labelledby="codec-supported-inputs" data-role="supported-inputs">
      <h3 id="codec-supported-inputs" className="text-title-sm font-semibold text-ink">
        Supported Inputs
      </h3>
      <dl className="mt-4 flex flex-col gap-3">
        {SUPPORTED_INPUTS.map((format) => (
          <div key={format.name} className="flex flex-col gap-1.5 sm:flex-row sm:gap-4">
            <dt className="shrink-0 pt-0.5 text-label font-medium text-ink sm:w-28">{format.name}</dt>
            <dd className="flex flex-wrap gap-1.5">
              {format.kinds.map((kind) => (
                <Badge key={kind}>{kind}</Badge>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
