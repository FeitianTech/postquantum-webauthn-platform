import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type Difference, type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownText } from './recorded-words';
import { recorded } from './recorded';

// The text the Codec shows for inputs from tests/app/codec_corpus.py, against its
// recording (recorded.ts, which keeps each input), compared word for word per
// section once layout and separators are set aside (recorded-words.ts). Every
// difference must be one listed below, with its reason.

// Items of the corpus, and how each is sent: some with a CTAP status byte in
// front, one with five bytes of HID padding after it.
const INPUTS = [
  { name: 'literal:a30161616131616218016163', note: 'a repeated key, colliding keys, a non-shortest integer' },
  { name: 'literal:a241010162303102', note: 'a byte-string key and a text key that read alike' },
  { name: 'real_vectors:GET_INFO', note: 'getInfo without its status byte' },
  { name: 'real_vectors:GET_INFO', before: '00', note: 'getInfo as CTAP sends it' },
  { name: 'real_vectors:MAKE_CREDENTIAL_RESPONSE', before: '00', after: '0000000000', note: 'makeCredential with padding' },
  { name: 'captured-attestation-object:tpm', note: 'TPM attestation with its certificates' },
  { name: 'captured-attestation-object:packed', note: 'packed attestation' },
  { name: 'registration:ML-DSA-44:none', note: 'an ML-DSA-44 credential' },
  { name: 'fido2-client:_MC_RESP (not canonical)', note: 'a response that is not canonical' },
  { name: 'literal:5f4101580102ff', note: 'an indefinite-length byte string' },
  { name: 'literal:d80100', note: 'a tag' },
] as const;

// The corpus holds only strictly well-formed items; this one is read leniently.
const LENIENT = { hex: 'a2010203', note: 'CBOR that is not well-formed, read leniently' };

// What the page shows that the recording does not, and why.
const EXPECTED: ExpectedDifference[] = [
  {
    only: 'shown',
    token: /^(rendering|canonical|malformed|skipped|trailing|json|limit|input|ambiguous|ctap)$/,
    reason: "the finding's category, shown as a chip (not in the recording)",
  },
  // The TPM certificate's extensions: the recording holds cryptography's repr of
  // each value, which the server now writes as OpenSSL does.
  {
    only: 'recorded',
    section: 'Attestation object',
    token: /^(<KeyUsage\()?[a-z_]+=(True|False)(\)>)?$/,
    reason: 'KeyUsage was shown as a Python repr; it is now the usages in words',
  },
  { only: 'shown', section: 'Attestation object', token: /^(Digital|Signature)$/, reason: 'KeyUsage in words: Digital Signature' },
  {
    only: 'recorded',
    section: 'Attestation object',
    token: /^(<ExtendedKeyUsage\(\[<ObjectIdentifier\(oid=2\.23\.133\.8\.3|name=Unknown|OID\)>\]\)>)$/,
    reason: 'ExtendedKeyUsage was shown as a Python repr; it is now each purpose by name or number',
  },
  { only: 'shown', section: 'Attestation object', token: /^2\.23\.133\.8\.3$/, reason: 'ExtendedKeyUsage: the TPM purpose, by number' },
  {
    only: 'recorded',
    section: 'Attestation object',
    token: /^<SubjectAlternativeName\(<GeneralNames\(\[<DirectoryName\(value=<Name\((.+)\)>\)>\]\)>\)>$/,
    reason: 'SubjectAlternativeName was shown as a Python repr; it is now each name with its kind',
  },
  { only: 'shown', section: 'Attestation object', token: /^DirName:2\.23\.133\.2\.3=/, reason: "SubjectAlternativeName: the TPM's directory name" },
  {
    only: 'recorded',
    section: 'Attestation object',
    token: /^(<AuthorityInformationAccess\(\[<AccessDescription\(access_method=<ObjectIdentifier\(oid=1\.3\.6\.1\.5\.5\.7\.48\.2|name=caIssuers\)>|access_location=<UniformResourceIdentifier\(value='https:.+'\)>\)>\]\)>)$/,
    reason: 'AuthorityInformationAccess was shown as a Python repr; it is now each method and place',
  },
  {
    only: 'shown',
    section: 'Attestation object',
    token: /^(caIssuers|-|URI:https:\/\/azcsprodncuaikpublish\..+)$/,
    reason: "AuthorityInformationAccess: where the TPM's issuer certificate is",
  },
  {
    only: 'recorded',
    section: 'Attestation object',
    token: /^(<CertificatePolicies\(\[<PolicyInformation\(policy_identifier=<ObjectIdentifier\(oid=1\.3\.6\.1\.4\.1\.311\.21\.31|OID\)>|policy_qualifiers=\[<UserNotice\(notice_reference=None|explicit_text='TCPA|Identity'\)>\]\)>\]\)>)$/,
    reason: 'CertificatePolicies was shown as a Python repr; it is now each policy with its notices',
  },
  {
    only: 'shown',
    section: 'Attestation object',
    token: /^(Policy|1\.3\.6\.1\.4\.1\.311\.21\.31|User|Notice|TCPA|Identity)$/,
    reason: "CertificatePolicies: the TPM's policy and its notice",
  },
];

async function shownText(page: Page, input: string, lenient: boolean) {
  await page.goto('/#codec');
  const decoding = page.locator('#codec-mode-panel-decode');
  await decoding.getByRole('textbox', { name: 'Input to decode' }).fill(input);
  if (lenient) await decoding.getByRole('switch', { name: 'Best effort (lenient)' }).click();
  await decoding.getByRole('button', { name: 'Decode', exact: true }).click();
  const output = decoding.locator('[data-codec-output="decode"]');
  await expect(output).toBeVisible();
  return readShownText(output, '[data-codec-section] > h4');
}

test.describe('the Codec reads as recorded', () => {
  const found: Record<string, Difference[]> = {};

  test.afterAll(async ({}, testInfo) => {
    const report = Object.entries(found).flatMap(([label, differences]) => [`${label}:`, ...describeDifferences(differences).map((line) => `  ${line}`)]);
    await testInfo.attach('codec-recorded.txt', { body: report.join('\n') || 'no differences', contentType: 'text/plain' });
    console.log(report.join('\n') || 'no differences');
  });

  const cases = [
    ...INPUTS.map((input) => `${input.name}${'before' in input ? ` (${input.note})` : ''}`),
    `lenient ${LENIENT.hex}`,
  ];

  for (const label of cases) {
    test(label, async ({ page }) => {
      const current = recorded<{ input: string; lenient: boolean; sections: ShownSection[] }>('codec', label);
      const shownSections = await shownText(page, current.input, current.lenient);
      expect(current.sections.length, 'the recording holds sections').toBeGreaterThan(1);

      const differences = compareShownText(current.sections, shownSections, EXPECTED);
      found[label] = differences;
      expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    });
  }
});
