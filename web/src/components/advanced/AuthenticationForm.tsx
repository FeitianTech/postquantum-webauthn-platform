import { TextField } from '@/components/ui/Field';
import { ALLOW_CREDENTIALS_TEXT } from '@/logic/advanced/authentication/allow-credentials.js';
import { FAKE_CREDENTIAL_TEXT } from '@/logic/advanced/fake-credentials.js';
import { HINT_VALUES } from '@/logic/advanced/hints.js';

import { About, Chip, ChipGroupField, Chips, FakeCredentialField, FormSection, HexField, SelectField, toggled } from './FieldControls';
import { AUTHENTICATION_FIELDS, AUTHENTICATION_SECTIONS } from './fieldText';
import { lockedAuthFields } from './model';
import type { AuthenticationRequest } from './useAuthenticationRequest';

const FIELDS = AUTHENTICATION_FIELDS;
const WIDE = '@lg:col-span-full';

// The authentication's form: Credential Selection, Other Options and
// Extensions, each field changing the request (the JSON editor's text). What
// the saved credentials cannot ask for is locked, with a note saying why.
export function AuthenticationForm({ request }: { request: AuthenticationRequest }) {
  const { settings, change, availability } = request;
  const locked = lockedAuthFields(settings, availability);
  const [selection, other, extensions] = AUTHENTICATION_SECTIONS;
  const hintOrder = [...HINT_VALUES, ...settings.hints.filter((hint) => !HINT_VALUES.includes(hint))];
  const allowOptions = [
    { value: 'all', label: ALLOW_CREDENTIALS_TEXT.all },
    { value: 'empty', label: ALLOW_CREDENTIALS_TEXT.empty },
    ...request.choices.map(({ value, label }) => ({ value, label })),
  ];

  return (
    <div className="flex min-w-0 flex-col gap-6" data-authentication-form="">
      <FormSection title={selection}>
        <SelectField text={FIELDS.userVerification} value={settings.userVerification} onChange={(value) => change('userVerification', value)} />
        <SelectField
          text={FIELDS.allowCredentials}
          options={allowOptions}
          value={settings.allowCredentials}
          onChange={(value) => change('allowCredentials', value)}
        />
        <FakeCredentialField
          text={FIELDS.fakeCredLength}
          length={settings.fakeCredLength}
          onLength={(value) => change('fakeCredLength', value)}
          ids={request.fakeAllow}
          emptyText={FAKE_CREDENTIAL_TEXT.noAllow}
          message={request.fakeMessage}
          onAdd={request.addFake}
          onRemove={request.removeFake}
        />
      </FormSection>

      <FormSection title={other}>
        <HexField
          text={FIELDS.challenge}
          value={settings.challenge}
          onChange={(value) => change('challenge', value)}
          minBytes={16}
          onRandom={request.randomizeChallenge}
        />
        <TextField
          label={FIELDS.timeout.label}
          aside={<About label={FIELDS.timeout.label} about={FIELDS.timeout.about} />}
          type="number"
          min={1}
          value={settings.timeout}
          onChange={(event) => change('timeout', event.target.value)}
        />
        <ChipGroupField text={FIELDS.hints} className={WIDE}>
          <Chips>
            {FIELDS.hints.options.map((option) => (
              <Chip
                key={option.value}
                pressed={settings.hints.includes(option.value)}
                onChange={(pressed) => change('hints', toggled(settings.hints, option.value, pressed, hintOrder))}
              >
                {option.label}
              </Chip>
            ))}
          </Chips>
        </ChipGroupField>
        <SelectField text={FIELDS.hashAlgorithm} value={settings.hashAlgorithm} onChange={(value) => change('hashAlgorithm', value)} />
      </FormSection>

      <FormSection title={extensions}>
        <SelectField
          text={FIELDS.largeBlob}
          value={settings.largeBlob}
          onChange={(value) => change('largeBlob', value)}
          disabled={locked.largeBlob}
          disabledOptions={locked.largeBlob ? ['read', 'write'] : []}
          note={availability.largeBlob.message}
        />
        <HexField
          text={FIELDS.largeBlobWrite}
          value={settings.largeBlobWrite}
          onChange={(value) => change('largeBlobWrite', value)}
          minBytes={1}
          onRandom={request.randomizeLargeBlobWrite}
          disabled={locked.largeBlobWrite}
        />
        <HexField
          text={FIELDS.prfFirst}
          value={settings.prfFirst}
          onChange={(value) => change('prfFirst', value)}
          minBytes={32}
          onRandom={() => request.randomizePrf('prfFirst')}
          disabled={locked.prfFirst}
          note={availability.prf.message}
        />
        <HexField
          text={FIELDS.prfSecond}
          value={settings.prfSecond}
          onChange={(value) => change('prfSecond', value)}
          minBytes={32}
          onRandom={() => request.randomizePrf('prfSecond')}
          disabled={locked.prfSecond}
        />
      </FormSection>
    </div>
  );
}
