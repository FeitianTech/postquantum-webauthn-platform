import { TextField } from '@/components/ui/Field';
import { FAKE_CREDENTIAL_TEXT } from '@/logic/advanced/fake-credentials.js';
import { HINT_VALUES } from '@/logic/advanced/hints.js';
import { ALGORITHM_OPTIONS } from '@/logic/advanced/registration/algorithm-options.js';
import { registrationControls } from '@/logic/advanced/registration/request.js';

import { About, Chip, ChipGroupField, Chips, FakeCredentialField, FormSection, HexField, SelectField, SwitchField, toggled } from './FieldControls';
import { REGISTRATION_FIELDS, REGISTRATION_SECTIONS } from './fieldText';
import type { AdvancedRequest } from './useAdvancedRequest';

const FIELDS = REGISTRATION_FIELDS;

const WIDE = '@lg:col-span-full';

function AboutFor({ field }: { field: keyof typeof FIELDS }) {
  const text: { label: string; about?: { en: string[]; zh: string[] } } = FIELDS[field];
  return <About label={text.label} about={text.about} />;
}

const [USER_SECTION, SELECTION_SECTION, OTHER_SECTION, EXTENSIONS_SECTION] = REGISTRATION_SECTIONS;

function UserIdentity({ request }: { request: AdvancedRequest }) {
  const { settings, change } = request;
  return (
    <FormSection title={USER_SECTION}>
      <HexField
        text={FIELDS.userId}
        value={settings.userId}
        onChange={(value) => change('userId', value)}
        minBytes={1}
        onRandom={request.randomizeIdentity}
      />
      <TextField
        label={FIELDS.userName.label}
        placeholder={FIELDS.userName.placeholder}
        value={settings.userName}
        onChange={(event) => change('userName', event.target.value)}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
      />
      <TextField label={FIELDS.displayName.label} placeholder={FIELDS.displayName.placeholder} value={settings.displayName} readOnly />
    </FormSection>
  );
}

function AuthenticatorSelection({ request }: { request: AdvancedRequest }) {
  const { settings, change } = request;
  return (
    <FormSection title={SELECTION_SECTION}>
      <SelectField text={FIELDS.attachment} value={settings.attachment} onChange={(value) => change('attachment', value)} />
      <SelectField text={FIELDS.residentKey} value={settings.residentKey} onChange={(value) => change('residentKey', value)} />
      <SelectField text={FIELDS.userVerification} value={settings.userVerification} onChange={(value) => change('userVerification', value)} />
      <SelectField text={FIELDS.attestation} value={settings.attestation} onChange={(value) => change('attestation', value)} />
      <SwitchField text={FIELDS.excludeCredentials} checked={settings.excludeCredentials} onChange={(value) => change('excludeCredentials', value)} />
      <FakeCredentialField
        text={FIELDS.fakeCredLength}
        length={settings.fakeCredLength}
        onLength={(value) => change('fakeCredLength', value)}
        ids={request.fakeExclude}
        emptyText={FAKE_CREDENTIAL_TEXT.noExclude}
        message={request.fakeMessage}
        onAdd={request.addFake}
        onRemove={request.removeFake}
      />
    </FormSection>
  );
}

function OtherOptions({ request }: { request: AdvancedRequest }) {
  const { settings, change } = request;
  const classical = ALGORITHM_OPTIONS.filter((option) => !option.pqc);
  const pqc = ALGORITHM_OPTIONS.filter((option) => option.pqc);
  const algorithmOrder = ALGORITHM_OPTIONS.map((option) => option.alg);
  const toggleAlgorithm = (alg: number) => (pressed: boolean) => change('algorithms', toggled(settings.algorithms, alg, pressed, algorithmOrder));
  const hintOrder = [...HINT_VALUES, ...settings.hints.filter((hint) => !HINT_VALUES.includes(hint))];
  return (
    <FormSection title={OTHER_SECTION}>
      <HexField
        text={FIELDS.challenge}
        value={settings.challenge}
        onChange={(value) => change('challenge', value)}
        minBytes={16}
        onRandom={request.randomizeChallenge}
      />
      <TextField
        label={FIELDS.timeout.label}
        aside={<AboutFor field="timeout" />}
        type="number"
        min={1}
        value={settings.timeout}
        onChange={(event) => change('timeout', event.target.value)}
      />
      <ChipGroupField text={FIELDS.algorithms} className={WIDE}>
        <Chips>
          {classical.map((option) => (
            <Chip key={option.key} pressed={settings.algorithms.includes(option.alg)} onChange={toggleAlgorithm(option.alg)}>
              {option.label}
            </Chip>
          ))}
        </Chips>
        <Chips label="PQC">
          {pqc.map((option) => (
            <Chip key={option.key} pressed={settings.algorithms.includes(option.alg)} onChange={toggleAlgorithm(option.alg)}>
              {option.label}
            </Chip>
          ))}
        </Chips>
      </ChipGroupField>
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
    </FormSection>
  );
}

function Extensions({ request }: { request: AdvancedRequest }) {
  const { settings, change } = request;
  const locked = registrationControls(settings);
  return (
    <FormSection title={EXTENSIONS_SECTION}>
      <SwitchField text={FIELDS.credProps} checked={settings.credProps} onChange={(value) => change('credProps', value)} />
      <SwitchField text={FIELDS.minPinLength} checked={settings.minPinLength} onChange={(value) => change('minPinLength', value)} />
      <SelectField text={FIELDS.credProtect} value={settings.credProtect} onChange={(value) => change('credProtect', value)} />
      <SwitchField
        text={FIELDS.enforceCredProtect}
        checked={settings.enforceCredProtect}
        onChange={(value) => change('enforceCredProtect', value)}
        disabled={locked.enforceCredProtect}
      />
      <SelectField text={FIELDS.largeBlob} value={settings.largeBlob} onChange={(value) => change('largeBlob', value)} />
      <SwitchField text={FIELDS.prf} checked={settings.prf} onChange={(value) => change('prf', value)} />
      <HexField
        text={FIELDS.prfFirst}
        value={settings.prfFirst}
        onChange={(value) => change('prfFirst', value)}
        minBytes={32}
        onRandom={() => request.randomizePrf('prfFirst')}
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
  );
}

// The registration's form: User Identity, Authenticator Selection, Other Options
// and Extensions, each field changing the request (the JSON editor's text).
export function RegistrationForm({ request }: { request: AdvancedRequest }) {
  return (
    <div className="flex min-w-0 flex-col gap-6" data-registration-form="">
      <UserIdentity request={request} />
      <AuthenticatorSelection request={request} />
      <OtherOptions request={request} />
      <Extensions request={request} />
    </div>
  );
}
