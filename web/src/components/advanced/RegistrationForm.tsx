import { type ReactNode, useId } from 'react';

import { TextField } from '@/components/ui/Field';

import { About, Chip, ChipGroupField, Chips, FakeCredentialField, HexField, SelectField, SwitchField } from './FieldControls';
import { REGISTRATION_FIELDS, REGISTRATION_SECTIONS } from './fieldText';
import { ALGORITHMS, FAKE_TEXT, HINTS, lockedFields } from './model';
import type { AdvancedRequest } from './useAdvancedRequest';

const FIELDS = REGISTRATION_FIELDS;

// One section of the form: a card of its own (no card in a card) whose fields
// sit on a grid its own width sets: one column, then two, then three.
function FormSection({ title, children }: { title: string; children: ReactNode }) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className="@container min-w-0 rounded-lg border border-line bg-surface p-5 sm:p-6" data-form-section={title}>
      <h3 id={headingId} className="text-title-sm font-semibold text-ink">
        {title}
      </h3>
      <div className="mt-5 grid grid-cols-1 gap-x-5 gap-y-5 @lg:grid-cols-2 @3xl:grid-cols-3">{children}</div>
    </section>
  );
}

const WIDE = '@lg:col-span-full';

function AboutFor({ field }: { field: keyof typeof FIELDS }) {
  const text: { label: string; about?: { en: string[]; zh: string[] } } = FIELDS[field];
  return <About label={text.label} about={text.about} />;
}

/**
 * A set held in the settings, one member toggled: the rest keep their order (an
 * edit's included); one put in goes before the first that `order` puts after it.
 */
function toggled<T>(set: T[], member: T, pressed: boolean, order: T[]) {
  if (!pressed) return set.filter((value) => value !== member);
  if (set.includes(member)) return set;
  const at = set.findIndex((value) => order.indexOf(value) > order.indexOf(member));
  return at < 0 ? [...set, member] : [...set.slice(0, at), member, ...set.slice(at)];
}

// The registration's form: User Identity, Authenticator Selection, Other Options
// and Extensions, each field changing the request (the JSON editor's text).
export function RegistrationForm({ request }: { request: AdvancedRequest }) {
  const { settings, change } = request;
  const locked = lockedFields(settings);
  const [user, selection, other, extensions] = REGISTRATION_SECTIONS;
  const classical = ALGORITHMS.filter((option) => !option.pqc);
  const pqc = ALGORITHMS.filter((option) => option.pqc);
  const algorithmOrder = ALGORITHMS.map((option) => option.alg);
  const toggleAlgorithm = (alg: number) => (pressed: boolean) => change('algorithms', toggled(settings.algorithms, alg, pressed, algorithmOrder));
  const hintOrder = [...HINTS, ...settings.hints.filter((hint) => !HINTS.includes(hint))];

  return (
    <div className="flex min-w-0 flex-col gap-6" data-registration-form="">
      <FormSection title={user}>
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

      <FormSection title={selection}>
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
          emptyText={FAKE_TEXT.noExclude}
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

      <FormSection title={extensions}>
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
    </div>
  );
}
