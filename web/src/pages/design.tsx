import { SOURCE_TEXT } from '@legacy/shared/browser/identity.js';
import { STATE_TEXT } from '@legacy/shared/browser/webauthn-facts.js';
import Head from 'next/head';
import { type ReactNode, useState } from 'react';

import { STATE_TONES } from '@/components/analyze-browser/FactList';
import { Badge, StatusChip } from '@/components/ui/Badge';
import { Button, IconButton } from '@/components/ui/Button';
import { Card, CardHeader } from '@/components/ui/Card';
import { Select, TextArea, TextField } from '@/components/ui/Field';
import { CloseIcon, CopyIcon, InfoIcon } from '@/components/ui/icons';
import { InfoPopover } from '@/components/ui/InfoPopover';
import { KeyValueGrid } from '@/components/ui/KeyValueGrid';
import { MonoValue } from '@/components/ui/MonoValue';
import { Dialog, Drawer, OverlayBody, OverlayHeader, Sheet } from '@/components/ui/Overlay';
import { SegmentedControl, segmentIds } from '@/components/ui/SegmentedControl';
import { Switch, ToggleChip } from '@/components/ui/Switch';
import { TBody, THead, Table, Td, Th, Tr } from '@/components/ui/Table';
import { ToastProvider, useToast } from '@/components/ui/Toast';
import { SECTION_OPTIONS } from '@/lib/sections';

// Unlisted: every component in every state, for review (docs/UI_MIGRATION.md).
// Hover, keyboard focus and pressed are shown still through data-demo, which
// the components style exactly as the real state.

const DEMO_STATES = [
  { label: 'Default', demo: undefined },
  { label: 'Hover', demo: 'hover' },
  { label: 'Keyboard focus', demo: 'focus' },
  { label: 'Pressed', demo: 'active' },
] as const;

const AAGUID = 'ee882879-721c-4913-9775-3dfcce97072a';
const PUBLIC_KEY =
  'pQECAyYgASFYIJzXm9a0WX1ifXaCxk7t5tLVEQ4g7tJjKY2QwHqHjfhVIlggLp8XoUXbA2vD6Hbpu8Q0T8SrXl1zVx2k5K6vJdGf3dI';

function Section({ id, title, description, children }: { id: string; title: string; description?: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="border-t border-line pt-8">
      <h2 id={id} className="text-heading font-semibold text-ink">
        {title}
      </h2>
      {description ? <p className="mt-1.5 max-w-prose text-body text-ink-muted">{description}</p> : null}
      <div className="mt-6 flex flex-col gap-8">{children}</div>
    </section>
  );
}

function Example({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={className}>
      <p className="mb-2 text-caption text-ink-muted">{label}</p>
      {children}
    </div>
  );
}

function Row({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-end gap-x-6 gap-y-5">{children}</div>;
}

function Grid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-1 gap-x-6 gap-y-6 sm:grid-cols-2 lg:grid-cols-3 wide:grid-cols-4">{children}</div>;
}

function Colours() {
  const tints = [
    ['Accent', 'bg-accent', 'text-white'],
    ['Accent tint', 'bg-accent-tint', 'text-accent-ink'],
    ['Success tint', 'bg-success-tint', 'text-success'],
    ['Warning tint', 'bg-warning-tint', 'text-warning'],
    ['Danger tint', 'bg-danger-tint', 'text-danger'],
    ['Surface', 'bg-surface border border-line-strong', 'text-ink'],
  ] as const;
  return (
    <>
      <Example label="Text: grey exists only as text colour">
        <Row>
          <span className="text-title font-semibold text-ink">Ink #1d1d1f</span>
          <span className="text-title text-ink-muted">Secondary #6e6e73</span>
          <span className="text-title text-ink-faint">Placeholder #86868b</span>
          <span className="text-title text-accent-ink">Link #0062c4</span>
        </Row>
      </Example>
      <Example label="Fills: white, the accent, and semantic tints (never grey)">
        <Row>
          {tints.map(([name, fill, ink]) => (
            <span key={name} className={`inline-flex h-12 w-36 items-center justify-center rounded-md text-label font-medium ${fill} ${ink}`}>
              {name}
            </span>
          ))}
        </Row>
      </Example>
      <Example label="Hairlines: divider, control border, hovered control border">
        <Row>
          <span className="h-10 w-36 rounded-sm border border-line" />
          <span className="h-10 w-36 rounded-sm border border-line-strong" />
          <span className="h-10 w-36 rounded-sm border border-line-hover" />
        </Row>
      </Example>
    </>
  );
}

function Typography() {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-display font-semibold">Display — page titles</p>
      <p className="text-heading font-semibold">Heading — section titles</p>
      <p className="text-title font-semibold">Title — dialog titles</p>
      <p className="text-title-sm font-semibold">Title small — card titles</p>
      <p className="text-body-lg">Body large — values and prominent text</p>
      <p className="text-body">Body — the default size for text and controls</p>
      <p className="text-label font-medium">Label — field labels and chips</p>
      <p className="text-caption text-ink-muted">Caption — hints, sources and table headers</p>
      <p className="font-mono text-label">Geist Mono — {AAGUID} a1 01 02 03 26 20 01</p>
    </div>
  );
}

function RadiiAndShadows() {
  return (
    <>
      <Example label="Radii: 6, 10, 14, 20 and pill">
        <Row>
          {['rounded-xs', 'rounded-sm', 'rounded-md', 'rounded-lg', 'rounded-full'].map((radius) => (
            <span key={radius} className={`inline-flex h-16 w-24 items-center justify-center border border-line-strong text-caption text-ink-muted ${radius}`}>
              {radius.replace('rounded-', '')}
            </span>
          ))}
        </Row>
      </Example>
      <Example label="Shadows: only on floating layers (popover, menu, dialog)">
        <Row>
          {['shadow-float-sm', 'shadow-float', 'shadow-float-lg'].map((shadow) => (
            <span key={shadow} className={`inline-flex h-20 w-40 items-center justify-center rounded-md bg-surface text-caption text-ink-muted ${shadow}`}>
              {shadow.replace('shadow-', '')}
            </span>
          ))}
        </Row>
      </Example>
    </>
  );
}

function Buttons() {
  return (
    <>
      {(['primary', 'secondary', 'danger', 'quiet'] as const).map((variant) => (
        <Example key={variant} label={`Button — ${variant}`}>
          <Row>
            {DEMO_STATES.map(({ label, demo }) => (
              <Button key={label} variant={variant} data-demo={demo}>
                {label}
              </Button>
            ))}
            <Button variant={variant} disabled>
              Disabled
            </Button>
            <Button variant={variant} busy>
              Busy
            </Button>
            <Button variant={variant} size="sm">
              Small
            </Button>
          </Row>
        </Example>
      ))}
      <Example label="IconButton — quiet and secondary, in each state">
        <Row>
          {DEMO_STATES.map(({ label, demo }) => (
            <IconButton key={label} label={`Close (${label})`} icon={<CloseIcon />} data-demo={demo} />
          ))}
          <IconButton label="Close (disabled)" icon={<CloseIcon />} disabled />
          {DEMO_STATES.map(({ label, demo }) => (
            <IconButton key={`s-${label}`} variant="secondary" label={`Copy (${label})`} icon={<CopyIcon />} data-demo={demo} />
          ))}
          <IconButton size="sm" label="Info (small)" icon={<InfoIcon />} />
        </Row>
      </Example>
    </>
  );
}

function Fields() {
  const [text, setText] = useState('alice');
  return (
    <>
      <Grid>
        <TextField label="Empty, with a placeholder" placeholder="Enter username" hint="Letters, digits and dashes" />
        <TextField label="Filled" value={text} onChange={(event) => setText(event.target.value)} />
        <TextField label="Hover (a darker hairline)" defaultValue="alice" data-demo="hover" />
        <TextField label="Focused: no effect, by design" defaultValue="the caret shows focus" data-demo="focus" />
        <TextField label="Read-only (white, muted text)" readOnly value={AAGUID} mono />
        <TextField label="Disabled (white, muted text)" disabled defaultValue="Not available" />
        <TextField label="Error" defaultValue="xyz" error="Invalid hex value (exactly 32 bytes required)" />
        <TextField
          label="With a control inside"
          placeholder="Hex value"
          trailing={<IconButton size="sm" label="Generate random PRF evaluation data" icon={<CopyIcon />} />}
        />
      </Grid>
      <Grid>
        <TextArea label="Text area" placeholder="Paste something to decode" rows={4} />
        <TextArea label="Monospaced text area" mono rows={4} defaultValue={'{\n  "challenge": "3q2-7w",\n  "timeout": 90000\n}'} />
        <TextArea label="Text area with an error" rows={4} defaultValue="a1 02" error="Not valid CBOR: the input ended in the middle of an item." />
      </Grid>
      <Grid>
        <Select label="Select" defaultValue="direct" hint="A native select: the platform's own list">
          <option value="none">none</option>
          <option value="indirect">indirect</option>
          <option value="direct">direct</option>
          <option value="enterprise">enterprise</option>
        </Select>
        <Select label="Select with keyboard focus" data-demo="focus" defaultValue="preferred">
          <option value="required">required</option>
          <option value="preferred">preferred</option>
          <option value="discouraged">discouraged</option>
        </Select>
        <Select label="Disabled select" disabled defaultValue="a">
          <option value="a">Not available</option>
        </Select>
        <Select label="Select with an error" error="Choose an attachment" defaultValue="">
          <option value="">Choose…</option>
        </Select>
      </Grid>
    </>
  );
}

function Switches() {
  const [on, setOn] = useState(true);
  const [off, setOff] = useState(false);
  const [chips, setChips] = useState<string[]>(['ML-DSA-65', 'ES256']);
  const toggle = (name: string) => setChips(chips.includes(name) ? chips.filter((chip) => chip !== name) : [...chips, name]);
  return (
    <>
      <Grid>
        <Switch label="Off" checked={off} onCheckedChange={setOff} description="Require a resident key" />
        <Switch label="On" checked={on} onCheckedChange={setOn} description="Require user verification" />
        <Switch label="Hover" checked={false} onCheckedChange={() => {}} data-demo="hover" />
        <Switch label="Keyboard focus" checked onCheckedChange={() => {}} data-demo="focus" />
        <Switch label="Disabled, off" checked={false} onCheckedChange={() => {}} disabled />
        <Switch label="Disabled, on" checked onCheckedChange={() => {}} disabled hint="Not changeable here" />
      </Grid>
      <Example label="ToggleChip — a set chosen in any combination (algorithms, hints)">
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-2">
            {['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'ES256', 'EdDSA', 'RS256'].map((name) => (
              <ToggleChip key={name} pressed={chips.includes(name)} onPressedChange={() => toggle(name)}>
                {name}
              </ToggleChip>
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {DEMO_STATES.map(({ label, demo }) => (
              <ToggleChip key={label} pressed={false} onPressedChange={() => {}} data-demo={demo}>
                {label}
              </ToggleChip>
            ))}
            <ToggleChip pressed onPressedChange={() => {}} data-demo="hover">
              On, hover
            </ToggleChip>
            <ToggleChip pressed={false} onPressedChange={() => {}} disabled>
              Disabled
            </ToggleChip>
            <ToggleChip pressed onPressedChange={() => {}} disabled>
              Disabled, on
            </ToggleChip>
          </div>
        </div>
      </Example>
    </>
  );
}

function Segments() {
  const [section, setSection] = useState<(typeof SECTION_OPTIONS)[number]['value']>('simple');
  const [mode, setMode] = useState<'registration' | 'authentication'>('registration');
  const [codec, setCodec] = useState<'decode' | 'encode'>('decode');
  return (
    <>
      <Example label="The top bar's sections: one highlight slides to the chosen tab (it jumps under reduced motion)">
        <div className="max-w-full overflow-x-auto pb-1">
          <SegmentedControl label="Sections (demo)" idBase="design-sections" options={SECTION_OPTIONS} value={section} onChange={setSection} />
        </div>
        <p id={segmentIds('design-sections', section).panel} className="mt-2 text-caption text-ink-muted">
          Chosen: {section}. Arrow keys, Home and End move between tabs.
        </p>
      </Example>
      <Row>
        <Example label="Small, as the Registration / Authentication switch">
          <SegmentedControl
            label="Ceremony (demo)"
            idBase="design-ceremony"
            size="sm"
            options={[
              { value: 'registration', label: 'Registration' },
              { value: 'authentication', label: 'Authentication' },
            ]}
            value={mode}
            onChange={setMode}
          />
        </Example>
        <Example label="Small, as the Decode / Encode switch">
          <SegmentedControl
            label="Codec mode (demo)"
            idBase="design-codec"
            size="sm"
            options={[
              { value: 'decode', label: 'Decode' },
              { value: 'encode', label: 'Encode' },
            ]}
            value={codec}
            onChange={setCodec}
          />
        </Example>
      </Row>
    </>
  );
}

function Display() {
  return (
    <>
      <Row>
        <Example label="Badge tones">
          <div className="flex flex-wrap gap-2">
            <Badge tone="accent">ML-DSA-65</Badge>
            <Badge tone="success">FIDO Certified L2</Badge>
            <Badge tone="warning">Revoked key</Badge>
            <Badge tone="danger">Compromised</Badge>
            <Badge tone="neutral">USB</Badge>
          </div>
        </Example>
        <Example label="StatusChip — the four states of an answer">
          <div className="flex flex-wrap gap-2">
            {(['yes', 'no', 'unavailable', 'undetermined'] as const).map((state) => (
              <StatusChip key={state} tone={STATE_TONES[state]}>
                {STATE_TEXT[state]}
              </StatusChip>
            ))}
          </div>
        </Example>
      </Row>
      <Card aria-labelledby="design-card-title">
        <CardHeader
          titleId="design-card-title"
          title="Card"
          description="A white section with a hairline and no shadow. Cards never nest: inside one, parts are separated by space and hairlines."
          actions={
            <>
              <Button variant="danger" size="sm">
                Clear All
              </Button>
              <Button size="sm">Register</Button>
            </>
          }
        />
        <KeyValueGrid
          columns={4}
          items={[
            { key: 'browser', label: 'Browser', value: 'Google Chrome', hint: SOURCE_TEXT['client-hints'] },
            { key: 'version', label: 'Version', value: '140.0.7339.128', hint: SOURCE_TEXT['client-hints'] },
            { key: 'engine', label: 'Engine', value: 'Blink', hint: SOURCE_TEXT['user-agent'] },
            { key: 'aaguid', label: 'AAGUID', value: AAGUID, mono: true },
          ]}
        />
      </Card>
      <Grid>
        <Example label="MonoValue — short, with copy">
          <MonoValue value={AAGUID} label="AAGUID" />
        </Example>
        <Example label="MonoValue — long: truncated, with Show all and copy">
          <MonoValue value={PUBLIC_KEY} label="public key" className="max-w-72" />
        </Example>
      </Grid>
      <Example label="Table primitives: the table scrolls inside its own frame; headers sort">
        <Table caption="Authenticators (demo)">
          <THead>
            <Tr>
              <Th sort="ascending" onSort={() => {}}>
                Name
              </Th>
              <Th sort="none" onSort={() => {}}>
                AAGUID
              </Th>
              <Th>Certification</Th>
              <Th>User verification</Th>
            </Tr>
          </THead>
          <TBody>
            <Tr>
              <Td>YubiKey 5 Series with NFC</Td>
              <Td>
                <MonoValue value="cb69481e-8ff7-4039-93ec-0a2729a154a8" label="AAGUID" />
              </Td>
              <Td>
                <Badge tone="success">FIDO Certified L1</Badge>
              </Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  <Badge>passcode</Badge>
                  <Badge>presence</Badge>
                </div>
              </Td>
            </Tr>
            <Tr data-demo="hover">
              <Td>Row on hover</Td>
              <Td>
                <MonoValue value={AAGUID} label="AAGUID" />
              </Td>
              <Td>
                <Badge tone="warning">Not FIDO Certified</Badge>
              </Td>
              <Td>
                <Badge>fingerprint</Badge>
              </Td>
            </Tr>
          </TBody>
        </Table>
      </Example>
    </>
  );
}

function Floating() {
  const toast = useToast();
  const [dialog, setDialog] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [sheet, setSheet] = useState(false);
  return (
    <>
      <Row>
        <Example label="InfoPopover — hover, click or Enter; ENG / 中">
          <div className="flex items-center gap-1.5">
            <span className="text-label font-medium">prf eval second</span>
            <InfoPopover
              label="About prf eval second"
              en={
                <>
                  <p>
                    The second prf extension input to evaluate. If set, the client extension outputs will include a
                    prf.results.second output if the client and authenticator both support the extension.
                  </p>
                  <p className="mt-3">
                    This is optional and can be used alongside the first PRF evaluation input for additional key
                    derivation capabilities.
                  </p>
                </>
              }
              zh={
                <>
                  <p>
                    要评估的第二个 prf 扩展输入。如果设置，如果客户端和认证器都支持该扩展，客户端扩展输出将包含
                    prf.results.second 输出。
                  </p>
                  <p className="mt-3">这是可选的，可以与第一个 PRF 评估输入一起使用，以获得额外的密钥派生功能。</p>
                </>
              }
            />
          </div>
        </Example>
        <Example label="Dialog, Drawer and Sheet">
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" onClick={() => setDialog(true)}>
              Open dialog
            </Button>
            <Button variant="secondary" onClick={() => setDrawer(true)}>
              Open drawer
            </Button>
            <Button variant="secondary" onClick={() => setSheet(true)}>
              Open sheet
            </Button>
          </div>
        </Example>
        <Example label="Toast — each tone">
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" onClick={() => toast({ tone: 'info', message: 'Processing…' })}>
              Info
            </Button>
            <Button variant="secondary" onClick={() => toast({ tone: 'success', message: 'Registration successful! Algorithm: ES256' })}>
              Success
            </Button>
            <Button variant="secondary" onClick={() => toast({ tone: 'warning', message: 'The signature counter did not advance.' })}>
              Warning
            </Button>
            <Button variant="secondary" onClick={() => toast({ tone: 'danger', message: 'User cancelled or authenticator not available' })}>
              Danger
            </Button>
          </div>
        </Example>
      </Row>
      <Dialog open={dialog} onClose={() => setDialog(false)} labelledBy="design-dialog-title">
        <OverlayHeader
          titleId="design-dialog-title"
          title="Dialog"
          closeLabel="Close dialog"
          onClose={() => setDialog(false)}
          actions={
            <Button variant="secondary" size="sm">
              Copy report
            </Button>
          }
        />
        <OverlayBody>
          <p className="text-body text-ink-muted">
            Takes focus when it opens, keeps Tab inside, closes on Escape, the close button or the backdrop, and gives
            focus back. The page behind is inert and not scroll-locked.
          </p>
        </OverlayBody>
      </Dialog>
      <Drawer open={drawer} onClose={() => setDrawer(false)} labelledBy="design-drawer-title">
        <OverlayHeader titleId="design-drawer-title" title="Saved Credentials" closeLabel="Close drawer" onClose={() => setDrawer(false)} />
        <OverlayBody>
          <p className="text-body text-ink-muted">A drawer slides in from the right, as the saved credentials will.</p>
        </OverlayBody>
      </Drawer>
      <Sheet open={sheet} onClose={() => setSheet(false)} labelledBy="design-sheet-title">
        <OverlayHeader titleId="design-sheet-title" title="Sheet" closeLabel="Close sheet" onClose={() => setSheet(false)} />
        <OverlayBody>
          <p className="text-body text-ink-muted">The phone menu drops from the top as a sheet.</p>
        </OverlayBody>
      </Sheet>
    </>
  );
}

export default function DesignPage() {
  return (
    <ToastProvider>
      <Head>
        <title>Design system · FIDO2/WebAuthn PQC Developer Tools</title>
      </Head>
      <main className="mx-auto flex w-full max-w-page flex-col gap-12 px-4 pt-12 pb-20 sm:px-6 lg:px-8">
        <header>
          <p className="text-label font-medium text-accent-ink">Unlisted review page</p>
          <h1 className="mt-1 text-display font-semibold">Design system</h1>
          <p className="mt-2 max-w-prose text-body-lg text-ink-muted">
            Every component in every state. Light only, white surfaces, grey only as text and hairlines, shadows only
            on floating layers, and no focus effect on text fields.
          </p>
        </header>
        <Section id="design-colours" title="Colour">
          <Colours />
        </Section>
        <Section id="design-type" title="Type" description="Geist for text, Geist Mono for data.">
          <Typography />
        </Section>
        <Section id="design-shape" title="Radii and shadows">
          <RadiiAndShadows />
        </Section>
        <Section id="design-buttons" title="Buttons">
          <Buttons />
        </Section>
        <Section id="design-fields" title="Fields" description="One field row for every control: the label above, the control, then a hint or an error.">
          <Fields />
        </Section>
        <Section id="design-switches" title="Switches and chips">
          <Switches />
        </Section>
        <Section id="design-segments" title="Segmented control">
          <Segments />
        </Section>
        <Section id="design-display" title="Cards, badges, values and tables">
          <Display />
        </Section>
        <Section id="design-floating" title="Floating layers">
          <Floating />
        </Section>
      </main>
    </ToastProvider>
  );
}
