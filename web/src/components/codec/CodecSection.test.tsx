import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import answers from '@/test/codec-answers.json';
import { renderPage } from '@/test/page';

import { CodecSection } from './CodecSection';

// Real answers of POST /api/codec (tests/app/tooling/test_web_codec_answers.py
// keeps them the server's own), each with the request that produced it.
type Recorded = { request: Record<string, unknown>; status: number; answer: Record<string, unknown> };
const RECORDED = answers as Record<string, Recorded>;

function reply(name: string) {
  const { status, answer } = RECORDED[name];
  return new Response(JSON.stringify(answer), { status, headers: { 'Content-Type': 'application/json' } });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

const fetchMock = vi.fn<(url: string, init: RequestInit) => Promise<Response>>();

function sentBodies() {
  return fetchMock.mock.calls.map(([, init]) => JSON.parse(String(init.body)));
}

function renderCodec() {
  renderPage(
    <ToastProvider>
      {/* The header's tab, which names the section's panel. */}
      <div role="tablist" aria-label="Sections">
        <button type="button" role="tab" id="nav-tab-codec" aria-selected="true">
          Codec
        </button>
      </div>
      <CodecSection active />
    </ToastProvider>,
  );
  return screen.getByRole('tabpanel', { name: 'Codec' });
}

const decodePanel = () => screen.getByRole('tabpanel', { name: 'Decode' });
// By id: a hidden panel has no accessible name to find it by.
const encodePanel = () => document.getElementById('codec-mode-panel-encode')!;

async function typeInto(panel: HTMLElement, text: string) {
  const input = within(panel).getByRole('textbox');
  await userEvent.clear(input);
  if (text) {
    // user-event reads { and [ as key descriptors: paste the text as it is.
    await userEvent.click(input);
    await userEvent.paste(text);
  }
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, 'clipboard');
});

describe('the Codec section', () => {
  it('has its title, description and the Decode / Encode switch, Decode first (CX-T1, CX-M1)', () => {
    const section = renderCodec();
    expect(within(section).getByRole('heading', { level: 2, name: 'Codec' })).toBeInTheDocument();
    expect(section).toHaveTextContent('Decode or encode WebAuthn payloads to inspect their underlying data formats.');
    const modes = within(section).getByRole('tablist', { name: 'Codec mode' });
    expect(within(modes).getByRole('tab', { name: 'Decode' })).toHaveAttribute('aria-selected', 'true');
    expect(within(modes).getByRole('tab', { name: 'Encode' })).toHaveAttribute('aria-controls', 'codec-mode-panel-encode');
    expect(decodePanel()).toBeVisible();
    expect(encodePanel()).toHaveAttribute('role', 'tabpanel');
    expect(encodePanel()).not.toBeVisible();
    // Each panel comes in as it is shown, and holds still under reduced motion (CX-M4).
    expect(encodePanel().className).toContain('animate-[section-in');
    expect(encodePanel().className).toContain('motion-reduce:animate-none');
  });

  it('keeps each mode\'s input and answer across switches (CX-M2, CX-M5)', async () => {
    fetchMock.mockResolvedValueOnce(reply('decode-duplicate-and-colliding-keys'));
    renderCodec();
    await typeInto(decodePanel(), 'a301616161316162016163');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await within(decodePanel()).findByRole('heading', { name: 'Codec Output' });

    await userEvent.click(screen.getByRole('tab', { name: 'Encode' }));
    expect(within(encodePanel()).getByRole('textbox')).toHaveValue('');
    expect(within(encodePanel()).getByText('The encoded bytes appear here.')).toBeInTheDocument();
    await typeInto(encodePanel(), '{"a": 1}');

    await userEvent.click(screen.getByRole('tab', { name: 'Decode' }));
    expect(within(decodePanel()).getByRole('textbox')).toHaveValue('a301616161316162016163');
    expect(within(decodePanel()).getByRole('heading', { name: 'Codec Output' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'Encode' }));
    expect(within(encodePanel()).getByRole('textbox')).toHaveValue('{"a": 1}');
  });

  it('shows Supported Inputs where the output goes until there is an answer (CX-I1, CX-I2)', () => {
    renderCodec();
    const supported = within(decodePanel()).getByRole('region', { name: 'Supported Inputs' });
    const rows = within(supported).getAllByRole('term').map((term) => term.textContent);
    expect(rows).toEqual(['JSON', 'JSON (binary)', 'CBOR', 'Binary', 'PEM', 'DER']);
    expect(supported).toHaveTextContent('CTAP getInfo response');
    expect(supported).toHaveTextContent('Certificate chains');
    expect(within(encodePanel()).queryByRole('region', { name: 'Supported Inputs', hidden: true })).toBeNull();
  });
});

describe('decoding', () => {
  it('sends the input as typed, shows progress while it runs, then the answer and a toast (CX-D4, CX-D5, CX-S7)', async () => {
    const pending = deferred<Response>();
    fetchMock.mockReturnValueOnce(pending.promise);
    renderCodec();
    await typeInto(decodePanel(), ' a301616161316162016163 ');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));

    expect(within(decodePanel()).getByRole('status')).toHaveTextContent('Decoding…');
    expect(within(decodePanel()).getByRole('button', { name: 'Decode' })).toBeDisabled();
    expect(within(decodePanel()).queryByRole('region', { name: 'Supported Inputs' })).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith('/api/codec', expect.objectContaining({ method: 'POST' }));
    expect(sentBodies()).toEqual([{ payload: ' a301616161316162016163 ', mode: 'decode' }]);

    await act(async () => pending.resolve(reply('decode-duplicate-and-colliding-keys')));
    const output = within(decodePanel()).getByRole('region', { name: 'Codec Output' });
    expect(within(output).getByText('Success')).toBeInTheDocument();
    expect(output.querySelector('[data-role="type"]')).toHaveTextContent('CBOR');
    expect(screen.getByText('Response decoded successfully!')).toBeInTheDocument();
    expect(within(decodePanel()).getByRole('button', { name: 'Decode' })).toBeEnabled();
  });

  it('sends lenient only when the switch is on (CX-D2, CX-D4)', async () => {
    fetchMock.mockImplementation(async () => reply('decode-nan-lenient'));
    renderCodec();
    const lenient = within(decodePanel()).getByRole('switch', { name: 'Best effort (lenient)' });
    expect(lenient).toHaveAccessibleDescription('read CBOR that is not well-formed as far as it goes');
    expect(lenient).toHaveAttribute('aria-checked', 'false');

    await typeInto(decodePanel(), '{"a": NaN}');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await userEvent.click(lenient);
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(sentBodies()).toEqual([
      { payload: '{"a": NaN}', mode: 'decode' },
      { payload: '{"a": NaN}', mode: 'decode', lenient: true },
    ]);
  });

  it('says a refusal in the current words, with the offset and path in their own place, and shows no answer (CX-S8, CX-S11)', async () => {
    fetchMock.mockResolvedValueOnce(reply('decode-duplicate-and-colliding-keys')).mockResolvedValueOnce(reply('decode-nan-strict'));
    renderCodec();
    await typeInto(decodePanel(), 'a301616161316162016163');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await within(decodePanel()).findByRole('region', { name: 'Codec Output' });

    await typeInto(decodePanel(), '{"a": NaN}');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    const alert = await within(decodePanel()).findByRole('alert');
    expect(alert.querySelector('[data-role="failure-text"]')).toHaveTextContent(
      `Decoding failed: ${String(RECORDED['decode-nan-strict'].answer.error)}`,
    );
    expect(alert.querySelector('[data-role="offset"]')).toHaveTextContent('6');
    expect(alert.querySelector('[data-role="path"]')).toHaveTextContent('${"a"}');
    expect(within(decodePanel()).queryByRole('region', { name: 'Codec Output' })).toBeNull();
    expect(within(decodePanel()).queryByRole('region', { name: 'Supported Inputs' })).toBeNull();
  });

  it('adds what to do for a status the server did not explain, and never shows a page of markup (CX-S9)', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<!doctype html><h1>Unavailable</h1>', { status: 503, headers: { 'Content-Type': 'text/html' } }));
    renderCodec();
    await typeInto(decodePanel(), 'a0');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    const alert = await within(decodePanel()).findByRole('alert');
    expect(alert).toHaveTextContent('Decoding failed: The server is unavailable. Try again in a moment.');
    expect(alert.querySelector('[data-role="offset"]')).toBeNull();
    expect(alert.querySelector('[data-role="path"]')).toBeNull();
  });

  it('shows only the offset or only the path when the server names one', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'EDN is not valid at offset 4: no.', offset: 4 }), { status: 422 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'Somewhere.', path: '$' }), { status: 422 }));
    renderCodec();
    await typeInto(decodePanel(), 'a0');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    let alert = await within(decodePanel()).findByRole('alert');
    expect(alert.querySelector('[data-role="offset"]')).toHaveTextContent('4');
    expect(alert.querySelector('[data-role="path"]')).toBeNull();

    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await waitFor(() => expect(within(decodePanel()).getByRole('alert')).toHaveTextContent('Somewhere.'));
    alert = within(decodePanel()).getByRole('alert');
    expect(alert.querySelector('[data-role="offset"]')).toBeNull();
    expect(alert.querySelector('[data-role="path"]')).toHaveTextContent('$');
  });

  it('says so when a success is not JSON (CX-S10)', async () => {
    fetchMock.mockResolvedValueOnce(new Response('not json', { status: 200 }));
    renderCodec();
    await typeInto(decodePanel(), 'a0');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    expect(await within(decodePanel()).findByRole('alert')).toHaveTextContent('Decoding failed: Failed to parse decoder response.');
  });

  it('refuses an empty input before asking, and keeps the last answer shown (CX-S1, CX-S6)', async () => {
    fetchMock.mockResolvedValueOnce(reply('decode-duplicate-and-colliding-keys'));
    renderCodec();
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    expect(within(decodePanel()).getByRole('alert')).toHaveTextContent('Codec input is empty. Please paste something to process.');
    expect(fetchMock).not.toHaveBeenCalled();

    await typeInto(decodePanel(), 'a301616161316162016163');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await within(decodePanel()).findByRole('region', { name: 'Codec Output' });
    await typeInto(decodePanel(), '   ');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    expect(within(decodePanel()).getByRole('alert')).toHaveTextContent('Codec input is empty.');
    expect(within(decodePanel()).getByRole('region', { name: 'Codec Output' })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('Clear empties the input and the answer, keeps the lenient switch, and drops an answer still coming (CX-L1)', async () => {
    const pending = deferred<Response>();
    fetchMock.mockResolvedValueOnce(reply('decode-duplicate-and-colliding-keys')).mockReturnValueOnce(pending.promise);
    renderCodec();
    await userEvent.click(within(decodePanel()).getByRole('switch'));
    await typeInto(decodePanel(), 'a301616161316162016163');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await within(decodePanel()).findByRole('region', { name: 'Codec Output' });

    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Clear' }));
    expect(within(decodePanel()).getByRole('textbox')).toHaveValue('');
    expect(within(decodePanel()).queryByRole('region', { name: 'Codec Output' })).toBeNull();
    expect(within(decodePanel()).getByRole('region', { name: 'Supported Inputs' })).toBeInTheDocument();
    expect(within(decodePanel()).getByRole('switch')).toHaveAttribute('aria-checked', 'true');

    await typeInto(decodePanel(), 'a0');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Clear' }));
    await act(async () => pending.resolve(reply('decode-duplicate-and-colliding-keys')));
    expect(within(decodePanel()).queryByRole('region', { name: 'Codec Output' })).toBeNull();
    expect(within(decodePanel()).getByRole('button', { name: 'Decode' })).toBeEnabled();
  });

  it('drops a refusal that arrives after Clear', async () => {
    const pending = deferred<Response>();
    fetchMock.mockReturnValueOnce(pending.promise);
    renderCodec();
    await typeInto(decodePanel(), 'a0');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Clear' }));
    await act(async () => pending.resolve(reply('decode-nan-strict')));
    expect(within(decodePanel()).queryByRole('alert')).toBeNull();
  });
});

describe('encoding', () => {
  const FORMAT_CASES = [
    ['encode-cbor', 'CBOR (canonical)'],
    ['encode-edn', 'EDN'],
    ['encode-ctap', 'CBOR (CTAP/WebAuthn Data)'],
    ['encode-json', 'JSON (binary)'],
    ['encode-der', 'DER'],
    ['encode-pem', 'PEM'],
    ['encode-cose', 'COSE'],
  ] as const;

  it('offers the seven formats, CBOR (canonical) first (CX-E1)', async () => {
    renderCodec();
    await userEvent.click(screen.getByRole('tab', { name: 'Encode' }));
    const select = within(encodePanel()).getByRole('combobox', { name: 'Encoding format' });
    expect(select).toHaveValue('CBOR (canonical)');
    expect(within(select).getAllByRole('option').map((option) => [option.getAttribute('value'), option.textContent])).toEqual([
      ['CBOR (canonical)', 'CBOR (canonical)'],
      ['EDN', 'EDN (exact bytes)'],
      ['CBOR (CTAP/WebAuthn Data)', 'CBOR (CTAP/WebAuthn Data)'],
      ['JSON (binary)', 'JSON (binary)'],
      ['DER', 'DER'],
      ['PEM', 'PEM'],
      ['COSE', 'COSE'],
    ]);
  });

  it.each(FORMAT_CASES)('encodes %s and shows every view of the bytes and their length (CX-E5, CX-C1–C3)', async (name, format) => {
    fetchMock.mockResolvedValueOnce(reply(name));
    const { request, answer } = RECORDED[name];
    renderCodec();
    await userEvent.click(screen.getByRole('tab', { name: 'Encode' }));
    await userEvent.selectOptions(within(encodePanel()).getByRole('combobox', { name: 'Encoding format' }), format);
    await typeInto(encodePanel(), String(request.payload));
    await userEvent.click(within(encodePanel()).getByRole('button', { name: 'Encode' }));

    const output = await within(encodePanel()).findByRole('region', { name: 'Codec Output' });
    expect(sentBodies()).toEqual([request]);
    expect(output.querySelector('[data-role="type"]')).toHaveTextContent(String(answer.type));
    const binary = (answer.data as { binary: Record<string, unknown> }).binary;
    const encoded = within(output).getByRole('region', { name: 'Encoded output' });
    expect(encoded.querySelector('[data-encoded="hex"] pre')).toHaveTextContent(String(binary.hex));
    expect(Array.from(encoded.querySelectorAll('[data-encoded]')).map((block) => block.getAttribute('data-encoded')).slice(0, 4)).toEqual([
      'hex',
      'base64',
      'base64url',
      'colonHex',
    ]);
    expect(encoded.querySelector('[data-role="byte-length"]')).toHaveTextContent(`Byte length: ${String(binary.length)}`);
    expect(screen.getByText('Payload encoded successfully!')).toBeInTheDocument();
  });

  it.each([
    ['', 'CBOR (canonical)', 'Encoder input is empty. Provide JSON to encode.'],
    ['{"a": ', 'CBOR (canonical)', 'Encoder expects valid JSON input.'],
    ['{"a": true}', 'PEM', 'Input cannot be converted into PEM.'],
  ])('refuses %j for %s before asking (CX-S2, CX-S4, CX-S5)', async (input, format, message) => {
    renderCodec();
    await userEvent.click(screen.getByRole('tab', { name: 'Encode' }));
    await userEvent.selectOptions(within(encodePanel()).getByRole('combobox'), format);
    await typeInto(encodePanel(), input);
    await userEvent.click(within(encodePanel()).getByRole('button', { name: 'Encode' }));
    expect(within(encodePanel()).getByRole('alert')).toHaveTextContent(message);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('says an encoding refusal as the current panel does, and Clear keeps the format (CX-S8, CX-L1)', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'EDN is not valid at offset 4: 256 does not fit.', offset: 4 }), { status: 422 }));
    renderCodec();
    await userEvent.click(screen.getByRole('tab', { name: 'Encode' }));
    await userEvent.selectOptions(within(encodePanel()).getByRole('combobox'), 'EDN');
    await typeInto(encodePanel(), '[1, 256_0]');
    await userEvent.click(within(encodePanel()).getByRole('button', { name: 'Encode' }));
    expect(await within(encodePanel()).findByRole('alert')).toHaveTextContent('Encoding failed: EDN is not valid at offset 4: 256 does not fit.');

    await userEvent.click(within(encodePanel()).getByRole('button', { name: 'Clear' }));
    expect(within(encodePanel()).queryByRole('alert')).toBeNull();
    expect(within(encodePanel()).getByRole('combobox')).toHaveValue('EDN');
  });
});

describe('the raw views', () => {
  it('open the whole answer, indented, in a dialog; ×, Escape and Raw close it, focus back on Raw (CX-R1–R3)', async () => {
    fetchMock.mockResolvedValueOnce(reply('decode-duplicate-and-colliding-keys'));
    renderCodec();
    await typeInto(decodePanel(), 'a301616161316162016163');
    await userEvent.click(within(decodePanel()).getByRole('button', { name: 'Decode' }));
    const raw = await within(decodePanel()).findByRole('button', { name: 'Raw' });
    expect(raw).toHaveAttribute('aria-haspopup', 'dialog');
    expect(raw).toHaveAttribute('aria-expanded', 'false');

    await userEvent.click(raw);
    const dialog = await screen.findByRole('dialog', { name: 'Raw Codec Output' });
    expect(dialog.querySelector('pre')!.textContent).toBe(JSON.stringify(RECORDED['decode-duplicate-and-colliding-keys'].answer, null, 2));
    expect(within(dialog).getByRole('button', { name: 'Copy Raw Codec Output' })).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: 'Show all' })).toBeNull();

    await userEvent.click(within(dialog).getByRole('button', { name: 'Close raw codec output' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() => expect(raw).toHaveFocus());

    await userEvent.click(raw);
    await screen.findByRole('dialog', { name: 'Raw Codec Output' });
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('are titled for the encoder in Encode', async () => {
    fetchMock.mockImplementation(async () => reply('encode-cbor'));
    renderCodec();
    await userEvent.click(screen.getByRole('tab', { name: 'Encode' }));
    await typeInto(encodePanel(), '{"a": 1}');
    await userEvent.click(within(encodePanel()).getByRole('button', { name: 'Encode' }));
    await userEvent.click(await within(encodePanel()).findByRole('button', { name: 'Raw' }));
    const dialog = await screen.findByRole('dialog', { name: 'Raw Encoder Output' });
    expect(within(dialog).getByRole('button', { name: 'Close raw encoder output' })).toBeInTheDocument();
  });
});
