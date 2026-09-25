import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';

import { SegmentedControl, segmentIds } from './SegmentedControl';

const OPTIONS = [
  { value: 'simple', label: 'Simple Authentication' },
  { value: 'advanced', label: 'Advanced Authentication' },
  { value: 'codec', label: 'Codec' },
  { value: 'mds', label: 'FIDO MDS Authenticators' },
] as const;
type Section = (typeof OPTIONS)[number]['value'];

// jsdom has no layout: give each tab a position from its id.
const LAYOUT: Record<string, { left: number; width: number }> = {
  simple: { left: 3, width: 170 },
  advanced: { left: 175, width: 190 },
  codec: { left: 367, width: 70 },
  mds: { left: 439, width: 200 },
};

function layoutOf(element: HTMLElement) {
  const value = element.id?.replace('nav-tab-', '');
  return LAYOUT[value] ?? { left: 0, width: 0 };
}

let observers: Array<() => void> = [];

beforeEach(() => {
  observers = [];
  vi.spyOn(HTMLElement.prototype, 'offsetLeft', 'get').mockImplementation(function (this: HTMLElement) {
    return layoutOf(this).left;
  });
  vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(function (this: HTMLElement) {
    return layoutOf(this).width;
  });
  vi.stubGlobal(
    'ResizeObserver',
    class {
      constructor(callback: () => void) {
        observers.push(callback);
      }
      observe() {}
      disconnect() {}
    },
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function Harness({ initial = 'simple', onChange }: { initial?: Section; onChange?: (value: Section) => void }) {
  const [value, setValue] = useState<Section>(initial);
  return (
    <>
      <SegmentedControl
        label="Sections"
        idBase="nav"
        options={OPTIONS}
        value={value}
        onChange={(next) => {
          setValue(next);
          onChange?.(next);
        }}
      />
      <button type="button" onClick={() => setValue('mds')}>
        from outside
      </button>
    </>
  );
}

const highlight = () => document.querySelector<HTMLElement>('[data-segment-highlight]')!;

function recordInstant() {
  const records: string[] = [];
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) records.push(mutation.attributeName ?? '');
  });
  observer.observe(highlight(), { attributes: true, attributeFilter: ['data-instant'] });
  return { records, stop: () => observer.disconnect() };
}

describe('SegmentedControl', () => {
  it('is a labelled tab list whose tabs control their panels', () => {
    render(<Harness />);

    expect(screen.getByRole('tablist', { name: 'Sections' })).toHaveAttribute('data-segmented');
    const tabs = screen.getAllByRole('tab');
    expect(tabs.map((tab) => tab.textContent?.length && tab.getAttribute('aria-selected'))).toEqual([
      'true',
      'false',
      'false',
      'false',
    ]);
    expect(screen.getByRole('tab', { name: 'Codec' })).toHaveAttribute('aria-controls', segmentIds('nav', 'codec').panel);
    expect(screen.getByRole('tab', { name: 'Codec' })).toHaveAttribute('id', 'nav-tab-codec');
    expect(tabs.map((tab) => tab.tabIndex)).toEqual([0, -1, -1, -1]);
  });

  it('places the one highlight on the chosen tab, without sliding the first time', () => {
    render(<Harness initial="advanced" />);

    expect(highlight().style.width).toBe('190px');
    expect(highlight().style.transform).toBe('translateX(175px)');
    expect(highlight()).toHaveAttribute('data-ready');
    expect(highlight()).not.toHaveAttribute('data-instant');
    expect(screen.getByRole('tablist')).toHaveAttribute('data-ready');
    expect(document.querySelectorAll('[data-segment-highlight]')).toHaveLength(1);
  });

  it('slides the highlight to a tab chosen by click', async () => {
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    const instant = recordInstant();

    await userEvent.click(screen.getByRole('tab', { name: 'Codec' }));
    await Promise.resolve();

    expect(onChange).toHaveBeenCalledWith('codec');
    expect(screen.getByRole('tab', { name: 'Codec' })).toHaveAttribute('aria-selected', 'true');
    expect(highlight().style.transform).toBe('translateX(367px)');
    expect(highlight().style.width).toBe('70px');
    expect(instant.records).toEqual([]);
    instant.stop();
  });

  it('does not report a click on the tab already chosen', async () => {
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    await userEvent.click(screen.getByRole('tab', { name: 'Simple Authentication' }));
    expect(onChange).not.toHaveBeenCalled();
  });

  it('jumps rather than slides when the value changes from outside, or the list resizes', async () => {
    render(<Harness />);
    const instant = recordInstant();

    await userEvent.click(screen.getByRole('button', { name: 'from outside' }));
    await Promise.resolve();
    expect(highlight().style.transform).toBe('translateX(439px)');
    expect(instant.records.length).toBeGreaterThan(0);

    LAYOUT.mds = { left: 500, width: 210 };
    act(() => observers.forEach((callback) => callback()));
    expect(highlight().style.transform).toBe('translateX(500px)');
    expect(highlight().style.width).toBe('210px');
    LAYOUT.mds = { left: 439, width: 200 };
    instant.stop();
  });

  it('moves with the arrow keys, Home and End, wrapping at the ends, and takes focus with it', async () => {
    render(<Harness />);
    screen.getByRole('tab', { name: 'Simple Authentication' }).focus();

    await userEvent.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: 'Advanced Authentication' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: 'Advanced Authentication' })).toHaveFocus();

    await userEvent.keyboard('{End}');
    expect(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' })).toHaveFocus();
    await userEvent.keyboard('{ArrowDown}');
    expect(screen.getByRole('tab', { name: 'Simple Authentication' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.keyboard('{ArrowLeft}');
    expect(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.keyboard('{Home}');
    expect(screen.getByRole('tab', { name: 'Simple Authentication' })).toHaveFocus();
    await userEvent.keyboard('{ArrowUp}');
    expect(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.keyboard('a');
    expect(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' })).toHaveAttribute('aria-selected', 'true');
  });

  it('keeps each tab as wide as its bold selected state, and does not slide under reduced motion', () => {
    render(<Harness />);
    const tab = screen.getByRole('tab', { name: 'Codec' });

    expect(tab.querySelectorAll('span[aria-hidden="true"].font-semibold')).toHaveLength(1);
    expect(highlight().className).toContain('motion-reduce:transition-none');
    expect(highlight().className).toContain('data-instant:transition-none');
  });

  it('has a smaller size for switches inside a page', () => {
    render(
      <SegmentedControl
        label="Mode"
        idBase="mode"
        size="sm"
        options={[
          { value: 'decode', label: 'Decode' },
          { value: 'encode', label: 'Encode' },
        ]}
        value="decode"
        onChange={() => {}}
      />,
    );
    expect(screen.getByRole('tab', { name: 'Decode' }).className).toContain('h-7');
  });
});
