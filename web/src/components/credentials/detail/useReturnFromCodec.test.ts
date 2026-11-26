// Back from the Codec puts the "Decode in Codec" button where it sat in the
// details' view, and keeps it there when the level's late parts arrive, however
// late, until the person moves the view or leaves the level.
import { renderHook } from '@testing-library/react';

import { useReturnFromCodec } from './useReturnFromCodec';

// jsdom has no layout: the button sits `top` pixels down the level, and the view
// shows the level from its scrollTop on.
function details() {
  const scroller = document.createElement('div');
  scroller.setAttribute('data-overlay-scroll', '');
  scroller.innerHTML = '<div><div data-level="registration"><button data-decode="attestation object"></button></div></div>';
  document.body.append(scroller);
  const levels = scroller.firstElementChild as HTMLElement;
  const button = scroller.querySelector('button')!;
  const layout = { top: 500 };
  scroller.getBoundingClientRect = () => ({ top: 0, height: 0 }) as DOMRect;
  button.getBoundingClientRect = () => ({ top: layout.top - scroller.scrollTop }) as DOMRect;
  return { scroller, levels, button, layout, place: () => layout.top - scroller.scrollTop };
}

// The observers live, and a size change of what they observe, as a browser
// reports it at its next rendering step.
const observers = new Set<() => void>();
const resized = () => observers.forEach((report) => report());

beforeEach(() => {
  vi.useFakeTimers();
  window.location.hash = '#simple/credential/key/registration';
  vi.stubGlobal(
    'ResizeObserver',
    class {
      report: () => void;
      constructor(report: () => void) {
        this.report = report;
      }
      observe() {
        observers.add(this.report);
      }
      disconnect() {
        observers.delete(this.report);
      }
    },
  );
});

afterEach(() => {
  observers.clear();
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

// Leaves for the Codec from 200 px down the view, and comes back: the overlay
// opens at the top and focuses what the hook gives it.
function leaveAndReturn() {
  const shown = details();
  shown.scroller.scrollTop = 300;
  const leaving = renderHook(() => useReturnFromCodec({ current: shown.levels }, 'registration'));
  leaving.result.current.leave('attestation object', shown.button);
  leaving.unmount();

  shown.scroller.scrollTop = 0;
  const back = renderHook(() => useReturnFromCodec({ current: shown.levels }, 'registration'));
  back.result.current.initialFocus()?.focus({ preventScroll: true });
  return shown;
}

describe('Back from the Codec', () => {
  it('puts the button back at its place, and keeps it there when the level\'s parts arrive seconds later', () => {
    const shown = leaveAndReturn();
    expect(shown.place()).toBe(200);
    expect(shown.button).toHaveFocus();

    vi.advanceTimersByTime(5000);
    shown.layout.top += 24;
    resized();

    expect(shown.place()).toBe(200);
  });

  it('leaves the view where the person moved it', () => {
    const shown = leaveAndReturn();
    shown.scroller.dispatchEvent(new WheelEvent('wheel'));
    shown.scroller.scrollTop = 100;
    shown.layout.top += 24;
    resized();

    expect(shown.place()).toBe(424);
  });

  it('stops keeping the place once the person has gone to another level', () => {
    const shown = leaveAndReturn();
    shown.levels.querySelector('[data-level]')!.setAttribute('hidden', '');
    shown.layout.top += 24;
    resized();

    expect(shown.place()).toBe(224);
    expect(observers.size).toBe(0);
  });

  it('stops keeping the place once the details have closed', () => {
    const shown = leaveAndReturn();
    shown.scroller.remove();
    resized();

    expect(observers.size).toBe(0);
  });
});
