import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { renderApp } from '@/test/app';

const { gather } = vi.hoisted(() => ({ gather: vi.fn() }));

vi.mock('@/logic/browser/report.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('@/logic/browser/report.js')>();
  gather.mockImplementation(original.gatherAnalysis);
  return { ...original, gatherAnalysis: gather };
});

describe('when the analysis fails', () => {
  it('does not open, enables the trigger again, and asks again on the next click', async () => {
    gather.mockRejectedValueOnce(new Error('the browser threw'));
    renderApp();
    const trigger = screen.getByRole('button', { name: 'Analyze Browser' });

    await userEvent.click(trigger);
    await waitFor(() => expect(trigger).toBeEnabled());
    expect(screen.queryByRole('dialog', { name: 'Browser Analysis' })).toBeNull();

    await userEvent.click(trigger);
    expect(await screen.findByRole('dialog', { name: 'Browser Analysis' })).toBeInTheDocument();
    expect(gather).toHaveBeenCalledTimes(2);
  });
});
