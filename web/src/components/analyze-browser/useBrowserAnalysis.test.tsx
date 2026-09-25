import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AppShell } from '@/components/shell/AppShell';
import { renderPage } from '@/test/page';

const { gather } = vi.hoisted(() => ({ gather: vi.fn() }));

vi.mock('@legacy/shared/browser/report.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('@legacy/shared/browser/report.js')>();
  gather.mockImplementation(original.gatherAnalysis);
  return { ...original, gatherAnalysis: gather };
});

describe('when the analysis fails', () => {
  it('does not open, enables the trigger again, and asks again on the next click (AB-T5)', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    gather.mockRejectedValueOnce(new Error('the browser threw'));
    renderPage(<AppShell />);
    const trigger = screen.getByRole('button', { name: 'Analyze Browser' });

    await userEvent.click(trigger);
    await waitFor(() => expect(trigger).toBeEnabled());
    expect(screen.queryByRole('dialog', { name: 'Browser Analysis' })).toBeNull();
    expect(error).toHaveBeenCalledWith('Analyze Browser could not gather its findings.', expect.any(Error));

    await userEvent.click(trigger);
    expect(await screen.findByRole('dialog', { name: 'Browser Analysis' })).toBeInTheDocument();
    expect(gather).toHaveBeenCalledTimes(2);
  });
});
