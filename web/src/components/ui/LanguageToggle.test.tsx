import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { LanguageToggle } from './LanguageToggle';

describe('the language toggle', () => {
  it('reads the language shown, and its name says which way it switches', () => {
    const { rerender } = render(<LanguageToggle language="en" onToggle={() => {}} />);
    expect(screen.getByRole('button', { name: 'ENG, show in Chinese' })).toHaveTextContent('ENG');

    rerender(<LanguageToggle language="zh" onToggle={() => {}} />);
    expect(screen.getByRole('button', { name: '中, show in English' })).toHaveTextContent('中');
  });

  it('asks its parent to switch, and sits where its parent places it', async () => {
    const onToggle = vi.fn();
    render(<LanguageToggle language="en" onToggle={onToggle} className="absolute right-3" />);
    const toggle = screen.getByRole('button', { name: 'ENG, show in Chinese' });
    expect(toggle.className).toContain('absolute right-3');

    await userEvent.click(toggle);
    expect(onToggle).toHaveBeenCalledOnce();
  });
});
