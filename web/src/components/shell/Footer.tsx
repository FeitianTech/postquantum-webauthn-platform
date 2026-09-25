// The footer as the current UI has it (frontend/templates/index.html). The year
// is kept current by tools/update_footer_year.py, which edits this file too.
export function Footer() {
  return (
    <footer className="mx-auto flex w-full max-w-page flex-wrap gap-x-6 gap-y-1 border-t border-line px-4 pt-5 pb-8 text-caption text-ink-muted sm:px-6 lg:px-8">
      <p>© 2026 Feitian Technologies Co., Ltd. All rights reserved.</p>
      <p>
        This is an independent testing platform and is{' '}
        <strong className="font-semibold text-ink">not affiliated with or endorsed by</strong> the FIDO Alliance,
        W3C, or Open Quantum Safe.
      </p>
    </footer>
  );
}
