// Saves text as a file: a Blob behind a temporary <a download>, its URL
// released once the click has been handled. Nothing is parsed as markup, and a
// download is not a navigation the Content-Security-Policy governs.
export function downloadText(filename: string, text: string, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

// A name a file system takes for an id such as "aaid:F1D0#0012".
export function fileNameFor(id: string, extension: string) {
  const stem = id.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'download';
  return `${stem}.${extension}`;
}
