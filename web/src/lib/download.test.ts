import { downloadText, fileNameFor } from './download';

describe('saving text as a file', () => {
  it('clicks a hidden link to a Blob of the text, then lets the URL go', async () => {
    vi.useFakeTimers();
    const blobs: Blob[] = [];
    const create = vi.fn((blob: Blob) => {
      blobs.push(blob);
      return 'blob:http://localhost/1';
    });
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    let clicked: HTMLAnchorElement | null = null;
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked = this;
      expect(this.isConnected).toBe(true);
    });

    downloadText('entry.json', '{"a": 1}');

    expect(click).toHaveBeenCalledTimes(1);
    expect(clicked!.download).toBe('entry.json');
    expect(clicked!.href).toBe('blob:http://localhost/1');
    expect(clicked!.hidden).toBe(true);
    expect(clicked!.isConnected).toBe(false);
    expect(blobs[0].type).toBe('application/json');
    await expect(blobs[0].text()).resolves.toBe('{"a": 1}');
    expect(revoke).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith('blob:http://localhost/1');
    click.mockRestore();
  });

  it('names a file after an id a file system would refuse', () => {
    expect(fileNameFor('aaguid:f1d0f1d0-0000-4000-8000-000000000001', 'json')).toBe('aaguid-f1d0f1d0-0000-4000-8000-000000000001.json');
    expect(fileNameFor('aaid:F1D0#0012', 'json')).toBe('aaid-F1D0-0012.json');
    expect(fileNameFor(':#/', 'json')).toBe('download.json');
  });
});
