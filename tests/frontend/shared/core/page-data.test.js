import { afterEach, describe, expect, it, vi } from 'vitest';

import { readPageData } from '../../../../frontend/static/scripts/shared/utils/page-data.js';

afterEach(() => {
  document.head.replaceChildren();
});

function block(id, text, type = 'application/json') {
  const element = document.createElement('script');
  if (type !== null) {
    element.type = type;
  }
  element.id = id;
  element.textContent = text;
  document.head.appendChild(element);
  return element;
}

describe('readPageData', () => {
  it('parses the JSON of the block with that id, as tojson escapes it', () => {
    block('test-data', '{"legalHeader": "a \\u003c/script\\u003e \\u0026 \\u0027b\\u0027", "entryCount": 3}');

    expect(readPageData('test-data')).toEqual({ legalHeader: "a </script> & 'b'", entryCount: 3 });
  });

  it('gives null when there is no such block', () => {
    expect(readPageData('no-such-data')).toBeNull();
  });

  it('reads only a JSON script block', () => {
    // A block without the JSON type would run (jsdom runs scripts here), so it holds
    // a number that is valid code as well as JSON.
    block('as-code', '1', null);
    block('as-text', '{"a": 1}', 'text/plain');
    const div = document.createElement('div');
    div.id = 'as-div';
    div.textContent = '{"a": 1}';
    document.body.appendChild(div);

    expect(readPageData('as-code')).toBeNull();
    expect(readPageData('as-text')).toBeNull();
    expect(readPageData('as-div')).toBeNull();
  });

  it('gives null and says so when the block is not JSON', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    block('broken', '{"a": NaN}');

    expect(readPageData('broken')).toBeNull();
    expect(error).toHaveBeenCalledWith('The page\'s "broken" data is not JSON.', expect.any(SyntaxError));
    error.mockRestore();
  });

  it('keeps a JSON null or list as it is', () => {
    block('nothing', 'null');
    block('list', '[{"a": 1}, null, "x"]');

    expect(readPageData('nothing')).toBeNull();
    expect(readPageData('list')).toEqual([{ a: 1 }, null, 'x']);
  });
});
