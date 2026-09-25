// Data the server renders into the page for its scripts: a
// <script type="application/json" id="..."> block. The browser never runs one,
// so the CSP's script-src has nothing to allow, and a module parses it when it
// loads. Jinja's tojson escapes <, > and &, so the block cannot close early.

/** The parsed JSON of the page's data block with this id, or null. */
export function readPageData(id) {
    if (typeof document === 'undefined') {
        return null;
    }
    const block = document.getElementById(id);
    if (!(block instanceof HTMLScriptElement) || block.type !== 'application/json') {
        return null;
    }
    try {
        return JSON.parse(block.textContent);
    } catch (error) {
        console.error(`The page's "${id}" data is not JSON.`, error);
        return null;
    }
}
