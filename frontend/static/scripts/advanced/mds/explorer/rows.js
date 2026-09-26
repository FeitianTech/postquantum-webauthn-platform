// What the explorer's table cells show beyond an entry's own text, for both UIs:
// the legacy tab (table-render.js, table-cells.js) and web's MDS table. No DOM.

export const MISSING_CELL_TEXT = '—';
export const NO_ICON_TEXT = 'N/A';

export function iconAltText(entry) {
    return `${entry?.name || 'Authenticator'} icon`;
}
