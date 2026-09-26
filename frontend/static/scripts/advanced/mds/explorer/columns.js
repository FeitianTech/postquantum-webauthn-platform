// The explorer's column widths, for both UIs: the legacy tab's resizers
// (column-resizers.js) and web's MDS table. No DOM.

export const MDS_MIN_COLUMN_WIDTH = 64;

// Whole pixels, never under the minimum; a width that is not a positive number
// becomes the minimum.
export function normaliseExplorerColumnWidths(widths, minWidth = MDS_MIN_COLUMN_WIDTH) {
    if (!Array.isArray(widths)) {
        return [];
    }
    return widths.map(value => {
        if (!Number.isFinite(value) || value <= 0) {
            return minWidth;
        }
        return Math.max(Math.round(value), minWidth);
    });
}
