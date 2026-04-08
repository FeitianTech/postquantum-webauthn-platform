export function renderMdsTable(state, entries, options = {}, deps = {}) {
    if (!state?.tableBody) {
        return;
    }

    const {
        COLUMN_COUNT,
        normaliseAaguid,
        createIconCell,
        createNameCell,
        createTextCell,
        createIdCell,
        createTagCell,
        hideScrollTopButton,
        stabiliseColumnWidths,
        scheduleColumnResizerMetricsUpdate,
        resetScrollPositions,
        scheduleHorizontalScrollMetricsUpdate,
        applyRowHighlightByKey,
        scheduleScrollTopButtonUpdate,
        scheduleRowHeightLock,
    } = deps;

    const { preserveTableScroll = false } = options;
    const container =
        state.tableContainer instanceof HTMLElement ? state.tableContainer : null;
    const horizontal =
        state.horizontalScrollContainer instanceof HTMLElement ? state.horizontalScrollContainer : null;

    let preservedScroll = null;
    if (preserveTableScroll && container) {
        const left = Number.isFinite(container.scrollLeft) ? container.scrollLeft : null;
        const top = Number.isFinite(container.scrollTop) ? container.scrollTop : null;
        if (left !== null || top !== null) {
            preservedScroll = { left, top };
        }
    }

    const adjustScrollPosition = () => {
        if (!container) {
            return;
        }
        if (preservedScroll) {
            const restore = () => {
                if (typeof preservedScroll.left === 'number') {
                    container.scrollLeft = preservedScroll.left;
                    if (horizontal) {
                        horizontal.scrollLeft = preservedScroll.left;
                    }
                }
                if (typeof preservedScroll.top === 'number') {
                    container.scrollTop = preservedScroll.top;
                }
            };
            restore();
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(restore);
            }
            return;
        }
        resetScrollPositions(container, horizontal);
    };

    const tbody = state.tableBody;
    tbody.innerHTML = '';

    if (!entries.length) {
        const emptyRow = document.createElement('tr');
        emptyRow.className = 'mds-empty-row';
        const cell = document.createElement('td');
        cell.colSpan = COLUMN_COUNT;
        cell.textContent = 'No authenticators match the selected filters.';
        emptyRow.appendChild(cell);
        tbody.appendChild(emptyRow);
        hideScrollTopButton();
        stabiliseColumnWidths();
        scheduleColumnResizerMetricsUpdate();
        adjustScrollPosition();
        scheduleHorizontalScrollMetricsUpdate();
        return;
    }

    const fragment = document.createDocumentFragment();

    entries.forEach(entry => {
        const row = document.createElement('tr');

        if (typeof entry.index === 'number' && Number.isFinite(entry.index)) {
            row.dataset.entryIndex = String(entry.index);
        }
        const aaguidKey = normaliseAaguid(entry.aaguid);
        if (aaguidKey) {
            row.dataset.aaguid = aaguidKey;
        } else if (entry.id) {
            const idKey = normaliseAaguid(entry.id);
            if (idKey) {
                row.dataset.aaguid = idKey;
            } else {
                row.dataset.entryId = entry.id;
            }
        }

        row.appendChild(createIconCell(entry));
        row.appendChild(createNameCell(entry));
        row.appendChild(createTextCell(entry.protocol || '—'));
        row.appendChild(createTextCell(entry.certification || '—'));
        row.appendChild(createIdCell(entry.id));
        row.appendChild(createTagCell(entry.userVerificationList));
        row.appendChild(createTagCell(entry.attachmentList));
        row.appendChild(createTagCell(entry.transportsList));
        row.appendChild(createTagCell(entry.keyProtectionList));
        row.appendChild(createTagCell(entry.algorithmsList));
        row.appendChild(createTagCell(entry.certificateAlgorithmInfoList));
        row.appendChild(createTagCell(entry.certificateCommonNameList));
        row.appendChild(createTextCell(entry.dateUpdated || '—', entry.dateTooltip));

        fragment.appendChild(row);
    });

    tbody.appendChild(fragment);
    adjustScrollPosition();
    if (state.highlightedRowKey) {
        const restored = applyRowHighlightByKey(state.highlightedRowKey, { scroll: false });
        if (!restored) {
            state.highlightedRow = null;
        }
    }
    stabiliseColumnWidths();
    scheduleScrollTopButtonUpdate();
    scheduleHorizontalScrollMetricsUpdate();
    scheduleColumnResizerMetricsUpdate();
    scheduleRowHeightLock();
}
