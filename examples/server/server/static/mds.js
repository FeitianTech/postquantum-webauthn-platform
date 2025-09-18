const MDS_HTML_PATH = 'mds.html';
const MDS_JWS_PATH = 'fido-mds3.jws';
const COLUMN_COUNT = 11;

const FILTER_CONFIG = [
    { key: 'name', inputId: 'mds-filter-name' },
    { key: 'protocol', inputId: 'mds-filter-protocol', datalistId: 'mds-options-protocol' },
    { key: 'certification', inputId: 'mds-filter-certification', datalistId: 'mds-options-certification' },
    { key: 'id', inputId: 'mds-filter-id' },
    { key: 'userVerification', inputId: 'mds-filter-user-verification', datalistId: 'mds-options-user-verification' },
    { key: 'attachment', inputId: 'mds-filter-attachment', datalistId: 'mds-options-attachment' },
    { key: 'transports', inputId: 'mds-filter-transports', datalistId: 'mds-options-transports' },
    { key: 'keyProtection', inputId: 'mds-filter-key-protection', datalistId: 'mds-options-key-protection' },
    { key: 'algorithms', inputId: 'mds-filter-algorithms', datalistId: 'mds-options-algorithms' },
];

let mdsState = null;
let mdsData = [];
let filteredData = [];
let isLoading = false;
let hasLoaded = false;

document.addEventListener('DOMContentLoaded', async () => {
    const tabElement = document.getElementById('mds-tab');
    if (!tabElement) {
        return;
    }

    try {
        const response = await fetch(MDS_HTML_PATH, { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(`Unable to load ${MDS_HTML_PATH}`);
        }
        const markup = await response.text();
        tabElement.innerHTML = markup;
        mdsState = initializeState(tabElement);
    } catch (error) {
        console.error('Failed to initialise the FIDO MDS tab:', error);
        tabElement.innerHTML = `
            <div class="section mds-section">
                <div class="mds-status mds-status-error">Unable to load authenticator explorer. Check the console for details.</div>
            </div>`;
        return;
    }

    if (tabElement.classList.contains('active')) {
        void loadMdsData();
    }
});

document.addEventListener('tab:changed', event => {
    if (event?.detail?.tab === 'mds') {
        void loadMdsData();
    }
});

function initializeState(root) {
    const filters = {};
    const filterInputs = {};
    const datalists = {};

    FILTER_CONFIG.forEach(config => {
        const input = root.querySelector(`#${config.inputId}`);
        if (input) {
            filters[config.key] = '';
            filterInputs[config.key] = input;
        }
        if (config.datalistId) {
            const datalist = root.querySelector(`#${config.datalistId}`);
            if (datalist) {
                datalists[config.key] = datalist;
            }
        }
    });

    const updateFilter = (key, rawValue) => {
        if (!mdsState) {
            return;
        }
        const value = rawValue.trim();
        if (filters[key] === value) {
            return;
        }
        filters[key] = value;
        applyFilters();
    };

    Object.entries(filterInputs).forEach(([key, input]) => {
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                updateFilter(key, event.target.value);
            }
            if (event.key === 'Escape') {
                event.target.value = '';
                updateFilter(key, '');
            }
        });

        input.addEventListener('change', event => {
            updateFilter(key, event.target.value);
        });

        input.addEventListener('input', event => {
            if (!event.target.value.trim() && filters[key]) {
                updateFilter(key, '');
            }
        });
    });

    return {
        root,
        filters,
        filterInputs,
        datalists,
        tableBody: root.querySelector('#mds-table-body'),
        countEl: root.querySelector('#mds-entry-count'),
        totalEl: root.querySelector('#mds-total-count'),
        statusEl: root.querySelector('#mds-status'),
    };
}

async function loadMdsData() {
    if (isLoading || hasLoaded || !mdsState) {
        return;
    }

    isLoading = true;
    setStatus('Loading metadata BLOB…', 'info');

    try {
        const response = await fetch(MDS_JWS_PATH, { cache: 'no-store' });
        if (!response.ok) {
            if (response.status === 404) {
                setStatus(
                    `Metadata file not found. Download the latest BLOB from ` +
                        `<a href="https://mds3.fidoalliance.org/" target="_blank" rel="noopener">mds3.fidoalliance.org</a> ` +
                        `and save it as <code>${MDS_JWS_PATH}</code> in this directory.`,
                    'error',
                );
                return;
            }
            throw new Error(`Unexpected response status: ${response.status}`);
        }

        const jws = await response.text();
        const payloadSegment = jws.split('.')[1];
        if (!payloadSegment) {
            throw new Error('Invalid metadata BLOB format.');
        }

        const payload = decodeBase64Url(payloadSegment);
        const metadata = JSON.parse(payload);

        mdsData = Array.isArray(metadata.entries)
            ? metadata.entries.map(transformEntry).filter(Boolean)
            : [];
        hasLoaded = true;

        const optionSets = collectOptionSets(mdsData);
        updateOptionLists(optionSets);
        applyFilters();

        const nextUpdate = metadata.nextUpdate ? `Next update: ${formatDate(metadata.nextUpdate)}` : '';
        const statusMessage = [`Loaded ${mdsData.length.toLocaleString()} authenticators.`];
        if (nextUpdate) {
            statusMessage.push(nextUpdate);
        }
        setStatus(statusMessage.join(' '), 'success');

        if (metadata.legalHeader && mdsState.statusEl) {
            mdsState.statusEl.setAttribute('title', metadata.legalHeader);
        }
    } catch (error) {
        console.error('Failed to load FIDO MDS metadata:', error);
        setStatus(
            `Unable to parse the metadata BLOB. Confirm that <code>${MDS_JWS_PATH}</code> is a valid download from ` +
                `<a href="https://mds3.fidoalliance.org/" target="_blank" rel="noopener">mds3.fidoalliance.org</a>.`,
            'error',
        );
    } finally {
        isLoading = false;
    }
}

function applyFilters() {
    if (!mdsState) {
        return;
    }

    const activeFilters = mdsState.filters;
    filteredData = mdsData.filter(entry => matchesFilters(entry, activeFilters));
    renderTable(filteredData);
    updateCount(filteredData.length, mdsData.length);
}

function matchesFilters(entry, filters) {
    return Object.entries(filters).every(([key, value]) => {
        if (!value) {
            return true;
        }
        const haystack = (entry[key] || '').toLowerCase();
        return haystack.includes(value.toLowerCase());
    });
}

function renderTable(entries) {
    if (!mdsState?.tableBody) {
        return;
    }

    const tbody = mdsState.tableBody;
    tbody.innerHTML = '';

    if (!entries.length) {
        const emptyRow = document.createElement('tr');
        emptyRow.className = 'mds-empty-row';
        const cell = document.createElement('td');
        cell.colSpan = COLUMN_COUNT;
        cell.textContent = 'No authenticators match the selected filters.';
        emptyRow.appendChild(cell);
        tbody.appendChild(emptyRow);
        return;
    }

    const fragment = document.createDocumentFragment();

    entries.forEach(entry => {
        const row = document.createElement('tr');

        row.appendChild(createTextCell(entry.name || '—'));
        row.appendChild(createTextCell(entry.protocol || '—'));
        row.appendChild(createIconCell(entry));
        row.appendChild(createTextCell(entry.certification || '—'));
        row.appendChild(createIdCell(entry.id));
        row.appendChild(createTagCell(entry.userVerificationList));
        row.appendChild(createTagCell(entry.attachmentList));
        row.appendChild(createTagCell(entry.transportsList));
        row.appendChild(createTagCell(entry.keyProtectionList));
        row.appendChild(createTagCell(entry.algorithmsList, true));
        row.appendChild(createTextCell(entry.dateUpdated || '—', entry.dateTooltip));

        fragment.appendChild(row);
    });

    tbody.appendChild(fragment);
}

function createTextCell(text, title) {
    const cell = document.createElement('td');
    cell.textContent = text;
    if (title) {
        cell.title = title;
    }
    return cell;
}

function createIdCell(id) {
    const cell = createTextCell(id || '—');
    cell.classList.add('mds-cell-id');
    return cell;
}

function createIconCell(entry) {
    const cell = document.createElement('td');
    const wrapper = document.createElement('div');
    wrapper.className = 'mds-icon-wrapper';

    if (entry.icon) {
        const img = document.createElement('img');
        img.src = entry.icon;
        img.alt = `${entry.name || 'Authenticator'} icon`;
        wrapper.appendChild(img);
    } else {
        const placeholder = document.createElement('span');
        placeholder.className = 'mds-icon-placeholder';
        placeholder.textContent = 'N/A';
        wrapper.appendChild(placeholder);
    }

    cell.appendChild(wrapper);
    return cell;
}

function createTagCell(items, neutral = false) {
    const cell = document.createElement('td');
    const values = Array.isArray(items) ? items : [];

    if (!values.length) {
        cell.textContent = '—';
        return cell;
    }

    const group = document.createElement('div');
    group.className = 'mds-tag-group';

    values.forEach(value => {
        const tag = document.createElement('span');
        tag.className = neutral ? 'mds-tag mds-tag--neutral' : 'mds-tag';
        tag.textContent = value;
        group.appendChild(tag);
    });

    cell.appendChild(group);
    return cell;
}

function updateCount(filtered, total) {
    if (mdsState?.countEl) {
        mdsState.countEl.textContent = filtered.toLocaleString();
    }
    if (mdsState?.totalEl) {
        mdsState.totalEl.textContent = total ? `of ${total.toLocaleString()} authenticators` : '';
    }
}

function setStatus(message, variant) {
    if (!mdsState?.statusEl) {
        return;
    }

    const statusEl = mdsState.statusEl;
    statusEl.classList.remove('mds-status-info', 'mds-status-success', 'mds-status-error');
    statusEl.classList.add(`mds-status-${variant}`);
    statusEl.innerHTML = message;
}

function collectOptionSets(data) {
    const sets = {
        protocol: new Set(),
        certification: new Set(),
        userVerification: new Set(),
        attachment: new Set(),
        transports: new Set(),
        keyProtection: new Set(),
        algorithms: new Set(),
    };

    data.forEach(entry => {
        if (entry.protocol) {
            sets.protocol.add(entry.protocol);
        }
        if (entry.certification) {
            sets.certification.add(entry.certification);
        }
        entry.userVerificationList.forEach(value => sets.userVerification.add(value));
        entry.attachmentList.forEach(value => sets.attachment.add(value));
        entry.transportsList.forEach(value => sets.transports.add(value));
        entry.keyProtectionList.forEach(value => sets.keyProtection.add(value));
        entry.algorithmsList.forEach(value => sets.algorithms.add(value));
    });

    return sets;
}

function updateOptionLists(optionSets) {
    if (!mdsState) {
        return;
    }

    Object.entries(optionSets).forEach(([key, values]) => {
        const datalist = mdsState.datalists[key];
        if (!datalist) {
            return;
        }
        datalist.innerHTML = '';
        Array.from(values)
            .filter(Boolean)
            .sort((a, b) => a.localeCompare(b))
            .forEach(value => {
                const option = document.createElement('option');
                option.value = value;
                datalist.appendChild(option);
            });
    });
}

function transformEntry(entry) {
    const metadata = entry?.metadataStatement ?? {};
    const name = resolveName(metadata, entry);
    const protocol = formatProtocol(metadata.protocolFamily || metadata.protocolType);
    const certification = formatCertification(entry?.statusReports || []);
    const identifier = resolveIdentifier(entry, metadata);
    const userVerificationList = extractUserVerification(metadata.userVerificationDetails);
    const attachmentList = extractList(metadata.attachmentHint).map(formatEnum);
    const transportsList = extractTransports(metadata);
    const keyProtectionList = extractList(metadata.keyProtection).map(formatEnum);
    const algorithmsList = extractList(metadata.authenticationAlgorithms).map(formatEnum);
    const icon = metadata.icon ? `data:image/png;base64,${metadata.icon}` : '';

    const latestStatusDate = latestEffectiveDate(entry?.statusReports || []);
    const rawDate = entry?.timeOfLastStatusChange || latestStatusDate;
    const dateUpdated = rawDate ? formatDate(rawDate) : '';

    return {
        name,
        protocol,
        certification,
        id: identifier,
        icon,
        userVerification: userVerificationList.join(', '),
        userVerificationList,
        attachment: attachmentList.join(', '),
        attachmentList,
        transports: transportsList.join(', '),
        transportsList,
        keyProtection: keyProtectionList.join(', '),
        keyProtectionList,
        algorithms: algorithmsList.join(', '),
        algorithmsList,
        dateUpdated,
        dateTooltip: rawDate || undefined,
    };
}

function resolveName(metadata, entry) {
    const description = metadata.description;
    if (typeof description === 'string' && description.trim()) {
        return description.trim();
    }
    if (description && typeof description === 'object') {
        const values = Object.values(description).filter(Boolean);
        if (values.length) {
            return String(values[0]).trim();
        }
    }
    const altDescriptions = metadata.alternativeDescriptions;
    if (altDescriptions) {
        const altValues = typeof altDescriptions === 'object' ? Object.values(altDescriptions) : [];
        const candidate = altValues.find(value => typeof value === 'string' && value.trim());
        if (candidate) {
            return candidate.trim();
        }
    }
    const statusDescriptor = entry?.statusReports?.find(report => report.certificationDescriptor)?.certificationDescriptor;
    if (statusDescriptor) {
        return statusDescriptor;
    }
    return 'Unknown Authenticator';
}

function resolveIdentifier(entry, metadata) {
    if (entry?.aaguid) {
        return entry.aaguid;
    }
    if (metadata?.aaguid) {
        return metadata.aaguid;
    }
    if (metadata?.aaid) {
        return metadata.aaid;
    }
    const attestKeyIds = extractList(metadata?.attestationCertificateKeyIdentifiers);
    if (attestKeyIds.length) {
        return attestKeyIds[0];
    }
    return '—';
}

function extractUserVerification(details) {
    const values = new Set();
    if (Array.isArray(details)) {
        details.forEach(group => {
            if (Array.isArray(group)) {
                group.forEach(entry => {
                    if (entry && entry.userVerificationMethod) {
                        values.add(formatEnum(entry.userVerificationMethod));
                    }
                });
            }
        });
    }
    return Array.from(values).sort((a, b) => a.localeCompare(b));
}

function extractTransports(metadata) {
    const infoTransports = extractList(metadata?.authenticatorGetInfo?.transports);
    const metadataTransports = extractList(metadata?.transports);
    const combined = new Set([
        ...infoTransports.map(formatEnum),
        ...metadataTransports.map(formatEnum),
    ]);
    return Array.from(combined).sort((a, b) => a.localeCompare(b));
}

function extractList(value) {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    return [value];
}

function formatProtocol(protocol) {
    if (!protocol) {
        return '';
    }
    const normalised = formatEnum(protocol);
    if (/^fido\s*\d$/i.test(normalised.replace(/\s+/g, ''))) {
        return normalised.replace(/\s+/g, '');
    }
    return normalised;
}

function formatEnum(value) {
    if (!value && value !== 0) {
        return '';
    }
    return String(value)
        .split(/[_-]/)
        .filter(Boolean)
        .map(part => {
            if (/^[A-Z0-9]+$/.test(part)) {
                return part;
            }
            if (/^.*\d.*$/.test(part)) {
                return part.toUpperCase();
            }
            if (part.length <= 3) {
                return part.toUpperCase();
            }
            return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
        })
        .join(' ');
}

function formatCertification(statusReports) {
    if (!Array.isArray(statusReports) || !statusReports.length) {
        return '';
    }

    const sorted = [...statusReports].sort((a, b) => {
        const dateA = Date.parse(a.effectiveDate || '') || 0;
        const dateB = Date.parse(b.effectiveDate || '') || 0;
        return dateB - dateA;
    });

    const latest = sorted[0];
    if (!latest) {
        return '';
    }

    const parts = [formatEnum(latest.status)];
    if (latest.certificationDescriptor) {
        parts.push(latest.certificationDescriptor);
    }
    if (latest.certificateNumber) {
        parts.push(`(${latest.certificateNumber})`);
    }
    return parts.filter(Boolean).join(' ');
}

function latestEffectiveDate(statusReports) {
    if (!Array.isArray(statusReports) || !statusReports.length) {
        return '';
    }
    const sorted = [...statusReports].sort((a, b) => {
        const dateA = Date.parse(a.effectiveDate || '') || 0;
        const dateB = Date.parse(b.effectiveDate || '') || 0;
        return dateB - dateA;
    });
    return sorted[0]?.effectiveDate || '';
}

function formatDate(value) {
    if (!value) {
        return '';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }
    return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    }).format(date);
}

function decodeBase64Url(value) {
    let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = base64.length % 4;
    if (padding) {
        base64 += '='.repeat(4 - padding);
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
}
