// Whether a saved credential is discoverable, as the browser said when it was
// registered: its credProps extension output's rk. Nothing else in a record says
// so: the residentKey an earlier version stored came from the BE flag or the
// request, so it is not read. DOM-free.

/**
 * credProps.rk from the record's extension outputs: true or false as the browser
 * reported it, null when it did not.
 * @param {Record<string, any> | null | undefined} record
 * @returns {boolean | null}
 */
export function reportedResidentKey(record) {
    const rk = record?.clientExtensionOutputs?.credProps?.rk;
    return typeof rk === 'boolean' ? rk : null;
}
