export function sortStatusReportsByEffectiveDateDesc(statusReports) {
    if (!Array.isArray(statusReports) || !statusReports.length) {
        return [];
    }

    return [...statusReports].sort((a, b) => {
        const dateA = Date.parse(a?.effectiveDate || '') || 0;
        const dateB = Date.parse(b?.effectiveDate || '') || 0;
        return dateB - dateA;
    });
}

export function latestEffectiveDate(statusReports) {
    const sorted = sortStatusReportsByEffectiveDateDesc(statusReports);
    return sorted[0]?.effectiveDate || '';
}