// The certificate's text is ./certificate-text.js's, which the new UI imports too;
// this module keeps the current UI's text areas' sizing.
export {formatCertificateDetails} from './certificate-text.js';

export function autoResizeCertificateTextareas(context) {
    const scope = context && typeof context.querySelectorAll === 'function'
        ? context
        : document;
    const textareas = scope.querySelectorAll('.certificate-textarea');
    textareas.forEach(textarea => {
        if (!(textarea instanceof HTMLTextAreaElement)) {
            return;
        }

        const resizeOnce = () => {
            textarea.style.height = 'auto';
            textarea.style.overflowY = 'hidden';
            textarea.style.overflowX = 'hidden';
            const measuredHeight = textarea.scrollHeight;
            if (Number.isFinite(measuredHeight) && measuredHeight > 0) {
                textarea.style.height = `${measuredHeight}px`;
            } else {
                textarea.style.height = '';
            }
        };

        resizeOnce();

        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(resizeOnce);
        }

        setTimeout(resizeOnce, 150);
    });
}
