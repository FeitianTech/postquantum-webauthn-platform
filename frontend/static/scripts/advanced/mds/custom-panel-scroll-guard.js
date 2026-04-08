export function createCustomPanelScrollGuard(panel) {
    const dialog = panel?.querySelector?.('.mds-custom-panel__dialog');
    if (!(dialog instanceof HTMLElement)) {
        return null;
    }

    const shouldPreventScroll = deltaY => {
        if (!Number.isFinite(deltaY) || deltaY === 0) {
            return false;
        }
        const scrollableHeight = dialog.scrollHeight - dialog.clientHeight;
        if (scrollableHeight <= 0) {
            return true;
        }
        const threshold = 1;
        if (deltaY < 0 && dialog.scrollTop <= threshold) {
            return true;
        }
        if (deltaY > 0 && dialog.scrollTop >= scrollableHeight - threshold) {
            return true;
        }
        return false;
    };

    const handleWheel = event => {
        if (shouldPreventScroll(event.deltaY)) {
            event.preventDefault();
        }
    };

    let lastTouchY = null;
    const handleTouchStart = event => {
        if (event.touches && event.touches.length > 0) {
            lastTouchY = event.touches[0].clientY;
        }
    };

    const handleTouchMove = event => {
        if (!event.touches || event.touches.length === 0) {
            return;
        }
        const currentY = event.touches[0].clientY;
        if (lastTouchY === null) {
            lastTouchY = currentY;
        }
        const deltaY = lastTouchY - currentY;
        lastTouchY = currentY;
        if (shouldPreventScroll(deltaY)) {
            event.preventDefault();
        }
    };

    const handleTouchEnd = () => {
        lastTouchY = null;
    };

    dialog.addEventListener('wheel', handleWheel, { passive: false });
    dialog.addEventListener('touchstart', handleTouchStart, { passive: true });
    dialog.addEventListener('touchmove', handleTouchMove, { passive: false });
    dialog.addEventListener('touchend', handleTouchEnd);
    dialog.addEventListener('touchcancel', handleTouchEnd);

    return () => {
        dialog.removeEventListener('wheel', handleWheel);
        dialog.removeEventListener('touchstart', handleTouchStart);
        dialog.removeEventListener('touchmove', handleTouchMove);
        dialog.removeEventListener('touchend', handleTouchEnd);
        dialog.removeEventListener('touchcancel', handleTouchEnd);
        lastTouchY = null;
    };
}
