// WebAuthn FIDO2 Test Application - Main App Logic

let currentSubTab = 'registration';
let storedCredentials = [];
let currentJsonMode = null;
let currentJsonData = null;

// Info popup functionality
function showInfoPopup(iconElement) {
    const popup = iconElement.querySelector('.info-popup');
    // Hide all other popups first
    document.querySelectorAll('.info-popup.show').forEach(p => p.classList.remove('show'));
    // Show this popup
    popup.classList.add('show');
}

function hideInfoPopup(iconElement) {
    const popup = iconElement.querySelector('.info-popup');
    popup.classList.remove('show');
}

// Utility functions for data validation and conversion
function isValidHex(str) {
    return /^[0-9a-fA-F]*$/.test(str) && str.length > 0;
}

function generateRandomHex(bytes) {
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Convert hex string to base64url format for WebAuthn JSON
function hexToBase64Url(hexString) {
    if (!hexString) return '';
    
    // Ensure hex string has even length
    if (hexString.length % 2 !== 0) {
        hexString = '0' + hexString;
    }
    
    // Convert hex to bytes
    const bytes = new Uint8Array(hexString.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    
    // Convert to base64
    const base64 = btoa(String.fromCharCode(...bytes));
    
    // Convert to base64url (URL-safe base64)
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Convert base64url back to hex string
function base64UrlToHex(base64url) {
    if (!base64url) return '';
    
    // Convert base64url to regular base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding if needed
    while (base64.length % 4) {
        base64 += '=';
    }
    
    // Decode base64 to bytes
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    
    // Convert bytes to hex
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Convert base64 to base64url
function base64ToBase64Url(base64) {
    if (!base64) return '';
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Convert hex to regular base64
function hexToBase64(hexString) {
    if (!hexString) return '';
    
    // Convert hex to bytes
    const bytes = new Uint8Array(hexString.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    
    // Convert to base64
    return btoa(String.fromCharCode(...bytes));
}

// Convert hex to GUID format (for AAGUID display)
function hexToGuid(hexString) {
    if (!hexString || hexString.length !== 32) return hexString;
    
    // Format as GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    return hexString.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
}

// Convert hex to JavaScript array format
function hexToJs(hexString) {
    if (!hexString) return '';
    
    // Convert hex pairs to decimal array
    const pairs = hexString.match(/.{2}/g) || [];
    const decimals = pairs.map(pair => parseInt(pair, 16));
    return `[${decimals.join(', ')}]`;
}

// Convert base64 to hex
function base64ToHex(base64) {
    if (!base64) return '';
    
    try {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
        return '';
    }
}

// Convert base64url to hex with proper error handling
function base64UrlToHexFixed(base64url) {
    if (!base64url) return '';
    
    try {
        // Convert base64url to regular base64
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        
        // Add padding if needed
        while (base64.length % 4) {
            base64 += '=';
        }
        
        return base64ToHex(base64);
    } catch (e) {
        return '';
    }
}

// Convert JavaScript array format to hex
function jsToHex(jsString) {
    if (!jsString) return '';
    
    try {
        // Extract numbers from array format like [1, 2, 3] or 1,2,3
        const matches = jsString.match(/\d+/g);
        if (!matches) return '';
        
        return matches.map(num => parseInt(num).toString(16).padStart(2, '0')).join('');
    } catch (e) {
        return '';
    }
}

// Format conversion utility
function convertFormat(value, fromFormat, toFormat) {
    if (!value) return '';
    
    let hexValue = '';
    
    // Convert to hex first
    switch (fromFormat) {
        case 'hex':
            hexValue = value;
            break;
        case 'b64':
            hexValue = base64ToHex(value);
            break;
        case 'b64u':
            hexValue = base64UrlToHexFixed(value);
            break;
        case 'js':
            hexValue = jsToHex(value);
            break;
        default:
            return value;
    }
    
    // Convert from hex to target format
    switch (toFormat) {
        case 'hex':
            return hexValue;
        case 'b64':
            return hexToBase64(hexValue);
        case 'b64u':
            return hexToBase64Url(hexValue);
        case 'js':
            return hexToJs(hexValue);
        default:
            return hexValue;
    }
}

// Binary format handling
function getCurrentBinaryFormat() {
    const formatSelect = document.getElementById('binary-format');
    return formatSelect ? formatSelect.value : 'hex';
}

function changeBinaryFormat() {
    const newFormat = getCurrentBinaryFormat();
    
    // Update all relevant input field values
    const fieldsToUpdate = [
        'user-id', 'challenge-reg', 'challenge-auth',
        'prf-eval-first-reg', 'prf-eval-second-reg',
        'prf-eval-first-auth', 'prf-eval-second-auth',
        'large-blob-write'
    ];
    
    fieldsToUpdate.forEach(fieldId => {
        const field = document.getElementById(fieldId);
        if (field && field.value) {
            // Convert from previous format to new format
            // We'll use hex as intermediate format
            const currentValue = field.value;
            let hexValue = '';
            
            // Convert current value to hex (assuming it was in the previous format)
            if (currentValue) {
                // For simplicity, we'll just update the labels and let users re-enter values
                // A more sophisticated approach would track the previous format
                if (newFormat !== 'hex' && isValidHex(currentValue)) {
                    field.value = convertFormat(currentValue, 'hex', newFormat);
                }
            }
        }
    });
    
    // Update field labels
    updateFieldLabels(newFormat);
    
    // Update JSON editor
    updateJsonEditor();
}

function updateFieldLabels(format) {
    const formatText = {
        'hex': 'hex',
        'b64': 'base64',
        'b64u': 'base64url',
        'js': 'JavaScript array'
    };
    
    const fields = [
        { id: 'user-id', base: 'User ID' },
        { id: 'challenge-reg', base: 'Challenge' },
        { id: 'challenge-auth', base: 'Challenge' },
        { id: 'prf-eval-first-reg', base: 'PRF First' },
        { id: 'prf-eval-second-reg', base: 'PRF Second' },
        { id: 'prf-eval-first-auth', base: 'PRF First' },
        { id: 'prf-eval-second-auth', base: 'PRF Second' },
        { id: 'large-blob-write', base: 'Large Blob Data' }
    ];
    
    fields.forEach(field => {
        const label = document.querySelector(`label[for="${field.id}"]`);
        if (label) {
            label.textContent = `${field.base} (${formatText[format] || format})`;
        }
    });
}

// Input validation
function validateHexInput(inputId, errorId, minBytes = 0) {
    const input = document.getElementById(inputId);
    const errorElement = document.getElementById(errorId);
    
    if (!input || !errorElement) return true;
    
    const value = input.value.trim();
    
    if (!value) {
        input.classList.remove('error');
        errorElement.style.display = 'none';
        return true;
    }
    
    const format = getCurrentBinaryFormat();
    let isValid = false;
    let byteLength = 0;
    
    switch (format) {
        case 'hex':
            isValid = isValidHex(value) && value.length % 2 === 0;
            byteLength = value.length / 2;
            break;
        case 'b64':
        case 'b64u':
            // Basic base64/base64url validation
            isValid = /^[A-Za-z0-9+/\-_]*={0,2}$/.test(value);
            try {
                const hexConverted = format === 'b64' ? base64ToHex(value) : base64UrlToHexFixed(value);
                byteLength = hexConverted.length / 2;
            } catch (e) {
                isValid = false;
            }
            break;
        case 'js':
            // JavaScript array format validation
            isValid = /^\[[\d,\s]*\]$|^[\d,\s]*$/.test(value);
            try {
                const hexConverted = jsToHex(value);
                byteLength = hexConverted.length / 2;
            } catch (e) {
                isValid = false;
            }
            break;
    }
    
    if (!isValid || (minBytes > 0 && byteLength < minBytes) || byteLength > 64) {
        input.classList.add('error');
        errorElement.style.display = 'block';
        return false;
    } else {
        input.classList.remove('error');
        errorElement.style.display = 'none';
        return true;
    }
}

// Specific input validators
function validateUserIdInput() {
    return validateHexInput('user-id', 'user-id-error', 1);
}

function validateChallengeInputs() {
    const regValid = validateHexInput('challenge-reg', 'challenge-reg-error');
    const authValid = validateHexInput('challenge-auth', 'challenge-auth-error');
    return regValid && authValid;
}

function validatePrfEvalInputs() {
    const regFirstValid = validateHexInput('prf-eval-first-reg', 'prf-eval-first-reg-error');
    const regSecondValid = validateHexInput('prf-eval-second-reg', 'prf-eval-second-reg-error');
    const authFirstValid = validateHexInput('prf-eval-first-auth', 'prf-eval-first-auth-error');
    const authSecondValid = validateHexInput('prf-eval-second-auth', 'prf-eval-second-auth-error');
    return regFirstValid && regSecondValid && authFirstValid && authSecondValid;
}

function validateLargeBlobWriteInput() {
    return validateHexInput('large-blob-write', 'large-blob-write-error');
}

// Status and progress management
function showStatus(tabId, message, type = 'info') {
    const statusEl = document.getElementById(tabId + '-status');
    if (statusEl) {
        statusEl.textContent = message;
        statusEl.className = 'status ' + type + ' show';
        statusEl.style.display = 'block';
        
        // Auto-hide after 10 seconds for success messages
        if (type === 'success') {
            setTimeout(() => hideStatus(tabId), 10000);
        }
    }
}

function hideStatus(tabId) {
    const statusEl = document.getElementById(tabId + '-status');
    if (statusEl) {
        statusEl.style.display = 'none';
        statusEl.classList.remove('show');
    }
}

function showProgress(tabId, message) {
    const progressEl = document.getElementById(tabId + '-progress');
    const textEl = document.getElementById(tabId + '-progress-text');
    if (progressEl && textEl) {
        textEl.textContent = message;
        progressEl.classList.add('show');
    }
}

function hideProgress(tabId) {
    const progressEl = document.getElementById(tabId + '-progress');
    if (progressEl) {
        progressEl.classList.remove('show');
    }
}

// Tab switching functionality
function switchTab(tab) {
    // Debug logging with fallback
    if (window.console && console.log) {
        console.log('Switching to tab:', tab);
    }
    
    // Hide all tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Hide all nav buttons
    document.querySelectorAll('.nav-tab').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show the selected tab content - try with fallback
    const targetTab = document.getElementById(tab + '-tab');
    if (targetTab) {
        targetTab.classList.add('active');
        if (window.console && console.log) {
            console.log('Activated tab:', targetTab.id);
        }
    } else {
        if (window.console && console.error) {
            console.error('Tab not found:', tab + '-tab');
        }
    }
    
    // Activate the corresponding nav button - use a more direct approach
    const navButtons = document.querySelectorAll('.nav-tab');
    const tabNames = ['simple', 'advanced', 'decoder'];
    const tabIndex = tabNames.indexOf(tab);
    
    if (tabIndex !== -1 && navButtons[tabIndex]) {
        navButtons[tabIndex].classList.add('active');
        if (window.console && console.log) {
            console.log('Activated nav button:', tabIndex);
        }
    }
    
    // Update JSON editor if in advanced tab
    if (tab === 'advanced') {
        updateJsonEditor();
    }
}

// Sub-tab switching for Registration/Authentication
function switchSubTab(subTab) {
    currentSubTab = subTab;
    
    // Update sub-tab buttons
    document.querySelectorAll('.sub-tab').forEach(btn => {
        btn.classList.remove('active');
    });
    document.getElementById(subTab + '-tab-btn').classList.add('active');
    
    // Update sub-tab content
    document.querySelectorAll('.sub-tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(subTab + '-form').classList.add('active');
    
    // Update JSON editor
    updateJsonEditor();
}

// Section toggle functionality
function toggleSection(sectionId) {
    const header = event.currentTarget;
    const content = document.getElementById(sectionId);
    const icon = header.querySelector('.expand-icon');
    
    if (content.classList.contains('expanded')) {
        content.classList.remove('expanded');
        header.classList.remove('expanded');
        icon.classList.remove('rotated');
    } else {
        content.classList.add('expanded');
        header.classList.add('expanded');
    }
}

// Randomization functions
function randomizeUserId() {
    const userId = generateRandomHex(32);
    const format = getCurrentBinaryFormat();
    const formattedValue = convertFormat(userId, 'hex', format);
    document.getElementById('user-id').value = formattedValue;
    updateJsonEditor();
}

function randomizeChallenge() {
    const challenge = generateRandomHex(32);
    const format = getCurrentBinaryFormat();
    const formattedValue = convertFormat(challenge, 'hex', format);
    
    if (currentSubTab === 'registration') {
        document.getElementById('challenge-reg').value = formattedValue;
    } else {
        document.getElementById('challenge-auth').value = formattedValue;
    }
    
    updateJsonEditor();
}

function randomizePrfEval() {
    const prfFirst = generateRandomHex(32);
    const prfSecond = generateRandomHex(32);
    const format = getCurrentBinaryFormat();
    const formattedFirst = convertFormat(prfFirst, 'hex', format);
    const formattedSecond = convertFormat(prfSecond, 'hex', format);
    
    if (currentSubTab === 'registration') {
        document.getElementById('prf-eval-first-reg').value = formattedFirst;
        document.getElementById('prf-eval-second-reg').value = formattedSecond;
    } else {
        document.getElementById('prf-eval-first-auth').value = formattedFirst;
        document.getElementById('prf-eval-second-auth').value = formattedSecond;
    }
    
    updateJsonEditor();
}

function randomizeLargeBlobWrite() {
    const blobData = generateRandomHex(64); // 64 bytes
    const format = getCurrentBinaryFormat();
    const formattedValue = convertFormat(blobData, 'hex', format);
    document.getElementById('large-blob-write').value = formattedValue;
    updateJsonEditor();
}

// Make functions globally available
window.showInfoPopup = showInfoPopup;
window.hideInfoPopup = hideInfoPopup;
window.switchTab = switchTab;
window.switchSubTab = switchSubTab;
window.toggleSection = toggleSection;
window.randomizeUserId = randomizeUserId;
window.randomizeChallenge = randomizeChallenge;
window.randomizePrfEval = randomizePrfEval;
window.randomizeLargeBlobWrite = randomizeLargeBlobWrite;
window.changeBinaryFormat = changeBinaryFormat;
window.validateUserIdInput = validateUserIdInput;
window.validateChallengeInputs = validateChallengeInputs;
window.validatePrfEvalInputs = validatePrfEvalInputs;
window.validateLargeBlobWriteInput = validateLargeBlobWriteInput;