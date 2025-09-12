// WebAuthn FIDO2 Test Application - Advanced Authentication

// Advanced authentication will be implemented in a future version
// For now, providing basic placeholder functionality

let advancedCredentials = [];

// Placeholder functions for advanced authentication
async function advancedRegister() {
    showStatus('advanced', 'Advanced registration functionality coming soon!', 'info');
}

async function advancedAuthenticate() {
    showStatus('advanced', 'Advanced authentication functionality coming soon!', 'info');
}

function resetRegistrationForm() {
    showStatus('advanced', 'Reset functionality coming soon!', 'info');
}

function resetAuthenticationForm() {
    showStatus('advanced', 'Reset functionality coming soon!', 'info');
}

// JSON Editor Functions - placeholder
function updateJsonEditor() {
    // Placeholder for JSON editor functionality
    console.log('JSON editor update - coming soon');
}

function loadSavedCredentials() {
    // Placeholder for loading saved credentials
    console.log('Load saved credentials - coming soon');
}

// Advanced credentials display
function updateCredentialsDisplay() {
    const list = document.getElementById('advanced-credentials-list');
    if (!list) return;
    
    if (advancedCredentials.length === 0) {
        list.innerHTML = '<p style="color: #6c757d; font-style: italic;">No advanced credentials registered yet.</p>';
        return;
    }
    
    list.innerHTML = advancedCredentials.map((cred, index) => `
        <div class="credential-item" onclick="toggleCredentialExpansion(this)">
            <div class="credential-summary">
                ${cred.userName || cred.userId} - Advanced Registration
            </div>
            <div class="credential-details">
                <strong>User ID:</strong> ${cred.userId}<br>
                <strong>User Name:</strong> ${cred.userName}<br>
                <strong>Display Name:</strong> ${cred.displayName || 'N/A'}<br>
                <strong>Credential ID:</strong> ${cred.credentialId}<br>
                <strong>Algorithm:</strong> ${cred.algorithm}
                <button class="credential-delete" onclick="deleteAdvancedCredential(event, ${index})">Delete</button>
            </div>
        </div>
    `).join('');
}

async function deleteAdvancedCredential(event, index) {
    event.stopPropagation();
    
    const credential = advancedCredentials[index];
    if (!credential) return;
    
    if (!confirm(`Are you sure you want to delete this advanced credential?`)) {
        return;
    }

    try {
        const response = await fetch('/api/deletepub', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({"username": credential.userName})
        });

        if (response.ok) {
            // Remove from local array
            advancedCredentials.splice(index, 1);
            updateCredentialsDisplay();
            
            showStatus('advanced', 
                'Advanced credential deleted from server successfully! ' +
                'Note: This only removes the credential from our application. ' +
                'The credential remains on your authenticator device.', 
                'success'
            );
        } else {
            throw new Error('Failed to delete credential from server');
        }
    } catch (error) {
        console.error('Error deleting advanced credential:', error);
        showStatus('advanced', `Failed to delete credential: ${error.message}`, 'error');
    }
}

// Form validation placeholders
function validateLargeBlobDependency() {
    // Placeholder validation
    return true;
}

function getAdvancedCreateOptions() {
    // Return basic options for now
    return {
        username: 'test-user',
        displayName: 'Test User',
        userId: generateRandomHex(32),
        attestation: 'none',
        userVerification: 'preferred',
        residentKey: 'discouraged',
        timeout: 90000,
        pubKeyCredParams: ['ES256', 'RS256'],
        extensions: {}
    };
}

function getAdvancedAssertOptions() {
    // Return basic options for now
    return {
        userVerification: 'preferred',
        allowCredentials: 'all',
        timeout: 90000,
        extensions: {}
    };
}

// Make functions globally available
window.advancedRegister = advancedRegister;
window.advancedAuthenticate = advancedAuthenticate;
window.resetRegistrationForm = resetRegistrationForm;
window.resetAuthenticationForm = resetAuthenticationForm;
window.updateJsonEditor = updateJsonEditor;
window.loadSavedCredentials = loadSavedCredentials;
window.updateCredentialsDisplay = updateCredentialsDisplay;
window.deleteAdvancedCredential = deleteAdvancedCredential;
window.validateLargeBlobDependency = validateLargeBlobDependency;
window.getAdvancedCreateOptions = getAdvancedCreateOptions;
window.getAdvancedAssertOptions = getAdvancedAssertOptions;