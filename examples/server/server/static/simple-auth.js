// WebAuthn FIDO2 Test Application - Simple Authentication

// Simple authentication functions (keeping existing functionality)
async function simpleRegister() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', 'Please enter an email address', 'error');
        return;
    }

    try {
        hideStatus('simple');
        showProgress('simple', 'Starting registration...');

        const response = await fetch('/api/register/begin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email: email}),
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const json = await response.json();
        const createOptions = parseCreationOptionsFromJSON(json);

        showProgress('simple', 'Connecting your authenticator device...');

        const credential = await create(createOptions);
        
        showProgress('simple', 'Completing registration...');

        const result = await fetch('/api/register/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                email: email,
                response: credential
            }),
        });

        if (result.ok) {
            const data = await result.json();
            showStatus('simple', `Registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');
            
            // Add to credentials list
            addCredentialToList({
                type: 'simple',
                email: email,
                credentialId: credential.id,
                algorithm: data.algo || 'Unknown'
            });
        } else {
            throw new Error('Registration failed');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showStatus('simple', `Registration failed: ${error.message}`, 'error');
    } finally {
        hideProgress('simple');
    }
}

async function simpleAuthenticate() {
    const email = document.getElementById('simple-email').value;
    if (!email) {
        showStatus('simple', 'Please enter an email address', 'error');
        return;
    }

    try {
        hideStatus('simple');
        showProgress('simple', 'Starting authentication...');

        const response = await fetch('/api/authenticate/begin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email: email}),
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const json = await response.json();
        const getOptions = parseRequestOptionsFromJSON(json);

        showProgress('simple', 'Connecting your authenticator device...');

        const assertion = await get(getOptions);
        
        showProgress('simple', 'Completing authentication...');

        const result = await fetch('/api/authenticate/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                email: email,
                response: assertion
            }),
        });

        if (result.ok) {
            showStatus('simple', 'Authentication successful!', 'success');
        } else {
            throw new Error('Authentication failed');
        }
    } catch (error) {
        console.error('Authentication error:', error);
        showStatus('simple', `Authentication failed: ${error.message}`, 'error');
    } finally {
        hideProgress('simple');
    }
}

// Credentials management
function addCredentialToList(credential) {
    storedCredentials.push(credential);
    updateCredentialsList();
}

function updateCredentialsList() {
    const list = document.getElementById('credentials-list');
    
    if (storedCredentials.length === 0) {
        list.innerHTML = '<p style="color: #6c757d; font-style: italic;">No credentials registered yet.</p>';
        return;
    }

    list.innerHTML = storedCredentials.map((cred, index) => `
        <div class="credential-item" onclick="toggleCredentialExpansion(this)">
            <div class="credential-summary">
                ${cred.email || 'Unknown User'} - ${cred.type === 'simple' ? 'Simple' : 'Advanced'} Registration
            </div>
            <div class="credential-details">
                <strong>Credential ID:</strong> ${cred.credentialId}<br>
                <strong>Algorithm:</strong> ${cred.algorithm}<br>
                <strong>Type:</strong> ${cred.type}
                <button class="credential-delete" onclick="deleteCredential(event, ${index})">Delete</button>
            </div>
        </div>
    `).join('');
}

function toggleCredentialExpansion(element) {
    element.classList.toggle('expanded');
}

async function deleteCredential(event, index) {
    event.stopPropagation();
    
    const credential = storedCredentials[index];
    if (!credential) return;
    
    if (!confirm(`Are you sure you want to delete this credential?`)) {
        return;
    }

    try {
        const response = await fetch('/api/deletepub', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({"email": credential.email})
        });

        if (response.ok) {
            // Remove from local array
            storedCredentials.splice(index, 1);
            updateCredentialsList();
            
            showStatus('simple', 
                'Credential deleted from server successfully! ' +
                'Note: This only removes the credential from our application. ' +
                'The credential remains on your authenticator device and may still appear during resident key authentication. ' +
                'To fully remove credentials, you may need to reset your authenticator or use device-specific management tools.', 
                'success'
            );
        } else {
            throw new Error('Failed to delete credential from server');
        }
    } catch (error) {
        console.error('Error deleting credential:', error);
        showStatus('simple', `Failed to delete credential: ${error.message}`, 'error');
    }
}

// Make functions globally available
window.simpleRegister = simpleRegister;
window.simpleAuthenticate = simpleAuthenticate;
window.addCredentialToList = addCredentialToList;
window.updateCredentialsList = updateCredentialsList;
window.toggleCredentialExpansion = toggleCredentialExpansion;
window.deleteCredential = deleteCredential;