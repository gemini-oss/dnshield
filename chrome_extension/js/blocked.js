// Script for the blocked page

// Parse URL parameters
const urlParams = new URLSearchParams(window.location.search);
const blockedDomain = urlParams.get('domain') || 'Unknown';
const blockedUrl = urlParams.get('url') || 'Unknown';
const blockedProcess = urlParams.get('process') || 'Unknown';
const blockTimestamp = urlParams.get('timestamp') || new Date().toISOString();

// Update page content
document.getElementById('blocked-domain').textContent = blockedDomain;
document.getElementById('blocked-url').textContent = blockedUrl;
document.getElementById('blocked-process').textContent = blockedProcess;
document.getElementById('block-time').textContent = new Date(blockTimestamp).toLocaleString();

// Handle "Go Back" button
document.getElementById('go-back').addEventListener('click', () => {
    history.back();
});

// Handle "New Tab" button
document.getElementById('new-tab').addEventListener('click', () => {
    chrome.tabs.create({ url: 'chrome://newtab' });
});

// Handle "View History" button
document.getElementById('view-history').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'openPopup' });
    // Also open the extension popup
    chrome.action.openPopup();
});

// Handle "Request Bypass" button
document.getElementById('request-bypass').addEventListener('click', () => {
    const button = document.getElementById('request-bypass');
    button.disabled = true;
    button.textContent = 'Requesting...';
    
    chrome.runtime.sendMessage({ 
        type: 'requestBypass',
        domain: blockedDomain
    }, (response) => {
        if (response && response.success) {
            button.textContent = 'Bypass Requested';
            button.classList.add('btn-success');
            // Show success message
            const message = document.createElement('p');
            message.className = 'success-message';
            message.textContent = 'Bypass request sent. The page will reload if approved.';
            button.parentElement.appendChild(message);
            
            // Try to reload after a short delay
            setTimeout(() => {
                if (blockedUrl !== 'Unknown') {
                    window.location.href = blockedUrl;
                }
            }, 2000);
        } else {
            button.textContent = 'Request Failed';
            button.classList.add('btn-error');
            button.disabled = false;
            
            // Show error message
            const message = document.createElement('p');
            message.className = 'error-message';
            message.textContent = response.error || 'Failed to send bypass request';
            button.parentElement.appendChild(message);
        }
    });
});
