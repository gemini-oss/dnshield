// Popup script for DNShield Monitor extension

let blockHistory = [];
let blockedDomains = [];

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
    loadBlockData();
    setupEventListeners();
    checkNativeHostStatus();
});

// Load block data from background script
async function loadBlockData() {
    chrome.runtime.sendMessage({ type: 'getBlockedDomains' }, (response) => {
        if (response) {
            blockedDomains = response.domains || [];
            blockHistory = response.history || [];
            updateUI();
        }
    });
}

// Check connection status
function checkNativeHostStatus() {
    // Check WebSocket connection to DNShield
    chrome.runtime.sendMessage({ type: 'checkConnection' }, (response) => {
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.querySelector('.status-text');

        if (response && response.connected) {
            statusIndicator.classList.add('active');
            statusText.textContent = 'Connected';
        } else {
            statusIndicator.classList.remove('active');
            statusText.textContent = 'Disconnected';
        }
    });
}

// Update UI with block data
function updateUI() {
    // Update total blocked count using history (unique browser-originated blocks)
    const uniqueBlockedSites = new Set(
        (blockHistory || [])
            .filter(item => item && typeof item.domain === 'string')
            .map(item => item.domain)
    ).size;
    document.getElementById('blocked-count').textContent = uniqueBlockedSites;

    // Count blocks in last 24 hours
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentCount = blockHistory.filter(block =>
        new Date(block.timestamp) > oneDayAgo
    ).length;
    document.getElementById('recent-count').textContent = recentCount;

    // Display recent blocks
    const recentBlocksDiv = document.getElementById('recent-blocks');

    if (blockHistory.length === 0) {
        recentBlocksDiv.innerHTML = '<p class="empty-state">No blocked sites yet</p>';
    } else {
        recentBlocksDiv.innerHTML = blockHistory.slice(0, 10).map(block => {
            const time = new Date(block.timestamp).toLocaleTimeString();
            return `
                <div class="block-item" data-domain="${block.domain}">
                    <div class="block-domain">${block.domain}</div>
                    <div class="block-info">
                        <span>${time}</span>
                        <span>${block.process || 'Unknown'}</span>
                    </div>
                </div>
            `;
        }).join('');

        // Add click handlers to block items
        recentBlocksDiv.querySelectorAll('.block-item').forEach(item => {
            item.addEventListener('click', () => {
                const domain = item.dataset.domain;
                if (confirm(`Unblock ${domain}?`)) {
                    unblockDomain(domain);
                }
            });
        });
    }
}

// Setup event listeners
function setupEventListeners() {
    // Clear history button
    document.getElementById('clear-history').addEventListener('click', () => {
        if (confirm('Clear all block history?')) {
            chrome.runtime.sendMessage({ type: 'clearHistory' }, (response) => {
                if (response && response.success) {
                    blockHistory = [];
                    blockedDomains = [];
                    updateUI();
                }
            });
        }
    });

    // View all button
    document.getElementById('view-all').addEventListener('click', () => {
        // Open a new tab with full history view
        chrome.tabs.create({
            url: chrome.runtime.getURL('history.html')
        });
    });
}

// Unblock a domain
function unblockDomain(domain) {
    chrome.runtime.sendMessage({
        type: 'unblockDomain',
        domain: domain
    }, (response) => {
        if (response && response.success) {
            loadBlockData(); // Reload data
        }
    });
}

// Refresh data every 5 seconds while popup is open
setInterval(() => {
    loadBlockData();
    checkNativeHostStatus();
}, 5000);
