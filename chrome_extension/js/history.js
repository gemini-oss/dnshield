// History page JavaScript

let allHistory = [];
let filteredHistory = [];

// Initialize the page
document.addEventListener('DOMContentLoaded', async () => {
    loadHistory();
    
    // Setup event listeners
    document.getElementById('searchInput').addEventListener('input', filterHistory);
    document.getElementById('clearAllBtn').addEventListener('click', clearAllHistory);
    document.getElementById('exportBtn').addEventListener('click', exportHistory);
});

// Load history from background script
async function loadHistory() {
    try {
        const response = await chrome.runtime.sendMessage({ type: 'getBlockedDomains' });
        allHistory = response.history || [];
        filteredHistory = [...allHistory];
        
        displayHistory();
    } catch (error) {
        console.error('Error loading history:', error);
        document.getElementById('historyList').innerHTML = '<div class="empty">Error loading history</div>';
    }
}

// Display history items
function displayHistory() {
    const historyList = document.getElementById('historyList');
    
    if (filteredHistory.length === 0) {
        historyList.innerHTML = '<div class="empty">No blocked domains in history</div>';
        return;
    }
    
    historyList.innerHTML = filteredHistory.map(item => `
        <div class="history-item" data-domain="${item.domain}">
            <div class="domain-info">
                <div class="domain">${escapeHtml(item.domain)}</div>
                <div class="process">Process: ${escapeHtml(item.process || 'Unknown')}</div>
            </div>
            <div class="timestamp">${formatTimestamp(item.timestamp)}</div>
        </div>
    `).join('');
}

// Filter history based on search input
function filterHistory() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    
    if (searchTerm === '') {
        filteredHistory = [...allHistory];
    } else {
        filteredHistory = allHistory.filter(item => 
            item.domain.toLowerCase().includes(searchTerm) ||
            (item.process && item.process.toLowerCase().includes(searchTerm))
        );
    }
    
    displayHistory();
}

// Clear all history
async function clearAllHistory() {
    if (!confirm('Are you sure you want to clear all history?')) {
        return;
    }
    
    try {
        await chrome.runtime.sendMessage({ type: 'clearHistory' });
        allHistory = [];
        filteredHistory = [];
        displayHistory();
    } catch (error) {
        console.error('Error clearing history:', error);
        alert('Failed to clear history');
    }
}

// Export history as CSV
function exportHistory() {
    if (allHistory.length === 0) {
        alert('No history to export');
        return;
    }
    
    // Create CSV content
    const headers = ['Domain', 'Process', 'Timestamp'];
    const rows = allHistory.map(item => [
        item.domain,
        item.process || 'Unknown',
        formatTimestamp(item.timestamp)
    ]);
    
    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');
    
    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dnshield-history-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}


// Format timestamp
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    // Less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }
    
    // Less than 1 hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    }
    
    // Less than 24 hours
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }
    
    // More than 24 hours - show date
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}