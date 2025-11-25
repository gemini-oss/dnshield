// Global state
let currentEntity = null;
let originalManifests = [];
let currentManifests = [];
let availableManifests = [];
let manifestPathMap = {};
let searchType = 'user';

// API endpoint - will be updated to match backend server
const API_BASE = 'http://localhost:7777/api';

// Initialize the app
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    checkConfiguration();
    // Check and update auth UI
    updateAuthUI();
});

// Setup event listeners
function setupEventListeners() {
    // Search type buttons
    document.querySelectorAll('.search-type button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.search-type button').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            searchType = e.target.dataset.type;
            updateSearchPlaceholder();
        });
    });
    
    // Enter key on search input
    document.getElementById('searchInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
    
    // Show all rules toggle
    document.getElementById('showAllRules').addEventListener('change', (e) => {
        if (currentEntity) {
            loadEntityManifests(currentEntity, e.target.checked);
        }
    });
    
    // Escape key to close modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            // Close any open modal
            const configModal = document.getElementById('configModal');
            const prModal = document.getElementById('prModal');
            const domainModal = document.getElementById('domainModal');
            
            if (configModal.classList.contains('active')) {
                closeConfigModal();
            } else if (prModal.classList.contains('active')) {
                closePRModal();
            } else if (domainModal.classList.contains('active')) {
                closeDomainModal();
            }
        }
    });
}

function updateSearchPlaceholder() {
    const input = document.getElementById('searchInput');
    switch(searchType) {
        case 'user':
            input.placeholder = 'Enter username (e.g., dnshield.manifest)...';
            break;
        case 'machine':
            input.placeholder = 'Enter machine serial (e.g., C02ABC1234)...';
            break;
        case 'group':
            input.placeholder = 'Enter group name (e.g., foo-bar)...';
            break;
    }
}

// Perform search
async function performSearch() {
    const searchValue = document.getElementById('searchInput').value.trim();
    if (!searchValue) {
        showAlert('Please enter a search term', 'error');
        return;
    }
    
    showLoading(true);
    hideAlert();
    
    try {
        const response = await fetch(`${API_BASE}/search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: searchType, query: searchValue })
        });
        
        if (!response.ok) {
            throw new Error('Search failed');
        }
        
        const data = await response.json();
        
        if (!data.found) {
            showAlert(`No ${searchType} found matching "${searchValue}"`, 'error');
            showLoading(false);
            return;
        }
        
        // Handle multiple machines for a user
        if (data.machines && data.machines.length > 1) {
            showMachineSelector(data);
            return;
        }
        
        currentEntity = data;
        displayEntity(data);
        loadEntityManifests(data);
        document.getElementById('contentSection').style.display = 'block';
        showAlert(`Found ${searchType}: ${data.name || data.serial || searchValue}`, 'success');
        
    } catch (error) {
        console.error('Search error:', error);
        if (error.message && error.message.includes('Repository path not configured')) {
            showAlert('Repository not configured. Click the settings gear to configure.', 'error');
            openConfigModal();
        } else {
            showAlert('Error performing search. Please ensure the backend server is running.', 'error');
        }
    } finally {
        showLoading(false);
    }
}

// Display entity information
function displayEntity(entity) {
    document.getElementById('entityName').textContent = entity.name || entity.serial || entity.id;
    document.getElementById('entityType').textContent = searchType.charAt(0).toUpperCase() + searchType.slice(1);
    document.getElementById('entityFile').textContent = entity.file || '-';
}

// Show machine selector for users with multiple machines
function showMachineSelector(data) {
    showLoading(false);
    
    // Create a modal or dropdown to select machine
    const modalHtml = `
        <div class="modal active" id="machineModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Select Machine for ${data.name}</h3>
                </div>
                <div class="modal-body">
                    <p>This user has multiple machines. Please select one:</p>
                    <div style="margin-top: 20px;">
                        ${data.machines.map(machine => `
                            <div class="manifest-item" style="margin-bottom: 10px; cursor: pointer;" 
                                 onclick="selectMachine('${machine.file}', '${machine.serial}', '${machine.hostname || machine.serial}')">
                                <div>
                                    <div class="manifest-name">${machine.hostname || 'Unknown'}</div>
                                    <div style="color: #868e96; font-size: 0.9rem;">Serial: ${machine.serial}</div>
                                </div>
                                <span class="manifest-type">Select</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div class="actions">
                    <button class="btn btn-secondary" onclick="closeMachineModal()">Cancel</button>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to page
    const modalDiv = document.createElement('div');
    modalDiv.innerHTML = modalHtml;
    document.body.appendChild(modalDiv);
}

// Select a specific machine
function selectMachine(file, serial, hostname) {
    closeMachineModal();
    
    currentEntity = {
        found: true,
        type: 'user',
        name: hostname,
        file: file,
        serial: serial
    };
    
    displayEntity(currentEntity);
    loadEntityManifests(currentEntity);
    document.getElementById('contentSection').style.display = 'block';
    showAlert(`Selected machine: ${hostname} (${serial})`, 'success');
}

// Close machine selector modal
function closeMachineModal() {
    const modal = document.getElementById('machineModal');
    if (modal && modal.parentElement) {
        modal.parentElement.remove();
    }
}

// Make functions globally available
window.selectMachine = selectMachine;
window.closeMachineModal = closeMachineModal;

// Load manifests for the entity
async function loadEntityManifests(entity, showAll = false) {
    try {
        const response = await fetch(`${API_BASE}/manifests/${entity.file}`);
        const data = await response.json();
        
        originalManifests = [...data.manifests];
        currentManifests = [...data.manifests];
        
        displayCurrentManifests(currentManifests, showAll);
        
        // Load available manifests based on entity scope
        loadAvailableManifestsForEntity(entity);
        
    } catch (error) {
        console.error('Error loading manifests:', error);
        // Fallback to demo data for now
        useDemoData();
    }
}

function buildManifestPathMap(manifests) {
    manifestPathMap = {};
    if (manifests && Array.isArray(manifests)) {
        manifests.forEach(manifest => {
            const name = manifest.name || manifest;
            const path = manifest.path || `includes/${manifest.type}/${name}`;
            manifestPathMap[name] = path;
        });
    }
}

// Load available manifests
async function loadAvailableManifests() {
    try {
        const response = await fetch(`${API_BASE}/manifests/available`);
        const data = await response.json();
        availableManifests = data.manifests;
    } catch (error) {
        console.error('Error loading available manifests:', error);
        // Use demo data
        availableManifests = [
            { name: 'global-allowlist', type: 'global' },
            { name: 'global-blocklist', type: 'global' }
        ];
    }
    buildManifestPathMap(availableManifests);
}

// Load available manifests filtered for entity
async function loadAvailableManifestsForEntity(entity) {
    try {
        // Pass entity file to backend for proper filtering
        const response = await fetch(`${API_BASE}/manifests/available?entity=${encodeURIComponent(entity.file || '')}`);
        const data = await response.json();
        buildManifestPathMap(data.manifests);

        // Filter out already assigned manifests
        const assignedNames = currentManifests.map(m => m.name || m);
        const filtered = data.manifests.filter(m => {
            const manifestName = m.name || m;
            return !assignedNames.includes(manifestName);
        });

        displayAvailableManifests(filtered);
    } catch (error) {
        console.error('Error loading available manifests:', error);
        // Fallback to local filtering
        const assignedNames = currentManifests.map(m => m.name || m);
        const filtered = availableManifests.filter(m => {
            const manifestName = m.name || m;
            return !assignedNames.includes(manifestName);
        });
        displayAvailableManifests(filtered);
    }
}

// Display current manifests
function displayCurrentManifests(manifests, showAll = false) {
    const container = document.getElementById('currentManifests');
    container.innerHTML = '';
    
    if (manifests.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No manifests currently assigned</p></div>';
        return;
    }
    
    manifests.forEach(manifest => {
        const item = createManifestItem(manifest, 'current');
        container.appendChild(item);
        
        if (showAll && manifest.rules) {
            // Show individual rules if available
            // This would need backend support to fetch rule details
        }
    });
}

// Display available manifests
function displayAvailableManifests(manifests) {
    const container = document.getElementById('availableManifests');
    container.innerHTML = '';
    
    if (manifests.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No additional manifests available</p></div>';
        return;
    }
    
    manifests.forEach(manifest => {
        const item = createManifestItem(manifest, 'available');
        container.appendChild(item);
    });
}

// Create manifest item element
function createManifestItem(manifest, source) {
    const div = document.createElement('div');
    div.className = 'manifest-item';
    div.draggable = true;
    
    const name = manifest.name || manifest;
    const type = manifest.type || detectManifestType(name);
    
    div.innerHTML = `
        <span class="manifest-name">${name}</span>
        <span class="manifest-type">${type}</span>
    `;
    
    div.dataset.name = name;
    div.dataset.source = source;
    
    // Add drag and drop event listeners
    div.addEventListener('dragstart', handleDragStart);
    div.addEventListener('dragend', handleDragEnd);
    
    return div;
}

// Detect manifest type from name
function detectManifestType(name) {
    if (name.includes('global')) return 'global';
    if (name.includes('allow') || name.includes('block')) return 'domain';
    return 'custom';
}

// Drag and drop handlers
let draggedElement = null;
let draggedManifest = null;
let draggedSource = null;

function handleDragStart(e) {
    draggedElement = e.target;
    draggedManifest = e.target.dataset.name;
    draggedSource = e.target.dataset.source;
    e.target.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/html', e.target.innerHTML);
}

function handleDragEnd(e) {
    e.target.classList.remove('dragging');
    draggedElement = null;
    draggedManifest = null;
    draggedSource = null;
}

// Setup drop zones
document.addEventListener('DOMContentLoaded', () => {
    setupDropZone('currentManifests');
    setupDropZone('availableManifests');
    // Note: stagingArea is display-only now, not a drop zone
});

function setupDropZone(containerId) {
    const container = document.getElementById(containerId);
    
    container.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        container.classList.add('drag-over');
    });
    
    container.addEventListener('dragleave', (e) => {
        if (e.target === container) {
            container.classList.remove('drag-over');
        }
    });
    
    container.addEventListener('drop', (e) => {
        e.preventDefault();
        container.classList.remove('drag-over');
        
        if (!draggedManifest || !draggedSource) return;
        
        if (containerId === 'currentManifests') {
            handleDropToCurrentManifests();
        } else if (containerId === 'availableManifests') {
            handleDropToAvailableManifests();
        }
    });
}

function getDragAfterElement(container, y) {
    const draggableElements = [...container.querySelectorAll('.manifest-item:not(.dragging)')];
    
    return draggableElements.reduce((closest, child) => {
        const box = child.getBoundingClientRect();
        const offset = y - box.top - box.height / 2;
        
        if (offset < 0 && offset > closest.offset) {
            return { offset: offset, element: child };
        } else {
            return closest;
        }
    }, { offset: Number.NEGATIVE_INFINITY }).element;
}

function handleDropToCurrentManifests() {
    // Moving from available to current (adding a manifest)
    if (draggedSource === 'available') {
        // Check if already exists
        const exists = currentManifests.some(m => (m.name || m) === draggedManifest);
        if (!exists) {
            // Add to current manifests
            currentManifests.push(draggedManifest);
            
            // Remove from available display
            const availableIndex = availableManifests.findIndex(m => (m.name || m) === draggedManifest);
            if (availableIndex > -1) {
                availableManifests.splice(availableIndex, 1);
            }
            
            // Refresh displays
            displayCurrentManifests(currentManifests);
            displayAvailableManifests(availableManifests);
            
            // Track change
            updateChangeTracking();
        }
    }
}

function handleDropToAvailableManifests() {
    // Moving from current to available (removing a manifest)
    if (draggedSource === 'current') {
        // Remove from current manifests
        const currentIndex = currentManifests.findIndex(m => (m.name || m) === draggedManifest);
        if (currentIndex > -1) {
            currentManifests.splice(currentIndex, 1);
            
            // Add to available manifests
            availableManifests.push({
                name: draggedManifest,
                type: detectManifestType(draggedManifest)
            });
            
            // Refresh displays
            displayCurrentManifests(currentManifests);
            displayAvailableManifests(availableManifests);
            
            // Track change
            updateChangeTracking();
        }
    }
}

function updateChangeTracking() {
    // Compare current manifests with original to detect changes
    const currentNames = currentManifests.map(m => m.name || m).sort();
    const originalNames = originalManifests.map(m => m.name || m).sort();
    
    const hasChanges = JSON.stringify(currentNames) !== JSON.stringify(originalNames);
    
    // Update UI
    const changeCount = Math.abs(currentNames.length - originalNames.length);
    document.getElementById('changeCount').textContent = hasChanges ? changeCount || 1 : 0;
    document.getElementById('changeStatus').textContent = hasChanges ? 'Pending changes' : 'No changes';
}

// Update staging area display to show differences
function updateStagingArea() {
    const container = document.getElementById('stagingArea');
    container.innerHTML = '';
    
    const currentNames = currentManifests.map(m => m.name || m);
    const originalNames = originalManifests.map(m => m.name || m);
    
    // Find additions
    const additions = currentNames.filter(name => !originalNames.includes(name));
    // Find removals  
    const removals = originalNames.filter(name => !currentNames.includes(name));
    
    if (additions.length === 0 && removals.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>Drag manifests to make changes</p></div>';
        return;
    }
    
    // Show removals
    removals.forEach(name => {
        const item = document.createElement('div');
        item.className = 'manifest-item';
        item.innerHTML = `
            <span class="manifest-name">- ${name}</span>
            <span class="manifest-type">remove</span>
        `;
        container.appendChild(item);
    });
    
    // Show additions
    additions.forEach(name => {
        const item = document.createElement('div');
        item.className = 'manifest-item';
        item.innerHTML = `
            <span class="manifest-name">+ ${name}</span>
            <span class="manifest-type">add</span>
        `;
        container.appendChild(item);
    });
}

// Reset changes
function resetChanges() {
    // Handle direct manifest file editing
    if (currentEditingManifest) {
        // Clear the editing state and return to home
        currentEditingManifest = null;
        currentEditingManifestPath = null;
        goHome();
        showAlert('Manifest editing session ended', 'info');
        return;
    }
    
    // Restore original manifests
    currentManifests = [...originalManifests];
    
    // Reload displays
    displayCurrentManifests(currentManifests);
    if (currentEntity) {
        loadAvailableManifestsForEntity(currentEntity);
    }
    
    updateChangeTracking();
    updateStagingArea();
    showAlert('Changes reset', 'info');
}

// Save changes
async function saveChanges() {
    // Handle direct manifest file editing
    if (currentEditingManifest) {
        showAlert('Manifest file has already been saved! You can now create a pull request.', 'info');
        return;
    }
    
    // Check if there are any changes
    const currentNames = currentManifests.map(m => m.name || m).sort();
    const originalNames = originalManifests.map(m => m.name || m).sort();
    
    if (JSON.stringify(currentNames) === JSON.stringify(originalNames)) {
        showAlert('No changes to save', 'info');
        return;
    }
    
    try {
        showLoading(true);
        
        // Send current manifests to backend
        const response = await fetch(`${API_BASE}/manifests/${currentEntity.file}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ manifests: currentNames })
        });
        
        if (!response.ok) {
            throw new Error('Failed to save changes');
        }
        
        // dont update originalManifests here. keep them for PR creation
        // and only update after PR is created or changes are reset
        
        showAlert('Changes saved to file! You can now create a PR or continue editing.', 'success');
        
        // Update UI to show saved status but keep tracking changes
        document.getElementById('changeStatus').textContent = 'Changes saved (PR not created)';
        
    } catch (error) {
        console.error('Save error:', error);
        showAlert('Failed to save changes. Please try again.', 'error');
    } finally {
        showLoading(false);
    }
}

// Create pull request
function createPullRequest() {
    // Handle direct manifest file editing
    if (currentEditingManifest) {
        createManifestFilePR();
        return;
    }
    
    // Check if there are any changes
    const currentNames = currentManifests.map(m => m.name || m);
    const originalNames = originalManifests.map(m => m.name || m);
    
    const additions = currentNames.filter(name => !originalNames.includes(name));
    const removals = originalNames.filter(name => !currentNames.includes(name));
    
    if (additions.length === 0 && removals.length === 0) {
        showAlert('No changes to create PR for', 'info');
        return;
    }
    
    // Populate PR form with defaults
    const entityName = currentEntity.name || currentEntity.serial || currentEntity.id;
    document.getElementById('branchName').value = `update-manifests-${entityName.toLowerCase().replace(/\./g, '-')}`;
    document.getElementById('prTitle').value = `Update manifest assignments for ${entityName}`;
    
    let changesList = [];
    removals.forEach(name => changesList.push(`- Remove ${name}`));
    additions.forEach(name => changesList.push(`- Add ${name}`));
    
    document.getElementById('prDescription').value = `Updates manifest assignments for ${entityName}:\n\n${changesList.join('\n')}`;
    
    // Show modal
    document.getElementById('prModal').classList.add('active');
}

// Close PR modal
function closePRModal() {
    document.getElementById('prModal').classList.remove('active');
}

// Submit pull request
async function submitPullRequest() {
    // Handle direct manifest file editing
    if (currentEditingManifest) {
        await submitManifestFilePR();
        return;
    }
    
    const branchName = document.getElementById('branchName').value.trim();
    const prTitle = document.getElementById('prTitle').value.trim();
    const prDescription = document.getElementById('prDescription').value.trim();
    
    if (!branchName || !prTitle) {
        showAlert('Please fill in branch name and PR title', 'error');
        return;
    }
    
    try {
        showLoading(true);
        closePRModal();
        
        // Get current manifest file content for GitHub App PR
        const manifestPath = `manifests/${currentEntity.file}`;
        const manifestContent = await getCurrentManifestFileContent();
        
        if (!manifestContent) {
            throw new Error('Failed to get current manifest content');
        }
        
        // Convert to base64
        const contentBase64 = btoa(unescape(encodeURIComponent(manifestContent)));
        
        // Create GitHub App PR request
        const response = await fetch(`${API_BASE}/pr-from-json-edits`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                owner: "", // From config
                repo: "dnshield",  // From config  
                base_branch: "main",
                feature_prefix: "feature",
                commit_message: prTitle,
                pr_title: prTitle,
                pr_body: prDescription,
                files: [{
                    path: manifestPath,
                    content_base64: contentBase64
                }]
            })
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                showAlert('Please sign in with GitHub to create PRs. Redirecting to login...', 'error');
                setTimeout(() => { window.location.href = `${API_BASE}/auth/login`; }, 1000);
                return;
            }
            const errorText = await response.text();
            throw new Error(`GitHub API error: ${errorText}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            showAlert(`Pull request created successfully! #${data.pr_number}`, 'success');
            console.log(`PR created: ${data.pr_url}`);
            console.log(`Branch: ${data.branch}`);
            console.log(`Commit: ${data.commit_sha}`);
            
            // Now update originalManifests since changes are committed
            originalManifests = [...currentManifests];
            updateChangeTracking();
            updateStagingArea();
            
        } else {
            showAlert(data.error || 'Failed to create pull request', 'error');
        }
        
    } catch (error) {
        console.error('PR error:', error);
        showAlert(`Failed to create pull request: ${error.message}`, 'error');
    } finally {
        showLoading(false);
    }
}

// Get current manifest file content with updated manifests
async function getCurrentManifestFileContent() {
    try {
        // Get the current manifest data from the server
        const response = await fetch(`${API_BASE}/manifests/${currentEntity.file}`);
        const data = await response.json();
        
        if (!data.raw) {
            throw new Error('No raw manifest data available');
        }

        // Get existing and current manifest lists
        const existingCatalogs = data.raw.catalogs || data.raw.included_manifests || [];
        const currentNames = currentManifests.map(m => m.name || m);

        // Build a map of existing paths (manifest name -> path)
        const existingPathMap = {};
        existingCatalogs.forEach(path => {
            if (!path || typeof path !== 'string') return;
            // Extract manifest name from path (e.g., "includes/domain/okta-allowlist" -> "okta-allowlist")
            const parts = path.split('/');
            if (parts.length < 2) return; // Skip malformed paths
            const manifestName = parts[parts.length - 1].replace('.json', '');
            if (manifestName) existingPathMap[manifestName] = path;
        });

        // Build updated catalogs: keep existing paths, generate only for new manifests
        const updatedCatalogs = currentNames.map(name => {
            // If manifest already exists with a path, keep it
            if (existingPathMap[name]) {
                return existingPathMap[name];
            }
            // Only generate path for NEW manifests
            return determineCatalogPath(name);
        });

        updatedCatalogs.sort();

        // Preserve field order by explicitly building in the correct order
        const updatedManifest = {};

        // Standard field order for DNShield manifests
        const fieldOrder = ['manifest_version', 'identifier', 'display_name', 'catalogs', 'included_manifests', 'metadata'];

        // Add fields in the correct order
        for (const key of fieldOrder) {
            if (key in data.raw) {
                if (key === 'catalogs' || key === 'included_manifests') {
                    updatedManifest[key] = updatedCatalogs;
                } else {
                    updatedManifest[key] = data.raw[key];
                }
            }
        }

        // Add any remaining fields that weren't in the standard order
        for (const key in data.raw) {
            if (!(key in updatedManifest)) {
                updatedManifest[key] = data.raw[key];
            }
        }

        // Convert back to formatted JSON
        return JSON.stringify(updatedManifest, null, 2) + '\n';

    } catch (error) {
        console.error('Error getting current manifest content:', error);
        return null;
    }
}

// Determine catalog path - uses dynamic lookup from backend
function determineCatalogPath(manifest) {
    // Remove .json extension if present
    manifest = manifest.replace('.json', '');

    if (manifestPathMap[manifest]) {
        return manifestPathMap[manifest];
    }
}

// UI Helper functions
function showLoading(show) {
    document.getElementById('loadingSection').classList.toggle('active', show);
}

function showAlert(message, type = 'info') {
    const alertBox = document.getElementById('alertBox');
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
    
    setTimeout(() => {
        hideAlert();
    }, 5000);
}

function hideAlert() {
    const alertBox = document.getElementById('alertBox');
    alertBox.style.display = 'none';
}

// Configuration management
async function checkConfiguration() {
    try {
        const response = await fetch(`${API_BASE}/config`);
        const data = await response.json();
        
        if (!data.configured) {
            // Show configuration modal
            openConfigModal();
        } else {
            // Configuration is valid, load available manifests
            loadAvailableManifests();
        }
    } catch (error) {
        console.error('Error checking configuration:', error);
        showAlert('Error connecting to server. Please ensure the server is running.', 'error');
    }
}

async function openConfigModal() {
    document.getElementById('configModal').classList.add('active');
    // Try to detect repository automatically
    await detectRepository();
}

function closeConfigModal() {
    document.getElementById('configModal').classList.remove('active');
}

async function detectRepository() {
    try {
        const response = await fetch(`${API_BASE}/config`);
        const data = await response.json();
        
        if (data.suggestions && data.suggestions.length > 0) {
            displayPathSuggestions(data.suggestions);
            
            // Auto-fill with the detected repository
            const detectedRepo = data.suggestions[0];
            if (detectedRepo) {
                document.getElementById('repoPath').value = detectedRepo.path;
                if (detectedRepo.valid) {
                    showConfigAlert('Repository detected automatically. Click Save Configuration to continue.', 'success');
                } else {
                    showConfigAlert('Repository detected but validation failed. Please check the path.', 'error');
                }
            }
        } else {
            showConfigAlert('No git repository detected. Please enter the path manually.', 'info');
        }
    } catch (error) {
        console.error('Error detecting repository:', error);
        showConfigAlert('Unable to detect repository. Please enter the path manually.', 'error');
    }
}

function displayPathSuggestions(suggestions) {
    const container = document.getElementById('suggestionsList');
    const suggestionsDiv = document.getElementById('pathSuggestions');
    
    container.innerHTML = '';
    
    suggestions.forEach(suggestion => {
        const suggestionDiv = document.createElement('div');
        suggestionDiv.className = `path-suggestion ${suggestion.valid ? 'valid' : ''}`;
        suggestionDiv.onclick = () => selectPath(suggestion.path);
        
        suggestionDiv.innerHTML = `
            <div class="path-text">${suggestion.path}</div>
            <div class="path-description">${suggestion.description}</div>
        `;
        
        container.appendChild(suggestionDiv);
    });
    
    suggestionsDiv.style.display = 'block';
}

function selectPath(path) {
    document.getElementById('repoPath').value = path;
    showConfigAlert(`Selected: ${path}`, 'info');
}

async function saveRepoPath() {
    const repoPath = document.getElementById('repoPath').value.trim();
    
    if (!repoPath) {
        showConfigAlert('Please enter a repository path.', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repo_path: repoPath })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }
        
        const data = await response.json();
        
        if (data.success) {
            showConfigAlert('Configuration saved successfully!', 'success');
            setTimeout(() => {
                closeConfigModal();
                loadAvailableManifests();
                showAlert('Repository configured successfully!', 'success');
            }, 1000);
        } else {
            showConfigAlert('Failed to save configuration.', 'error');
        }
    } catch (error) {
        console.error('Error saving configuration:', error);
        showConfigAlert(error.message || 'Failed to save configuration.', 'error');
    }
}

function showConfigAlert(message, type = 'info') {
    const alertBox = document.getElementById('configAlert');
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
    
    setTimeout(() => {
        alertBox.style.display = 'none';
    }, 5000);
}

// Domain Management Functions
function openDomainModal() {
    // Load available manifests for selection
    loadManifestOptions();
    document.getElementById('domainModal').classList.add('active');
    
    // Set initial state
    toggleDomainFields();
}

function closeDomainModal() {
    document.getElementById('domainModal').classList.remove('active');
    // Clear form
    document.getElementById('domainList').value = '';
    document.getElementById('newManifestName').value = '';
    document.getElementById('domainAlert').style.display = 'none';
    
    // Reset manifest view content
    document.getElementById('manifestContent').textContent = 'Select a manifest to view its contents...';
    document.getElementById('domainCount').textContent = '0';
    document.getElementById('manifestMetadata').style.display = 'none';
    
    // Clear any stored data
    window.currentManifestData = null;
}

function toggleDomainFields() {
    const action = document.getElementById('domainAction').value;
    const existingGroup = document.getElementById('existingManifestGroup');
    const newGroup = document.getElementById('newManifestGroup');
    const categoryGroup = document.getElementById('categoryGroup');
    const domainInputGroup = document.getElementById('domainInputGroup');
    const manifestViewGroup = document.getElementById('manifestViewGroup');
    const executeBtn = document.getElementById('executeBtn');
    
    if (action === 'create') {
        existingGroup.style.display = 'none';
        newGroup.style.display = 'block';
        categoryGroup.style.display = 'block';
        domainInputGroup.style.display = 'block';
        manifestViewGroup.style.display = 'none';
        executeBtn.textContent = 'Create Manifest';
        executeBtn.style.display = 'inline-block';
    } else if (action === 'view') {
        existingGroup.style.display = 'block';
        newGroup.style.display = 'none';
        categoryGroup.style.display = 'none';
        domainInputGroup.style.display = 'none';
        manifestViewGroup.style.display = 'block';
        executeBtn.style.display = 'none';
        
        // Set up manifest selection change handler for viewing
        const selectElement = document.getElementById('selectedManifest');
        selectElement.onchange = () => {
            if (selectElement.value) {
                console.log('Viewing manifest:', selectElement.value);
                viewManifest(selectElement.value);
            }
        };
    } else {
        existingGroup.style.display = 'block';
        newGroup.style.display = 'none';
        categoryGroup.style.display = 'none';
        domainInputGroup.style.display = 'block';
        manifestViewGroup.style.display = 'none';
        executeBtn.textContent = action === 'add' ? 'Add Domains' : 'Remove Domains';
        executeBtn.style.display = 'inline-block';
        
        // Set up manifest selection change handler for add/remove actions
        const selectElement = document.getElementById('selectedManifest');
        selectElement.onchange = () => {
            if (selectElement.value && (action === 'add' || action === 'remove')) {
                loadExistingDomainsForEdit(selectElement.value);
            }
        };
    }
}

async function loadManifestOptions() {
    try {
        // Get all available manifests without entity filtering
        const response = await fetch(`${API_BASE}/manifests/available`);
        const data = await response.json();
        
        const select = document.getElementById('selectedManifest');
        select.innerHTML = '<option value="">Choose manifest...</option>';
        
        if (data.manifests) {
            // Sort manifests by type then name
            const sortedManifests = data.manifests.sort((a, b) => {
                if (a.type !== b.type) {
                    return a.type.localeCompare(b.type);
                }
                return a.name.localeCompare(b.name);
            });
            
            let currentType = '';
            sortedManifests.forEach(manifest => {
                // Add type separator
                if (manifest.type !== currentType) {
                    if (currentType !== '') {
                        const separator = document.createElement('option');
                        separator.disabled = true;
                        separator.textContent = '---';
                        select.appendChild(separator);
                    }
                    currentType = manifest.type;
                    const typeHeader = document.createElement('option');
                    typeHeader.disabled = true;
                    typeHeader.textContent = `${manifest.type.toUpperCase()} MANIFESTS`;
                    select.appendChild(typeHeader);
                }
                
                const option = document.createElement('option');
                option.value = manifest.name;
                option.textContent = manifest.name;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading manifest options:', error);
        showDomainAlert('Failed to load manifest options', 'error');
    }
}

async function processDomainRequest() {
    const action = document.getElementById('domainAction').value;
    
    // Handle view action separately (shouldn't happen since button is hidden)
    if (action === 'view') {
        const manifestName = document.getElementById('selectedManifest').value;
        if (manifestName) {
            viewManifest(manifestName);
        } else {
            showDomainAlert('Please select a manifest to view', 'error');
        }
        return;
    }
    
    const domainList = document.getElementById('domainList').value.trim();
    
    if (!domainList) {
        showDomainAlert('Please enter at least one domain', 'error');
        return;
    }
    
    // Parse domains (one per line)
    let domains = domainList.split('\n')
        .map(domain => domain.trim())
        .filter(domain => domain.length > 0 && !domain.startsWith('#')); // Filter out comments
    
    // For add action, only process domains after the "ADD NEW DOMAINS BELOW:" separator
    if (action === 'add') {
        const lines = domainList.split('\n');
        const separatorIndex = lines.findIndex(line => line.includes('ADD NEW DOMAINS BELOW:'));
        
        if (separatorIndex >= 0) {
            // Only take domains after the separator
            domains = lines.slice(separatorIndex + 1)
                .map(domain => domain.trim())
                .filter(domain => domain.length > 0 && !domain.startsWith('#'));
        }
    }
    
    if (domains.length === 0) {
        showDomainAlert('Please enter at least one valid domain', 'error');
        return;
    }
    
    let manifestName;
    let category;
    
    if (action === 'create') {
        manifestName = document.getElementById('newManifestName').value.trim();
        category = document.getElementById('manifestCategory').value;
        
        if (!manifestName) {
            showDomainAlert('Please enter a manifest name', 'error');
            return;
        }
        
        // Validate manifest name
        if (!/^[a-z0-9\-_]+$/.test(manifestName)) {
            showDomainAlert('Manifest name must contain only lowercase letters, numbers, hyphens, and underscores', 'error');
            return;
        }
    } else {
        manifestName = document.getElementById('selectedManifest').value;
        
        if (!manifestName) {
            showDomainAlert('Please select a manifest', 'error');
            return;
        }
    }
    
    try {
        const response = await fetch(`${API_BASE}/domains`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: action,
                manifest_name: manifestName,
                domains: domains,
                category: category
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showDomainAlert(result.message, 'success');
            
            // For create action, refresh available manifests and close
            if (action === 'create') {
                setTimeout(() => {
                    closeDomainModal();
                    loadAvailableManifests();
                    showAlert('New manifest created! You can now assign it to users or continue editing.', 'success');
                }, 1500);
            } else {
                // For add/remove actions, show that files were modified and provide save/PR options
                setTimeout(() => {
                    closeDomainModal();
                    showAlert('Domain changes saved to file! You can now create a pull request or continue editing.', 'info');
                    
                    // Show the manifest editing interface with save/PR buttons
                    showManifestEditInterface(manifestName);
                    
                    // If we're currently viewing an entity, reload their manifests to show updates
                    if (currentEntity) {
                        loadEntityManifests(currentEntity);
                    }
                }, 1500);
            }
        } else {
            showDomainAlert(result.error || 'Operation failed', 'error');
        }
    } catch (error) {
        console.error('Error processing domain request:', error);
        showDomainAlert('Failed to process request', 'error');
    }
}

async function viewManifest(manifestName) {
    try {
        const response = await fetch(`${API_BASE}/manifest/view/${manifestName}`);
        const result = await response.json();
        
        if (result.success) {
            displayManifestContents(result);
        } else {
            showDomainAlert(result.error || 'Failed to load manifest', 'error');
        }
    } catch (error) {
        console.error('Error viewing manifest:', error);
        showDomainAlert('Failed to load manifest', 'error');
    }
}

function displayManifestContents(manifestData) {
    // Update domain count
    document.getElementById('domainCount').textContent = manifestData.domain_count;
    
    // Display metadata if available
    const metadataDiv = document.getElementById('manifestMetadata');
    const metadataContent = document.getElementById('metadataContent');
    
    if (manifestData.metadata && Object.keys(manifestData.metadata).length > 0) {
        metadataDiv.style.display = 'block';
        
        let metadataHtml = '';
        for (const [key, value] of Object.entries(manifestData.metadata)) {
            metadataHtml += `<div style="margin-bottom: 5px;"><strong>${key}:</strong> ${value}</div>`;
        }
        
        // Add file info
        if (manifestData.last_modified) {
            const date = new Date(manifestData.last_modified);
            metadataHtml += `<div style="margin-bottom: 5px;"><strong>Last Modified:</strong> ${date.toLocaleString()}</div>`;
        }
        metadataHtml += `<div style="margin-bottom: 5px;"><strong>Path:</strong> ${manifestData.path}</div>`;
        
        metadataContent.innerHTML = metadataHtml;
    } else {
        metadataDiv.style.display = 'none';
    }
    
    // Display domains
    const contentDiv = document.getElementById('manifestContent');
    if (manifestData.domains && manifestData.domains.length > 0) {
        const domainList = manifestData.domains.map((domain, index) => 
            `${(index + 1).toString().padStart(3, ' ')}. ${domain}`
        ).join('\n');
        contentDiv.textContent = domainList;
    } else {
        contentDiv.textContent = 'No domains found in this manifest.';
    }
    
    // Store current manifest data for export
    window.currentManifestData = manifestData;
}

function exportDomains() {
    if (!window.currentManifestData || !window.currentManifestData.domains) {
        showDomainAlert('No manifest data to export', 'error');
        return;
    }
    
    const manifestName = window.currentManifestData.name;
    const domains = window.currentManifestData.domains;
    
    // Create downloadable text file
    const content = domains.join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    
    // Create temporary link and click it
    const a = document.createElement('a');
    a.href = url;
    a.download = `${manifestName}-domains.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showDomainAlert(`Exported ${domains.length} domains to ${manifestName}-domains.txt`, 'success');
}

async function loadExistingDomainsForEdit(manifestName) {
    try {
        const response = await fetch(`${API_BASE}/manifest/view/${manifestName}`);
        const result = await response.json();
        
        if (result.success && result.domains) {
            const domainTextarea = document.getElementById('domainList');
            const action = document.getElementById('domainAction').value;
            
            if (action === 'add') {
                // For add action, show ALL existing domains as reference with separator
                const existingDomainsText = result.domains.join('\n');
                domainTextarea.value = `# EXISTING DOMAINS (${result.domains.length}) - DO NOT EDIT ABOVE THIS LINE\n${existingDomainsText}\n\n# ADD NEW DOMAINS BELOW:\n`;
                domainTextarea.placeholder = 'Add new domains below the separator line';
                showDomainAlert(`Showing all ${result.domains.length} existing domains above. Add new domains below the separator.`, 'info');
            } else if (action === 'remove') {
                // For remove action, populate with existing domains so user can delete lines
                domainTextarea.value = result.domains.join('\n');
                domainTextarea.placeholder = 'Remove lines for domains you want to delete';
                showDomainAlert(`Loaded ${result.domains.length} domains. Remove lines for domains you want to delete.`, 'info');
            }
        }
    } catch (error) {
        console.error('Error loading existing domains:', error);
        showDomainAlert('Failed to load existing domains', 'error');
    }
}

function goHome() {
    // Hide content section and reset state
    document.getElementById('contentSection').style.display = 'none';
    
    // Clear current entity and manifests
    currentEntity = null;
    originalManifests = [];
    currentManifests = [];
    
    // Clear manifest editing state
    currentEditingManifest = null;
    currentEditingManifestPath = null;
    
    // Clear search input
    document.getElementById('searchInput').value = '';
    
    // Hide any alerts
    hideAlert();
    
    // Reset entity info display
    document.getElementById('entityName').textContent = '-';
    document.getElementById('entityType').textContent = '-';
    document.getElementById('entityFile').textContent = '-';
    
    // Clear manifest lists
    document.getElementById('currentManifests').innerHTML = '<div class="empty-state"><p>Search for a user, machine, or group to begin</p></div>';
    document.getElementById('availableManifests').innerHTML = '<div class="empty-state"><p>Available manifests will appear here</p></div>';
    
    // Reset change tracking
    document.getElementById('changeCount').textContent = '0';
    document.getElementById('changeStatus').textContent = 'No changes';
}

function showDomainAlert(message, type = 'info') {
    const alertBox = document.getElementById('domainAlert');
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
    
    setTimeout(() => {
        if (type !== 'error') {
            alertBox.style.display = 'none';
        }
    }, 5000);
}

// Global state for manifest editing
let currentEditingManifest = null;
let currentEditingManifestPath = null;

// Show manifest editing interface after domain changes
function showManifestEditInterface(manifestName) {
    currentEditingManifest = manifestName;
    
    // Create a temporary entity-like object for the manifest file editing
    const manifestEntity = {
        name: manifestName,
        file: `includes/${getManifestCategoryFromName(manifestName)}/${manifestName}.json`,
        type: 'manifest'
    };
    
    // Show the content section but with manifest editing context
    document.getElementById('contentSection').style.display = 'block';
    document.getElementById('entityName').textContent = `Manifest: ${manifestName}`;
    document.getElementById('entityType').textContent = 'Direct File Edit';
    document.getElementById('entityFile').textContent = manifestEntity.file;
    
    // Hide the manifest lists since we're editing a file directly
    document.getElementById('currentManifests').innerHTML = '<div class="empty-state"><p>Direct manifest file editing mode</p></div>';
    document.getElementById('availableManifests').innerHTML = '<div class="empty-state"><p>Use "Manage Domains & Manifests" to make more changes</p></div>';
    
    // Show save/PR controls for manifest editing
    document.getElementById('changeStatus').textContent = 'Manifest file modified - use Save/PR buttons';
    document.getElementById('changeCount').textContent = '1';
    
    showAlert(`Manifest "${manifestName}" has been modified. Use the Save Changes and Create Pull Request buttons below to commit your changes.`, 'success');
}

// Helper function to determine manifest category from name
function getManifestCategoryFromName(manifestName) {
    return 'domain'; // default
}

// Create pull request for direct manifest file editing
function createManifestFilePR() {
    // Populate PR form with defaults for manifest editing
    const manifestName = currentEditingManifest;
    document.getElementById('branchName').value = `update-manifest-${manifestName.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
    document.getElementById('prTitle').value = `Update ${manifestName} manifest`;
    document.getElementById('prDescription').value = `Updates to the ${manifestName} manifest file:\n\n- Modified domain rules\n- Updated via Manifest Editor`;
    
    // Show modal
    document.getElementById('prModal').classList.add('active');
}

// Submit PR function for manifest file editing
async function submitManifestFilePR() {
    const branchName = document.getElementById('branchName').value.trim();
    const prTitle = document.getElementById('prTitle').value.trim();
    const prDescription = document.getElementById('prDescription').value.trim();
    
    if (!branchName || !prTitle) {
        showAlert('Please fill in branch name and PR title', 'error');
        return;
    }
    
    try {
        showLoading(true);
        closePRModal();
        
        // Get current manifest file content
        const manifestCategory = getManifestCategoryFromName(currentEditingManifest);
        const manifestPath = `manifests/includes/${manifestCategory}/${currentEditingManifest}.json`;
        
        // Read the current file content from the server
        const manifestContent = await getCurrentManifestFileContentForEditing();
        
        if (!manifestContent) {
            throw new Error('Failed to get current manifest content');
        }
        
        // Convert to base64
        const contentBase64 = btoa(unescape(encodeURIComponent(manifestContent)));
        
        // Create GitHub App PR request
        const response = await fetch(`${API_BASE}/pr-from-json-edits`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                owner: "", // From config
                repo: "dnshield",  // From config  
                base_branch: "main",
                feature_prefix: "feature",
                commit_message: prTitle,
                pr_title: prTitle,
                pr_body: prDescription,
                files: [{
                    path: manifestPath,
                    content_base64: contentBase64
                }]
            })
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                showAlert('Please sign in with GitHub to create PRs. Redirecting to login...', 'error');
                setTimeout(() => { window.location.href = `${API_BASE}/auth/login`; }, 1000);
                return;
            }
            const errorText = await response.text();
            throw new Error(`GitHub API error: ${errorText}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            showAlert(`Pull request created successfully! #${data.pr_number}`, 'success');
            console.log(`PR created: ${data.pr_url}`);
            console.log(`Branch: ${data.branch}`);
            console.log(`Commit: ${data.commit_sha}`);
            
            // Clear the editing state
            currentEditingManifest = null;
            currentEditingManifestPath = null;
            
            // Reset the interface
            document.getElementById('changeStatus').textContent = 'No changes';
            document.getElementById('changeCount').textContent = '0';
            
        } else {
            showAlert(data.error || 'Failed to create pull request', 'error');
        }
        
    } catch (error) {
        console.error('PR error:', error);
        showAlert(`Failed to create pull request: ${error.message}`, 'error');
    } finally {
        showLoading(false);
    }
}

// Get current manifest file content for editing
async function getCurrentManifestFileContentForEditing() {
    try {
        const response = await fetch(`${API_BASE}/manifest/view/${currentEditingManifest}`);
        const result = await response.json();
        
        if (result.success && result.raw_content) {
            return result.raw_content;
        } else {
            throw new Error('No raw content available');
        }
        
    } catch (error) {
        console.error('Error getting current manifest content:', error);
        return null;
    }
}

// Demo data fallback
function useDemoData() {
    if (searchType === 'user' && currentEntity) {
        currentManifests = [
            { name: 'global-allowlist', type: 'global' },
            { name: 'global-blocklist', type: 'global' },
        ];
        
        displayCurrentManifests(currentManifests);
        
        const demoAvailable = [
        ];
        
        displayAvailableManifests(demoAvailable);
    }
}
// --- Auth helpers ---
async function updateAuthUI() {
    try {
        const res = await fetch(`${API_BASE}/auth/status`);
        const data = await res.json();
        const authContainer = document.getElementById('authStatus');
        if (!authContainer) return;
        if (data.authenticated) {
            authContainer.innerHTML = `Signed in as <strong>${data.user}</strong> · <a href="#" id="logoutLink">Sign out</a>`;
            const logout = document.getElementById('logoutLink');
            if (logout) logout.addEventListener('click', async (e) => {
                e.preventDefault();
                await fetch(`${API_BASE}/auth/logout`, { method: 'POST' });
                window.location.reload();
            });
        } else {
            authContainer.innerHTML = `<a class="btn btn-secondary" href="${API_BASE}/auth/login">Sign in with GitHub</a>`;
        }
    } catch (e) {
        // ignore
    }
}
