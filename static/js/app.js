// DarkOrca Web UI JavaScript

// Suppress harmless browser extension errors
window.addEventListener('error', (e) => {
    // Ignore errors from browser extensions
    const errorMsg = e.message || e.error?.message || String(e);
    if (errorMsg && (
        errorMsg.includes('MutationObserver') ||
        errorMsg.includes('asynchronous response') ||
        errorMsg.includes('message channel closed') ||
        errorMsg.includes('not of type') ||
        // Check if error is from extension scripts
        e.filename?.includes('extension://') ||
        e.filename?.includes('chrome-extension://') ||
        e.filename?.includes('moz-extension://')
    )) {
        e.preventDefault();
        e.stopPropagation();
        return false;
    }
}, true); // Use capture phase to catch errors early

// Suppress unhandled promise rejections from extensions
window.addEventListener('unhandledrejection', (e) => {
    const errorMsg = e.reason?.message || String(e.reason || '');
    if (errorMsg && (
        errorMsg.includes('asynchronous response') ||
        errorMsg.includes('message channel closed') ||
        errorMsg.includes('MutationObserver')
    )) {
        e.preventDefault();
        e.stopPropagation();
    }
});

let currentScanId = null;
let statusCheckInterval = null;
let lastRemainingTime = null; // Track last remaining time to prevent increases
let lastScannerName = null; // Track current scanner name to reset estimate when scanner changes

// Form submission handler - prevent default form behavior
// Wait for DOM to be ready before attaching handler
function setupFormHandler() {
    const scanForm = document.getElementById('scanForm');
    if (!scanForm) {
        console.error('scanForm element not found!');
        return;
    }
    
    // Remove any existing listeners to prevent duplicates
    const newForm = scanForm.cloneNode(true);
    scanForm.parentNode.replaceChild(newForm, scanForm);
    
    // Re-get the form element
    const form = document.getElementById('scanForm');
    
    // Setup scan mode listener after form is cloned
    setupScanModeListener();
    
    form.addEventListener('submit', async function(e) {
        // CRITICAL: Prevent default form submission which causes page reload/clear
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        
        console.log('Form submit handler called - preventing default');
        
        // Store form values IMMEDIATELY before any operations
        const targetInput = document.getElementById('targetInput');
        const scanModeSelect = document.getElementById('scanMode');
        const emailInput = document.getElementById('email');
        
        if (!targetInput || !scanModeSelect) {
            console.error('Form elements not found');
            return false;
        }
        
        // Store values immediately
        const target = targetInput.value.trim();
        const scanMode = scanModeSelect.value;
        const email = emailInput?.value.trim() || '';
        const exhaustiveCheckbox = document.getElementById('exhaustiveMode');
        const exhaustive = exhaustiveCheckbox ? exhaustiveCheckbox.checked : false;
        
        console.log('Form values captured:', { target, scanMode, email, exhaustive });
        
        // All scanners enabled by default - no need to expose to user
        const enableSQLMap = true;
        const enableWPScan = true;
        const enableNuclei = true;
        const enableNmap = true;
        
        // Validate target
        if (!target || target.length === 0) {
            alert('Please enter a target URL or domain');
            targetInput.focus();
            return false;
        }
        
        // Disable form to prevent double submission
        const startBtn = document.getElementById('startScanBtn');
        if (startBtn) {
            startBtn.disabled = true;
            startBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Running...';
        }
        
        // Reset remaining time tracker for new scan
        lastRemainingTime = null;
        lastScannerName = null;
        
        try {
            console.log('Starting scan with target:', target);
            if (email) {
                console.log('Email notification will be sent to:', email);
            }
            // Get CSRF token if available
            let csrfToken = window.csrfToken;
            if (!csrfToken) {
                const metaTag = document.querySelector('meta[name="csrf-token"]');
                csrfToken = metaTag ? metaTag.content : null;
            }
            
            if (!csrfToken) {
                console.error('CSRF token not found! Cannot submit scan request.');
                alert('Error: CSRF token missing. Please refresh the page and try again.');
                if (startBtn) {
                    startBtn.disabled = false;
                    startBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Scan';
                }
                return false;
            }
            
            console.log('CSRF token found:', csrfToken.substring(0, 10) + '...');
            
            const headers = {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            };
            
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({
                    target,
                    scan_mode: scanMode,
                    email: email,
                    enable_sqlmap: enableSQLMap,
                    enable_wpscan: enableWPScan,
                    enable_nuclei: enableNuclei,
                    enable_nmap: enableNmap,
                    exhaustive: exhaustive,
                    csrf_token: csrfToken,  // Also include in body for compatibility
                }),
            });
            
            const data = await response.json();
            console.log('Response status:', response.status, 'Data:', data);
            
            if (response.ok) {
                if (data.scan_id) {
                    currentScanId = data.scan_id;
                    console.log('Scan started with ID:', currentScanId);
                    // Validate scan_id format (should have underscores, not spaces)
                    if (currentScanId.includes(' ')) {
                        console.error('WARNING: scan_id contains spaces:', currentScanId);
                    }
                    
                    // IMPORTANT: Form values are preserved - they're still in the DOM
                    // We don't clear them, and preventDefault() prevents form reset
                    // Verify values are still there
                    console.log('After scan start - targetInput value:', document.getElementById('targetInput')?.value);
                    
                    showProgress();
                    startStatusCheck();
                } else {
                    throw new Error('No scan_id in response');
                }
            } else {
                const errorMsg = data.error || data.message || 'Failed to start scan';
                console.error('Scan start error:', errorMsg);
                alert('Error: ' + errorMsg);
                // Restore button but keep form values
                if (startBtn) {
                    startBtn.disabled = false;
                    startBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Scan';
                }
            }
        } catch (error) {
            console.error('Scan start exception:', error);
            alert('Failed to start scan: ' + error.message + '. Please check the console for details.');
            // Restore button but keep form values
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Scan';
            }
        }
        
        // CRITICAL: Return false to prevent any form submission
        return false;
    }, { capture: true, passive: false }); // Use capture phase and non-passive
}

// Setup form handler when DOM is ready
function initializeForm() {
    setupFormHandler();
    // setupScanModeListener is called inside setupFormHandler after form cloning
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeForm);
} else {
    // DOM is already ready
    initializeForm();
}

function showProgress() {
    // Show progress section
    const progressSection = document.getElementById('scanProgress');
    const resultsSection = document.getElementById('scanResults');
    const cancelBtn = document.getElementById('cancelScanBtn');
    
    if (progressSection) {
        progressSection.classList.remove('hidden');
        // Scroll to progress section
        progressSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    
    if (resultsSection) {
        resultsSection.classList.add('hidden');
    }
    
    if (cancelBtn) {
        cancelBtn.classList.remove('hidden');
    }
    
    // Initialize progress display
    const progressBar = document.getElementById('progressBar');
    const currentScanner = document.getElementById('currentScanner');
    const scannerProgress = document.getElementById('scannerProgress');
    const elapsedTimeText = document.getElementById('elapsedTimeText');
    const estimatedTimeText = document.getElementById('estimatedTimeText');
    
    if (progressBar) progressBar.style.width = '0%';
    if (currentScanner) currentScanner.textContent = 'Initializing scan...';
    if (scannerProgress) scannerProgress.textContent = 'Preparing scanners...';
    if (elapsedTimeText) elapsedTimeText.textContent = '0s';
    if (estimatedTimeText) estimatedTimeText.textContent = 'Calculating...';
}

function cancelScan() {
    if (!currentScanId) return;
    
    if (confirm('Are you sure you want to cancel this scan?')) {
        fetch(`/api/scan/${currentScanId}/cancel`, { method: 'POST' })
            .then(() => {
                if (statusCheckInterval) {
                    clearInterval(statusCheckInterval);
                }
                currentScanId = null;
                // Don't reset form - keep user input
                // resetForm();
                alert('Scan cancelled');
            })
            .catch(err => {
                console.error('Cancel error:', err);
                alert('Failed to cancel scan');
            });
    }
}

function startStatusCheck() {
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
    }
    
    // Poll every 1 second for real-time updates
    let consecutiveErrors = 0;
    const maxConsecutiveErrors = 5;
    
    statusCheckInterval = setInterval(async () => {
        if (!currentScanId) return;
        
        try {
            // Note: Underscores are valid in URL paths, so we don't need to encode
            // Only encode if scan_id contains characters that need encoding
            const response = await fetch(`/api/scan/${currentScanId}/status`);
            
            // Reset error counter on successful fetch
            consecutiveErrors = 0;
            
            if (response.status === 404) {
                // Scan not found - might have been cleared or server restarted
                console.warn(`Scan not found (scan_id: ${currentScanId}), clearing interval`);
                clearInterval(statusCheckInterval);
                currentScanId = null;
                resetForm();
                alert('Scan session expired. Please start a new scan.');
                return;
            }
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const status = await response.json();
            
            if (status.status === 'completed') {
                clearInterval(statusCheckInterval);
                loadResults();
            } else if (status.status === 'error') {
                clearInterval(statusCheckInterval);
                alert('Scan failed: ' + (status.error || 'Unknown error'));
                resetForm();
            } else if (status.status === 'running') {
                updateProgress(status);
            }
        } catch (error) {
            consecutiveErrors++;
            console.error('Status check error:', error);
            
            // If we get too many consecutive errors, assume server is down
            if (consecutiveErrors >= maxConsecutiveErrors) {
                console.error('Too many consecutive errors, stopping status checks');
                clearInterval(statusCheckInterval);
                currentScanId = null;
                resetForm();
                alert('Lost connection to server. Please refresh the page and start a new scan.');
            }
        }
    }, 1000);  // Check every 1 second for real-time updates
}

function updateProgress(status) {
    // Ensure progress section is visible
    const progressSection = document.getElementById('scanProgress');
    if (progressSection && progressSection.classList.contains('hidden')) {
        progressSection.classList.remove('hidden');
    }
    
    const progressBar = document.getElementById('progressBar');
    const scanStatus = document.getElementById('scanStatus');
    const currentScanner = document.getElementById('currentScanner');
    const scannerProgress = document.getElementById('scannerProgress');
    const elapsedTimeText = document.getElementById('elapsedTimeText');
    const estimatedTimeText = document.getElementById('estimatedTimeText');
    
    if (!progressBar || !scanStatus || !currentScanner || !scannerProgress || !elapsedTimeText || !estimatedTimeText) {
        console.warn('Progress elements not found');
        return;
    }
    
    // Update progress bar
    const progress = status.progress || 0;
    progressBar.style.width = progress + '%';
    
    // Update status
    if (status.status === 'running') {
        scanStatus.textContent = 'Running';
        scanStatus.className = 'text-sm text-green-600 font-medium';
    } else if (status.status === 'completed') {
        scanStatus.textContent = 'Completed';
        scanStatus.className = 'text-sm text-blue-600 font-medium';
    } else {
        scanStatus.textContent = 'Processing...';
        scanStatus.className = 'text-sm text-gray-600';
    }
    
    // Update current scanner
    if (status.current_scanner) {
        currentScanner.textContent = status.current_scanner;
    } else {
        currentScanner.textContent = 'Initializing scan...';
    }
    
    // Update estimate label to clarify it's for current step
    const estimatedTimeLabel = document.getElementById('estimatedTimeLabel');
    if (estimatedTimeLabel && status.current_scanner_name) {
        // Show which scanner the estimate is for
        const scannerName = status.current_scanner_name.toLowerCase().replace('running ', '').replace('...', '');
        estimatedTimeLabel.textContent = `Est. for ${scannerName}: `;
    } else if (estimatedTimeLabel) {
        estimatedTimeLabel.textContent = 'Est. for current step: ';
    }
    
    // Update scanner progress
    if (status.scanners_total && status.scanners_completed !== undefined) {
        const current = Math.min(status.scanners_completed, status.scanners_total);
        scannerProgress.textContent = `Scanner ${current} of ${status.scanners_total}`;
    } else {
        scannerProgress.textContent = 'Initializing...';
    }
    
    // Update elapsed time
    if (status.elapsed_seconds !== undefined) {
        elapsedTimeText.textContent = formatTime(status.elapsed_seconds);
    } else {
        elapsedTimeText.textContent = '0s';
    }
    
    // Update estimated remaining time (per-scanner estimate)
    let displayRemaining = null;
    
    // Prefer per-scanner estimate if available (more accurate)
    if (status.is_per_scanner_estimate && status.estimated_remaining_seconds !== undefined && status.estimated_remaining_seconds !== null) {
        // Per-scanner estimate - this is for the current scanner only
        displayRemaining = Math.max(0, status.estimated_remaining_seconds);
        // Reset tracker when switching scanners
        if (status.current_scanner_name && status.current_scanner_name !== lastScannerName) {
            lastRemainingTime = null;
            lastScannerName = status.current_scanner_name;
        }
    } else if (status.estimated_remaining_seconds !== undefined && status.estimated_remaining_seconds !== null && status.estimated_remaining_seconds > 0) {
        // Overall estimate fallback
        displayRemaining = status.estimated_remaining_seconds;
    } else if (status.progress && status.progress > 0 && status.elapsed_seconds && status.elapsed_seconds > 0) {
        // Calculate estimate based on elapsed time and progress (less accurate)
        const elapsed = status.elapsed_seconds;
        const calculated = Math.round((elapsed / status.progress) * (100 - status.progress));
        if (calculated > 0) {
            displayRemaining = calculated;
        }
    }
    
    // Only update if remaining time is decreasing or if we don't have a previous value
    // This prevents the weird behavior of time going up
    if (displayRemaining !== null && displayRemaining > 0) {
        // Only show estimate if it's greater than 0
        if (lastRemainingTime === null || displayRemaining <= lastRemainingTime || status.is_per_scanner_estimate) {
            // Time is decreasing, first estimate, or per-scanner estimate (can reset)
            estimatedTimeText.textContent = `~${formatTime(displayRemaining)}`;
            lastRemainingTime = displayRemaining;
        } else {
            // Time would increase - keep showing the last (lower) value
            estimatedTimeText.textContent = `~${formatTime(lastRemainingTime)}`;
        }
    } else if (displayRemaining === 0 && status.status === 'running') {
        // Scanner is still running but estimate is 0 (took longer than expected)
        estimatedTimeText.textContent = 'Finishing...';
        lastRemainingTime = 0;
    } else if (status.progress && status.progress >= 95) {
        // Almost done
        estimatedTimeText.textContent = 'Almost done...';
        lastRemainingTime = 0;
    } else {
        estimatedTimeText.textContent = 'Calculating...';
    }
}

function formatTime(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
    }
}

async function loadResults(retryCount = 0) {
    // Check if we're loading from a shareable URL
    const urlParams = new URLSearchParams(window.location.search);
    const shareableId = urlParams.get('id') || getShareableIdFromPath();
    
    if (shareableId) {
        // Load from shareable URL
        try {
            const response = await fetch(`/api/results/${shareableId}`);
            if (!response.ok) {
                throw new Error('Results not found or expired');
            }
            const results = await response.json();
            displayResults(results);
            showShareableUrl(shareableId);
            // Hide scan form when viewing shared results
            const scanForm = document.getElementById('scanForm');
            if (scanForm) {
                scanForm.style.display = 'none';
            }
            return;
        } catch (error) {
            console.error('Error loading shareable results:', error);
            alert('Failed to load results: ' + error.message);
            return;
        }
    }
    
    // Regular scan results loading
    if (!currentScanId) return;
    
    const maxRetries = 10;
    
    try {
        const response = await fetch(`/api/scan/${currentScanId}/results`);
        
        if (!response.ok) {
            if (response.status === 404) {
                // Results not ready yet, retry after a short delay
                if (retryCount < maxRetries) {
                    console.log(`Results not ready, retrying... (${retryCount + 1}/${maxRetries})`);
                    setTimeout(() => loadResults(retryCount + 1), 2000);
                    return;
                } else {
                    throw new Error('Results not available after multiple retries. The scan may have failed or the session expired.');
                }
            }
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const results = await response.json();
        
        if (!results || !results.risk_score) {
            throw new Error('Invalid results format');
        }
        
        displayResults(results);
        
        // Show shareable URL if available (pass results data for saving)
        if (results.shareable_id) {
            showShareableUrl(results.shareable_id, results);
        }
        
        resetForm();
    } catch (error) {
        console.error('Error loading results:', error);
        
        // Only show alert if we've exhausted retries
        if (retryCount >= maxRetries) {
            alert('Failed to load results: ' + error.message);
        } else {
            // Retry on connection errors
            setTimeout(() => loadResults(retryCount + 1), 2000);
        }
    }
}

function getShareableIdFromPath() {
    // Check if URL path is /results/<id>
    const path = window.location.pathname;
    const match = path.match(/^\/results\/([a-f0-9]{16})$/);
    return match ? match[1] : null;
}

function showShareableUrl(shareableId) {
    // Create or update shareable URL display
    let shareableDiv = document.getElementById('shareableUrlDiv');
    if (!shareableDiv) {
        // Create the div if it doesn't exist
        const resultsSection = document.getElementById('scanResults');
        if (resultsSection) {
            shareableDiv = document.createElement('div');
            shareableDiv.id = 'shareableUrlDiv';
            shareableDiv.className = 'card p-4 mb-6';
            shareableDiv.style.background = 'rgba(0, 0, 0, 0.3)';
            shareableDiv.style.border = '1px solid rgba(255, 255, 255, 0.08)';
            shareableDiv.style.borderRadius = '0.5rem';
            resultsSection.insertBefore(shareableDiv, resultsSection.firstChild);
        } else {
            return; // Can't add if results section doesn't exist
        }
    }
    
    const shareableUrl = `${window.location.origin}/results/${shareableId}`;
    
    // Determine download URL based on whether we have currentScanId or shareableId
    const downloadUrl = currentScanId 
        ? `/api/scan/${currentScanId}/download/pdf`
        : `/api/results/${shareableId}/download/pdf`;
    
    shareableDiv.innerHTML = `
        <div class="flex items-center justify-between">
            <div class="flex-1">
                <h3 class="text-lg font-semibold mb-2" style="color: var(--text-main);">
                    <i class="fas fa-share-alt mr-2" style="color: var(--accent);"></i>
                    Shareable Results Link
                </h3>
                <p class="text-sm mb-3" style="color: var(--text-muted);">
                    Share this link to view these scan results without rerunning the scan. Results are stored for 30 days.
                </p>
                <div class="flex items-center gap-2 mb-3">
                    <input 
                        type="text" 
                        id="shareableUrlInput" 
                        value="${shareableUrl}" 
                        readonly 
                        class="flex-1 px-4 py-2 rounded"
                        style="background: rgba(0, 0, 0, 0.5); border: 1px solid rgba(255, 255, 255, 0.2); color: var(--text-main);"
                    />
                    <button 
                        onclick="copyShareableUrl()" 
                        class="px-4 py-2 rounded btn-primary"
                        style="white-space: nowrap;"
                    >
                        <i class="fas fa-copy mr-2"></i>Copy Link
                    </button>
                </div>
                <div class="flex items-center gap-2">
                    <button 
                        id="downloadPdfBtn"
                        onclick="downloadPDF('${downloadUrl}')" 
                        class="px-4 py-2 rounded"
                        style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap;"
                    >
                        <i class="fas fa-file-pdf mr-2"></i>Download PDF
                    </button>
                    ${(currentScanId || shareableId) ? `
                    <button 
                        id="saveToProfileBtn"
                        onclick="saveScanToProfile('${shareableId || ''}')" 
                        class="px-4 py-2 rounded"
                        style="background: rgba(34, 197, 94, 0.2); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); white-space: nowrap;"
                    >
                        <i class="fas fa-bookmark mr-2"></i>Save to Profile
                    </button>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

async function saveScanToProfile(shareableId = null) {
    const scanId = currentScanId || (currentResultsData?.scan_id);
    const shareableIdToUse = shareableId || currentResultsData?.shareable_id;
    
    if (!scanId && !shareableIdToUse) {
        alert('No scan to save');
        return;
    }
    
    const btn = document.getElementById('saveToProfileBtn');
    const originalHTML = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Saving...';
    }
    
    try {
        // Get CSRF token
        const csrfToken = window.csrfToken || document.querySelector('meta[name="csrf-token"]')?.content;
        const headers = { 'Content-Type': 'application/json' };
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }
        
        const response = await fetch('/api/profile/save-scan', {
            method: 'POST',
            headers: headers,
            credentials: 'same-origin',  // Include cookies (session cookie) with request
            body: JSON.stringify({
                scan_id: scanId || 'shared_' + shareableIdToUse,  // Use scan_id if available, otherwise generate one for shared
                shareable_id: shareableIdToUse,
                csrf_token: csrfToken
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            if (btn) {
                btn.innerHTML = '<i class="fas fa-check mr-2"></i>Saved!';
                btn.style.background = 'rgba(34, 197, 94, 0.3)';
                btn.style.color = '#86efac';
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerHTML = originalHTML;
                    btn.style.background = 'rgba(34, 197, 94, 0.2)';
                }, 2000);
            }
            // Show success message
            alert('Scan saved to your profile!');
        } else {
            if (response.status === 401) {
                // Not logged in, redirect to login
                if (confirm('You need to be logged in to save scans. Would you like to login now?')) {
                    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
                }
            } else {
                alert(data.error || 'Failed to save scan');
            }
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }
    } catch (error) {
        console.error('Error saving scan:', error);
        alert('Error saving scan: ' + error.message);
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHTML;
        }
    }
}

function copyShareableUrl() {
    const input = document.getElementById('shareableUrlInput');
    if (input) {
        input.select();
        input.setSelectionRange(0, 99999); // For mobile devices
        document.execCommand('copy');
        
        // Show feedback
        const button = event.target.closest('button');
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check mr-2"></i>Copied!';
        button.style.background = 'rgba(34, 197, 94, 0.2)';
        button.style.color = '#86efac';
        
        setTimeout(() => {
            button.innerHTML = originalText;
            button.style.background = '';
            button.style.color = '';
        }, 2000);
    }
}

async function downloadPDF(downloadUrl) {
    // Find the button (may be dynamically created, so search for it)
    let btn = document.getElementById('downloadPdfBtn');
    if (!btn) {
        // Fallback: find button by looking for Download PDF text
        const buttons = Array.from(document.querySelectorAll('button'));
        btn = buttons.find(b => b.textContent.includes('Download PDF') || b.innerHTML.includes('fa-file-pdf'));
    }
    const originalHTML = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Generating PDF...';
    }
    
    try {
        // Fetch the PDF with proper error handling
        const response = await fetch(downloadUrl);
        
        // Check if response is OK
        if (!response.ok) {
            // Try to parse error message
            try {
                const errorData = await response.json();
                alert(`Failed to download PDF: ${errorData.error || 'Unknown error'}\n\nTip: If you see "PDF generation not available", install reportlab with: pip install reportlab`);
            } catch (e) {
                alert(`Failed to download PDF: HTTP ${response.status} ${response.statusText}`);
            }
            return;
        }
        
        // Check if response is actually a PDF
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/pdf')) {
            // Not a PDF - likely an error response
            try {
                const errorData = await response.json();
                alert(`Failed to download PDF: ${errorData.error || 'Server returned non-PDF content'}\n\nTip: If you see "PDF generation not available", install reportlab with: pip install reportlab`);
            } catch (e) {
                alert('Failed to download PDF: Server did not return a PDF file');
            }
            return;
        }
        
        // Get the PDF blob
        const blob = await response.blob();
        
        // Extract filename from Content-Disposition header or use default
        const contentDisposition = response.headers.get('content-disposition');
        let filename = 'darkorca_report.pdf';
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (filenameMatch && filenameMatch[1]) {
                filename = filenameMatch[1].replace(/['"]/g, '');
            }
        }
        
        // Create download link and trigger download
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Clean up the object URL
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('PDF download error:', error);
        alert(`Failed to download PDF: ${error.message || 'Network error'}`);
    } finally {
        // Re-enable button
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHTML;
        }
    }
}

// Chart instances
let riskGaugeChart = null;
let severityChart = null;
let categoryChart = null;
let scannerChart = null;

function displayResults(results) {
    // Hide progress, show results
    document.getElementById('scanProgress').classList.add('hidden');
    document.getElementById('scanResults').classList.remove('hidden');
    
    // Filter out information findings (plugins, themes, CMS) - they're in Information section
    const actionableFindings = results.findings.filter(f => {
        const title = f.title.toLowerCase();
        const category = f.category.toLowerCase();
        // Exclude plugin/theme detections and fingerprinting info
        return !(
            title.includes('plugin detected') ||
            title.includes('theme detected') ||
            title.includes('wordpress version detected') ||
            (category === 'fingerprinting' && f.severity === 'info')
        );
    });
    
    // Update risk summary (use actionable findings count)
    document.getElementById('riskScore').textContent = results.risk_score.overall_score.toFixed(1);
    document.getElementById('findingsCount').textContent = actionableFindings.length;
    // Format risk level in normal case
    const riskLevel = results.risk_score.risk_level.toLowerCase();
    document.getElementById('riskLevel').textContent = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1);
    
    // Update risk level color
    const riskLevelEl = document.getElementById('riskLevel');
    riskLevelEl.className = 'text-4xl font-bold';
    const level = results.risk_score.risk_level.toLowerCase();
    if (level === 'critical') riskLevelEl.classList.add('text-red-600');
    else if (level === 'high') riskLevelEl.classList.add('text-orange-600');
    else if (level === 'medium') riskLevelEl.classList.add('text-yellow-600');
    else if (level === 'low') riskLevelEl.classList.add('text-blue-600');
    else riskLevelEl.classList.add('text-green-600');
    
    // Display AI Analysis if available
    const aiAnalysisSection = document.getElementById('aiAnalysisSection');
    const aiAnalysisContent = document.getElementById('aiAnalysisContent');
    
    console.log('AI Analysis check:', {
        'ai_analysis exists': 'ai_analysis' in results,
        'ai_analysis value': results.ai_analysis ? `${results.ai_analysis.substring(0, 50)}...` : null,
        'ai_analysis length': results.ai_analysis ? results.ai_analysis.length : 0
    });
    
    if (results.ai_analysis && results.ai_analysis.trim()) {
        // Show AI analysis section
        console.log('Showing AI Analysis section - analysis found');
        if (aiAnalysisSection) {
            aiAnalysisSection.classList.remove('hidden');
            // Format the analysis text (preserve line breaks, convert to paragraphs)
            const analysisText = results.ai_analysis.trim();
            // Split by double newlines to create paragraphs
            const paragraphs = analysisText.split(/\n\n+/).filter(p => p.trim());
            if (aiAnalysisContent) {
                aiAnalysisContent.innerHTML = paragraphs.map(p => 
                    `<p style="margin-bottom: 1rem; line-height: 1.7; color: var(--text-main);">${p.trim().replace(/\n/g, '<br>')}</p>`
                ).join('');
            }
        } else {
            console.warn('aiAnalysisSection element not found in DOM');
        }
    } else {
        // Hide AI analysis section if not available
        console.log('Hiding AI Analysis section - no analysis found or empty');
        if (aiAnalysisSection) {
            aiAnalysisSection.classList.add('hidden');
        }
    }
    
    // Create visualizations
    createVisualizations(results, actionableFindings);
    
    // Display findings
    const findingsList = document.getElementById('findingsList');
    findingsList.innerHTML = '';
    
    if (actionableFindings.length === 0) {
        findingsList.innerHTML = '<div class="text-center py-8" style="color: #9aa0a6;">No actionable findings detected. Target appears secure.</div>';
        return;
    }
    
    // Group by severity
    const grouped = groupBySeverity(actionableFindings);
    
    // Display by severity order
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    
    // Severity labels with explanations
    const severityLabels = {
        'critical': 'Critical Severity',
        'high': 'High Severity',
        'medium': 'Medium Severity',
        'low': 'Low Severity',
        'info': 'Info Severity (Informational)'
    };
    
    severityOrder.forEach(severity => {
        if (grouped[severity] && grouped[severity].length > 0) {
            const severitySection = document.createElement('div');
            severitySection.className = 'mb-6';
            
            // For INFO severity, add a note explaining it's informational
            const isInfo = severity === 'info';
            
            // Create collapsible header
            const headerContainer = document.createElement('div');
            headerContainer.className = 'cursor-pointer hover:opacity-80 transition-opacity';
            
            const header = document.createElement('div');
            header.className = `flex items-center justify-between text-lg font-semibold mb-3 severity-${severity} px-3 py-2 rounded-lg border`;
            
            const headerLeft = document.createElement('div');
            headerLeft.className = 'flex items-center space-x-2';
            // Format severity in normal case (capitalize first letter)
            const severityDisplay = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
            const count = grouped[severity].length;
            const countText = count === 1 ? '1 finding' : `${count} findings`;
            headerLeft.innerHTML = `
                <i class="fas fa-chevron-down text-sm transition-transform duration-200" id="chevron-${severity}"></i>
                <span>${severityDisplay} Severity - ${countText}</span>
                ${isInfo ? '<span class="text-xs text-gray-500 ml-2 font-normal">(Informational - not a security issue)</span>' : ''}
            `;
            
            header.appendChild(headerLeft);
            headerContainer.appendChild(header);
            
            // Add explanation note for INFO severity
            if (isInfo) {
                const infoNote = document.createElement('div');
                infoNote.className = 'mb-3 p-3 rounded-lg text-sm';
                infoNote.style.cssText = 'background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); color: #93c5fd;';
                infoNote.innerHTML = `
                    <i class="fas fa-info-circle mr-2"></i>
                    <strong>What is Info Severity?</strong> These findings are informational only - they indicate normal behavior or detected information, but are not security vulnerabilities. They help with reconnaissance and understanding the target system.
                `;
                severitySection.appendChild(infoNote);
            }
            
            // Create content container
            const contentContainer = document.createElement('div');
            contentContainer.className = 'severity-content';
            contentContainer.id = `content-${severity}`;
            
            grouped[severity].forEach(finding => {
                contentContainer.appendChild(createFindingCard(finding));
            });
            
            // Toggle functionality
            let isExpanded = true; // Expanded by default
            headerContainer.addEventListener('click', () => {
                isExpanded = !isExpanded;
                const chevron = document.getElementById(`chevron-${severity}`);
                if (isExpanded) {
                    contentContainer.classList.remove('hidden');
                    chevron.classList.remove('fa-chevron-right');
                    chevron.classList.add('fa-chevron-down');
                } else {
                    contentContainer.classList.add('hidden');
                    chevron.classList.remove('fa-chevron-down');
                    chevron.classList.add('fa-chevron-right');
                }
            });
            
            severitySection.appendChild(headerContainer);
            severitySection.appendChild(contentContainer);
            
            findingsList.appendChild(severitySection);
        }
    });
    
    // Display information table (will be collapsed by default)
    displayInformationTable(results.findings);
    
    // Display security checks section
    displaySecurityChecks(results.findings);
    
    // Show shareable URL if available
    if (results.shareable_id) {
        showShareableUrl(results.shareable_id);
    }
    
    // Ensure Information section is visible but collapsed
    const infoSection = document.getElementById('informationToggle')?.closest('.card');
    if (infoSection) {
        infoSection.classList.remove('hidden');
    }
    
    // Ensure Security Checks section is visible but collapsed
    const checksSection = document.getElementById('securityChecksToggle')?.closest('.card');
    if (checksSection) {
        checksSection.classList.remove('hidden');
    }
    
    // Re-setup toggle after results are loaded (in case DOM was updated)
    setupInformationToggle();
    setupSecurityChecksToggle();
}

function createFindingCard(finding) {
    const card = document.createElement('div');
    card.className = 'rounded-lg p-4 mb-3 transition-shadow';
    card.style.cssText = 'border: 1px solid rgba(255, 255, 255, 0.08); background: rgba(11, 13, 22, 0.5);';
    
    const severityClass = `severity-${finding.severity}`;
    const icons = {
        critical: 'fa-exclamation-circle',
        high: 'fa-exclamation-triangle',
        medium: 'fa-info-circle',
        low: 'fa-info',
        info: 'fa-info-circle',
    };
    
    // Check if this is an exploit finding - show exploits first if available
    // New structure: exploits (remotely exploitable) and post_exploitation (shellcode, DOS, etc.)
    const hasExploits = finding.metadata && finding.metadata.exploits && finding.metadata.exploits.length > 0;
    const hasPostExploitation = finding.metadata && finding.metadata.post_exploitation && finding.metadata.post_exploitation.length > 0;
    
    // Filter exploits to only show those with useful information
    // Only show remotely exploitable exploits (not shellcode, DOS, local, etc.)
    let validExploits = [];
    if (hasExploits) {
        validExploits = finding.metadata.exploits.filter(exploit => {
            const exploitId = exploit['EDB-ID'] || exploit.EDB_ID || exploit.id || exploit.ID || null;
            const title = exploit.Title || exploit.title || exploit.Path || exploit.path || '';
            return title !== 'Unknown Exploit' && (title || exploitId);
        });
    }
    
    const exploitSection = validExploits.length > 0 ? `
        <div class="mb-4 p-4 rounded-lg" style="background: rgba(249, 115, 22, 0.1); border: 2px solid rgba(249, 115, 22, 0.3);">
            <div class="flex items-center mb-3">
                <i class="fas fa-bug mr-2" style="color: #fdba74;"></i>
                <h5 class="text-base font-bold" style="color: #fdba74;">Exploit References (${validExploits.length})</h5>
            </div>
            ${hasPostExploitation ? `
                <div class="mb-3 p-2 rounded text-xs" style="background: rgba(107, 114, 128, 0.2); border: 1px solid rgba(107, 114, 128, 0.3); color: #d1d5db;">
                    <i class="fas fa-info-circle mr-1"></i>
                    Note: ${finding.metadata.post_exploitation_count || 0} post-exploitation payload(s) (shellcode, DOS, local) were filtered out as they are not remotely exploitable vulnerabilities.
                </div>
            ` : ''}
            <div class="rounded-md p-3 max-h-96 overflow-y-auto" style="background: rgba(11, 13, 22, 0.8); border: 1px solid rgba(249, 115, 22, 0.2);">
                <ul class="space-y-3">
                    ${validExploits.map((exploit, idx) => {
                        // Try multiple field name variations
                        const exploitId = exploit['EDB-ID'] || exploit.EDB_ID || exploit.id || exploit.ID || null;
                        const title = exploit.Title || exploit.title || exploit.Path || exploit.path || 'Unknown Exploit';
                        const codes = exploit.Codes || exploit.codes || exploit.CVE || exploit.cve || [];
                        const cves = Array.isArray(codes) ? codes.filter(c => c && c.startsWith('CVE-')) : 
                                   (typeof codes === 'string' && codes.startsWith('CVE-')) ? [codes] : [];
                        const exploitUrl = exploitId ? `https://www.exploit-db.com/exploits/${exploitId}` : null;
                        
                        // Skip if no useful information
                        if (title === 'Unknown Exploit' && !exploitId) {
                            return '';
                        }
                        
                        return `
                            <li class="border-b border-gray-200 pb-3 last:border-0 last:pb-0">
                                <div class="flex items-start justify-between">
                                    <div class="flex-1">
                                        <div class="font-semibold mb-1" style="color: #f2f3f5;">
                                            ${idx + 1}. ${escapeHtml(title)}
                                        </div>
                                        <div class="flex flex-wrap gap-2 text-xs mt-2">
                                            ${exploitId ? `
                                                <a href="${exploitUrl || '#'}" target="_blank" 
                                                   class="px-2 py-1 rounded font-medium transition-colors" style="background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3);">
                                                    <i class="fas fa-external-link-alt mr-1"></i>EDB-ID: ${exploitId}
                                                </a>
                                            ` : ''}
                                            ${cves.length > 0 ? `
                                                <span class="px-2 py-1 rounded font-medium" style="background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3);">
                                                    <i class="fas fa-shield-alt mr-1"></i>${cves.join(', ')}
                                                </span>
                                            ` : ''}
                                        </div>
                                    </div>
                                </div>
                            </li>
                        `;
                    }).filter(html => html.trim() !== '').join('')}
                </ul>
            </div>
            ${finding.metadata.exploit_count > validExploits.length ? `
                <div class="mt-3 text-sm text-center" style="color: #fdba74;">
                    <i class="fas fa-info-circle mr-1"></i>
                    Showing ${validExploits.length} of ${finding.metadata.exploit_count} ${finding.metadata.exploit_count === 1 ? 'exploit' : 'exploits'} with available details. 
                    <a href="https://www.exploit-db.com/search?q=wordpress" target="_blank" 
                       class="hover:underline font-medium" style="color: #ff6b6b;">
                        View all on Exploit-DB <i class="fas fa-external-link-alt text-xs"></i>
                    </a>
                </div>
            ` : ''}
        </div>
    ` : (hasExploits && validExploits.length === 0) ? `
        <div class="mb-4 p-4 rounded-lg" style="background: rgba(234, 179, 8, 0.1); border: 2px solid rgba(234, 179, 8, 0.3);">
            <div class="flex items-center mb-2">
                <i class="fas fa-exclamation-triangle mr-2" style="color: #fde047;"></i>
                <h5 class="text-base font-bold" style="color: #fde047;">Exploits Found But Details Unavailable</h5>
            </div>
            <p class="text-sm" style="color: #fde047;">
                SearchSploit found ${finding.metadata.exploit_count || finding.metadata.exploits.length} potential ${(finding.metadata.exploit_count || finding.metadata.exploits.length) === 1 ? 'exploit' : 'exploits'}, but detailed information could not be parsed. 
                <a href="https://www.exploit-db.com/search?q=wordpress" target="_blank" 
                   class="hover:underline font-medium" style="color: #ff6b6b;">
                    View exploits on Exploit-DB <i class="fas fa-external-link-alt text-xs"></i>
                </a>
            </p>
        </div>
    ` : '';
    
    // Check for password brute-force test results
    const isBruteForceTest = finding.source_scanner === 'wordpress_offensive' && 
                             (finding.source_id === 'brute_force_test' || finding.source_id === 'brute_force_protection' || finding.source_id?.startsWith('login_compromised'));
    const bruteForceSection = isBruteForceTest && finding.metadata ? `
        <div class="mt-3 p-4 rounded-lg" style="background: rgba(234, 88, 12, 0.1); border: 2px solid rgba(234, 88, 12, 0.3);">
            <div class="flex items-center mb-3">
                <i class="fas fa-key mr-2" style="color: #fdba74;"></i>
                <h5 class="text-base font-bold" style="color: #fdba74;">Password Brute-Force Test Results</h5>
            </div>
            <div class="space-y-2 text-sm" style="color: #f2f3f5;">
                ${finding.metadata.users_tested ? `
                    <div>
                        <span class="font-semibold" style="color: #fdba74;">Users Tested:</span>
                        <span class="ml-2">${escapeHtml(finding.metadata.users_tested.join(', '))}</span>
                    </div>
                ` : finding.metadata.username ? `
                    <div>
                        <span class="font-semibold" style="color: #fdba74;">Username:</span>
                        <span class="ml-2">${escapeHtml(finding.metadata.username)}</span>
                    </div>
                ` : ''}
                ${finding.metadata.passwords_tested ? `
                    <div>
                        <span class="font-semibold" style="color: #fdba74;">Passwords Tested:</span>
                        <span class="ml-2">${finding.metadata.passwords_tested}</span>
                    </div>
                ` : ''}
                ${finding.metadata.password ? `
                    <div class="mt-2 p-2 rounded" style="background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3);">
                        <span class="font-semibold" style="color: #fca5a5;">⚠️ Compromised Password:</span>
                        <code class="ml-2 font-mono text-xs" style="color: #fca5a5;">${escapeHtml(finding.metadata.password)}</code>
                    </div>
                ` : ''}
                ${finding.metadata.blocked_attempts ? `
                    <div>
                        <span class="font-semibold" style="color: #fde047;">Blocked Attempts:</span>
                        <span class="ml-2">${finding.metadata.blocked_attempts}</span>
                        <span class="ml-2 text-xs" style="color: #d1d5db;">(Brute-force protection is active)</span>
                    </div>
                ` : ''}
            </div>
        </div>
    ` : '';
    
    card.innerHTML = `
        <div class="flex items-start justify-between mb-2">
            <div class="flex items-start space-x-3 flex-1">
                <i class="fas ${icons[finding.severity] || 'fa-info-circle'} text-xl mt-1 ${getSeverityColor(finding.severity)}"></i>
                <div class="flex-1">
                    <h4 class="font-semibold mb-1" style="color: #f2f3f5;">${escapeHtml(formatTitle(finding.title))}</h4>
                    <p class="text-sm mb-2 leading-relaxed whitespace-pre-line" style="color: #9aa0a6;">${escapeHtml(cleanDescription(finding.description))}</p>
                    <div class="flex flex-wrap gap-2 text-xs">
                        <span class="px-2.5 py-1 rounded-md font-medium" style="background: rgba(255, 107, 107, 0.2); color: #ff8e8e; border: 1px solid rgba(255, 107, 107, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span>
                        <span class="px-2.5 py-1 rounded-md font-medium" style="background: rgba(255, 255, 255, 0.1); color: #9aa0a6; border: 1px solid rgba(255, 255, 255, 0.08);">${escapeHtml(formatCategory(finding.category))}</span>
                        ${finding.url ? `<a href="${escapeHtml(finding.url)}" target="_blank" class="px-2.5 py-1 rounded-md font-medium transition-colors" style="background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3);">View URL</a>` : ''}
                        ${finding.exploited ? '<span class="px-2.5 py-1 rounded-md font-semibold" style="background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3);">⚠️ Exploited</span>' : ''}
                    </div>
                </div>
            </div>
            <span class="px-3 py-1 rounded text-xs font-semibold ${severityClass} border ml-3">
                ${finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1).toLowerCase()}
            </span>
        </div>
        ${exploitSection}
        ${bruteForceSection}
        ${finding.remediation ? `
            <div class="mt-3 p-3 rounded" style="background: rgba(59, 130, 246, 0.1); border-left: 4px solid rgba(59, 130, 246, 0.5);">
                <div class="text-sm font-medium mb-1" style="color: #93c5fd;">
                    <i class="fas fa-lightbulb mr-1"></i>Remediation
                </div>
                <div class="text-sm" style="color: #93c5fd;">${escapeHtml(finding.remediation)}</div>
            </div>
        ` : ''}
        ${finding.exploitation_details ? `
            <div class="mt-3 p-3 rounded" style="background: rgba(239, 68, 68, 0.1); border-left: 4px solid rgba(239, 68, 68, 0.5);">
                <div class="text-sm font-medium mb-2" style="color: #fca5a5;">
                    <i class="fas fa-bug mr-1"></i>Exploitation Details
                </div>
                ${finding.metadata && finding.metadata.execution_proven !== undefined ? `
                    <div class="mb-2 p-2 rounded" style="background: ${finding.metadata.execution_proven ? 'rgba(239, 68, 68, 0.2)' : 'rgba(234, 179, 8, 0.2)'}; border: 1px solid ${finding.metadata.execution_proven ? 'rgba(239, 68, 68, 0.4)' : 'rgba(234, 179, 8, 0.4)'};">
                        <div class="flex items-center space-x-2 text-xs font-semibold">
                            <span style="color: ${finding.metadata.execution_proven ? '#fca5a5' : '#fde047'};">
                                ${finding.metadata.execution_proven ? '✅' : '⚠️'} Execution Proven: <strong>${finding.metadata.execution_proven ? 'YES' : 'NO'}</strong>
                            </span>
                            ${finding.metadata.deserialization_confirmed !== undefined ? `
                                <span style="color: #93c5fd;">| Deserialization: <strong>${finding.metadata.deserialization_confirmed === true ? 'YES' : finding.metadata.deserialization_confirmed === false ? 'NO' : 'UNKNOWN'}</strong></span>
                            ` : ''}
                        </div>
                    </div>
                ` : ''}
                <div class="text-sm whitespace-pre-line" style="color: #fca5a5;">${escapeHtml(finding.exploitation_details)}</div>
                ${finding.metadata && finding.metadata.verification_methods && finding.metadata.verification_methods.length > 0 ? `
                    <div class="mt-2 text-xs" style="color: #86efac;">
                        <strong>Verification Methods:</strong> ${finding.metadata.verification_methods.join(', ')}
                    </div>
                ` : ''}
            </div>
        ` : ''}
    `;
    
    return card;
}

function groupBySeverity(findings) {
    const grouped = {};
    findings.forEach(finding => {
        const severity = finding.severity.toLowerCase();
        if (!grouped[severity]) {
            grouped[severity] = [];
        }
        grouped[severity].push(finding);
    });
    return grouped;
}

function displayInformationTable(findings) {
    // Extract information findings (INFO severity, FINGERPRINTING category, etc.)
    const infoFindings = findings.filter(f => 
        f.severity === 'info' || 
        f.category === 'fingerprinting' ||
        f.title.includes('Detected') ||
        f.title.includes('WordPress')
    );
    
    if (infoFindings.length === 0) {
        document.getElementById('informationTable').innerHTML = 
            '<div class="text-center py-4" style="color: var(--text-muted);">No information captured.</div>';
        return;
    }
    
    // Find comprehensive website info finding
    const websiteInfoFinding = infoFindings.find(f => f.source_scanner === 'website_info' && f.source_id === 'website_info_comprehensive');
    
    // Organize by type
    const organized = {
        cms: [],
        plugins: [],
        themes: [],
        users: [],
        server: [],
        cdn: [],
        technology: [],
        services: [],
        other: [],
        dns: [],
        ip: [],
        whois: [],
    };
    
    // Extract comprehensive website info
    if (websiteInfoFinding && websiteInfoFinding.metadata) {
        const meta = websiteInfoFinding.metadata;
        
        // DNS Information
        if (meta.ip_address || meta.ip_addresses || meta.name_servers || meta.mx_records) {
            organized.dns.push(meta);
        }
        
        // IP Information
        if (meta.ip_address || meta.country || meta.isp) {
            organized.ip.push(meta);
        }
        
        // WHOIS Information
        if (meta.registrar || meta.creation_date || meta.expiration_date) {
            organized.whois.push(meta);
        }
        
        // Web Server
        if (meta.web_server) {
            organized.server.push({
                title: 'Web Server',
                description: meta.web_server,
                source_scanner: 'website_info',
            });
        }
        
        // CDN
        if (meta.cdn) {
            organized.cdn.push({
                title: 'CDN',
                description: meta.cdn,
                source_scanner: 'website_info',
            });
        }
        
        // CMS
        if (meta.cms) {
            organized.cms.push({
                title: 'CMS',
                description: meta.cms,
                source_scanner: 'website_info',
            });
        }
        
        // Technology Stack
        if (meta.technology_stack && meta.technology_stack.length > 0) {
            organized.technology.push({
                title: 'Technology Stack',
                description: meta.technology_stack.join(', '),
                source_scanner: 'website_info',
            });
        }
    }
    
    // Process other findings
    infoFindings.forEach(finding => {
        // Skip if already processed as website_info
        if (finding.source_scanner === 'website_info' && finding.source_id === 'website_info_comprehensive') {
            return;
        }
        
        const title = finding.title.toLowerCase();
        const description = (finding.description || '').toLowerCase();
        
        if (title.includes('wordpress version') || title.includes('cms')) {
            organized.cms.push(finding);
        } else if (title.includes('plugin')) {
            organized.plugins.push(finding);
        } else if (title.includes('theme')) {
            organized.themes.push(finding);
        } else if (title.includes('user')) {
            organized.users.push(finding);
        } else if (title.includes('server') || title.includes('web server')) {
            organized.server.push(finding);
        } else if (title.includes('cdn') || description.includes('cloudflare') || description.includes('cloudfront') || description.includes('fastly') || description.includes('akamai')) {
            organized.cdn.push(finding);
        } else if (title.includes('technology') || title.includes('stack') || title.includes('powered by') || title.includes('asp.net') || title.includes('drupal') || title.includes('generator')) {
            organized.technology.push(finding);
        } else if (title.includes('service') || title.includes('port') || title.includes('nmap') || title.includes('open port')) {
            organized.services.push(finding);
        } else {
            organized.other.push(finding);
        }
    });
    
    // Build table HTML with dark theme
    let tableHTML = '<div class="space-y-6">';
    
    // Server Information
    if (organized.server.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">Web Server</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Type</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Details</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.server.forEach(finding => {
            const serverInfo = finding.description || finding.metadata?.server || 'Unknown';
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += '<td class="px-4 py-3 font-medium" style="color: var(--text-main);">Web Server</td>';
            tableHTML += `<td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(serverInfo)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // CDN Information
    if (organized.cdn.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">CDN</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Type</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Details</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.cdn.forEach(finding => {
            const cdnInfo = finding.description || finding.metadata?.cdn || 'Unknown';
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += '<td class="px-4 py-3 font-medium" style="color: var(--text-main);">CDN Provider</td>';
            tableHTML += `<td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(cdnInfo)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // Technology Stack
    if (organized.technology.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">Technology Stack</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Type</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Details</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.technology.forEach(finding => {
            const techName = finding.title.replace(' Detected', '') || 'Unknown';
            const techDetails = finding.description || finding.metadata?.value || '';
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">${escapeHtml(techName)}</td>`;
            tableHTML += `<td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(techDetails)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // CMS Information
    if (organized.cms.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">CMS</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Type</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.cms.forEach(finding => {
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += '<td class="px-4 py-3 font-medium" style="color: var(--text-main);">WordPress</td>';
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // Plugins
    if (organized.plugins.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">Plugins (' + organized.plugins.length + ')</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Plugin Name</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.plugins.forEach(finding => {
            const pluginName = formatPluginName(finding.title);
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">${escapeHtml(pluginName)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // Themes
    if (organized.themes.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">Themes (' + organized.themes.length + ')</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Theme Name</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.themes.forEach(finding => {
            const themeName = formatPluginName(finding.title); // Reuse same formatter
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">${escapeHtml(themeName)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // Users
    if (organized.users.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">Users</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Information</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Details</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.users.forEach(finding => {
            const userInfo = finding.description || finding.title;
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">User Enumeration</td>`;
            tableHTML += `<td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(userInfo)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // Services
    if (organized.services.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">Services</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Service</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Details</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.services.forEach(finding => {
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">${escapeHtml(finding.title)}</td>`;
            tableHTML += `<td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(finding.description)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // Other
    if (organized.other.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">Other Information</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
        tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Type</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Details</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        organized.other.forEach(finding => {
            tableHTML += '<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">${escapeHtml(finding.title)}</td>`;
            tableHTML += `<td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(finding.description)}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid rgba(234, 88, 12, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // DNS Information
    if (organized.dns.length > 0) {
        organized.dns.forEach(dnsInfo => {
            tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">DNS Information</h3>';
            tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
            tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr><th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Record Type</th><th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Value</th></tr></thead>';
            tableHTML += '<tbody>';
            if (dnsInfo.ip_address) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">IP Address (A)</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(dnsInfo.ip_address)}</td></tr>`;
            if (dnsInfo.ip_addresses && dnsInfo.ip_addresses.length > 1) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">All IP Addresses</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(dnsInfo.ip_addresses.join(', '))}</td></tr>`;
            if (dnsInfo.ipv6_addresses && dnsInfo.ipv6_addresses.length > 0) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">IPv6 (AAAA)</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(dnsInfo.ipv6_addresses.join(', '))}</td></tr>`;
            if (dnsInfo.name_servers && dnsInfo.name_servers.length > 0) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">Name Servers (NS)</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(dnsInfo.name_servers.join(', '))}</td></tr>`;
            if (dnsInfo.mx_records && dnsInfo.mx_records.length > 0) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">MX Records</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(dnsInfo.mx_records.join(', '))}</td></tr>`;
            if (dnsInfo.cname_records && dnsInfo.cname_records.length > 0) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">CNAME Records</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(dnsInfo.cname_records.join(', '))}</td></tr>`;
            tableHTML += '</tbody></table></div>';
        });
    }
    
    // IP & Location Information
    if (organized.ip.length > 0) {
        organized.ip.forEach(ipInfo => {
            tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">IP & Location</h3>';
            tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
            tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr><th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Field</th><th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Value</th></tr></thead>';
            tableHTML += '<tbody>';
            if (ipInfo.ip_address) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">IP Address</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(ipInfo.ip_address)}</td></tr>`;
            if (ipInfo.country) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">Country</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(ipInfo.country)}</td></tr>`;
            if (ipInfo.city) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">City</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(ipInfo.city)}</td></tr>`;
            if (ipInfo.isp) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">ISP</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(ipInfo.isp)}</td></tr>`;
            if (ipInfo.asn) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">ASN</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(ipInfo.asn)}</td></tr>`;
            tableHTML += '</tbody></table></div>';
        });
    }
    
    // WHOIS Information
    if (organized.whois.length > 0) {
        organized.whois.forEach(whoisInfo => {
            tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: var(--text-main);">WHOIS Information</h3>';
            tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(255, 255, 255, 0.08);">';
            tableHTML += '<thead style="background: rgba(0, 0, 0, 0.3);"><tr><th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Field</th><th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(255, 255, 255, 0.08);">Value</th></tr></thead>';
            tableHTML += '<tbody>';
            if (whoisInfo.registrar) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">Registrar</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(whoisInfo.registrar)}</td></tr>`;
            if (whoisInfo.creation_date) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">Creation Date</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(whoisInfo.creation_date)}</td></tr>`;
            if (whoisInfo.expiration_date) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">Expiration Date</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(whoisInfo.expiration_date)}</td></tr>`;
            if (whoisInfo.whois_status) tableHTML += `<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><td class="px-4 py-3 font-medium" style="color: var(--text-main);">Status</td><td class="px-4 py-3" style="color: var(--text-muted);">${escapeHtml(whoisInfo.whois_status)}</td></tr>`;
            tableHTML += '</tbody></table></div>';
        });
    }
    
    tableHTML += '</div>';
    
    document.getElementById('informationTable').innerHTML = tableHTML;
    
    // Update count badge
    const totalInfoItems = organized.server.length + organized.cdn.length + 
                          organized.technology.length + organized.cms.length + 
                          organized.plugins.length + organized.themes.length + 
                          organized.users.length + organized.services.length + 
                          organized.other.length + organized.dns.length + 
                          organized.ip.length + organized.whois.length;
    const countBadge = document.getElementById('informationCount');
    if (countBadge) {
        if (totalInfoItems > 0) {
            const itemText = totalInfoItems === 1 ? 'item' : 'items';
            countBadge.textContent = `${totalInfoItems} ${itemText}`;
            countBadge.classList.remove('hidden');
        } else {
            countBadge.textContent = '';
            countBadge.classList.add('hidden');
        }
    }
    
    // Setup toggle functionality
    setupInformationToggle();
}

function displaySecurityChecks(findings) {
    // Find all findings that represent security checks (defensive security tests, security headers, SSL checks, etc.)
    const defensiveScanners = [
        'security_headers', 'ssl_analyzer', 'dns_security', 'http_security',
        'cookie_security', 'rate_limiting', 'api_security', 'content_security',
        'backup_files', 'website_info'
    ];
    
    const checkFindings = findings.filter(f => {
        // Explicit test_passed metadata
        if (f.metadata && f.metadata.test_passed !== undefined) {
            return true;
        }
        
        // Defensive security scanners
        if (defensiveScanners.includes(f.source_scanner)) {
            return true;
        }
        
        // Offensive test scanners
        if (f.source_scanner === 'subdomain_enum' || f.source_scanner === 'wordpress_offensive') {
            return true;
        }
        
        // Security-related patterns in title or category
        const title = (f.title || '').toLowerCase();
        const category = (f.category || '').toLowerCase();
        
        if (title.includes('security header') ||
            title.includes('ssl') ||
            title.includes('tls') ||
            title.includes('cookie') ||
            title.includes('http security') ||
            title.includes('dns') ||
            title.includes('rate limit') ||
            title.includes('protected') ||
            title.includes('test') ||
            category.includes('security') ||
            category.includes('configuration')) {
            return true;
        }
        
        return false;
    });
    
    if (checkFindings.length === 0) {
        document.getElementById('securityChecksTable').innerHTML = 
            '<div class="text-center py-4" style="color: var(--text-muted);">No security checks performed.</div>';
        return;
    }
    
    // Separate passed and failed checks
    const passedChecks = [];
    const failedChecks = [];
    
    checkFindings.forEach(finding => {
        const testPassed = finding.metadata?.test_passed;
        if (testPassed === true || 
            finding.title.includes('Protected') ||
            finding.title.includes('No') ||
            (finding.title.includes('Test') && finding.description.includes('No'))) {
            passedChecks.push(finding);
        } else if (testPassed === false) {
            failedChecks.push(finding);
        } else {
            // Ambiguous - check description for positive indicators
            const desc = (finding.description || '').toLowerCase();
            if (desc.includes('no') || desc.includes('protected') || desc.includes('not found') || desc.includes('positive')) {
                passedChecks.push(finding);
            } else {
                failedChecks.push(finding);
            }
        }
    });
    
    let tableHTML = '<div class="space-y-6">';
    
    // Passed Checks Section
    if (passedChecks.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: #86efac;"><i class="fas fa-check-circle mr-2"></i>Passed Security Checks (' + passedChecks.length + ')</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(34, 197, 94, 0.3);">';
        tableHTML += '<thead style="background: rgba(34, 197, 94, 0.1);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(34, 197, 94, 0.3);">Check</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(34, 197, 94, 0.3);">Result</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(34, 197, 94, 0.3);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        passedChecks.forEach(finding => {
            tableHTML += '<tr style="border-bottom: 1px solid rgba(34, 197, 94, 0.2); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">${escapeHtml(formatTitle(finding.title))}</td>`;
            tableHTML += `<td class="px-4 py-3" style="color: #86efac;">${escapeHtml(cleanDescription(finding.description))}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(34, 197, 94, 0.2); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    // Failed Checks Section (if any)
    if (failedChecks.length > 0) {
        tableHTML += '<div class="mb-6"><h3 class="text-lg font-semibold mb-3" style="color: #fca5a5;"><i class="fas fa-exclamation-circle mr-2"></i>Issues Found (' + failedChecks.length + ')</h3>';
        tableHTML += '<table class="w-full border-collapse rounded-lg overflow-hidden" style="border: 1px solid rgba(239, 68, 68, 0.3);">';
        tableHTML += '<thead style="background: rgba(239, 68, 68, 0.1);"><tr>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(239, 68, 68, 0.3);">Check</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(239, 68, 68, 0.3);">Result</th>';
        tableHTML += '<th class="px-4 py-3 text-left font-semibold" style="color: var(--text-main); border-bottom: 1px solid rgba(239, 68, 68, 0.3);">Source</th>';
        tableHTML += '</tr></thead>';
        tableHTML += '<tbody>';
        failedChecks.forEach(finding => {
            tableHTML += '<tr style="border-bottom: 1px solid rgba(239, 68, 68, 0.2); transition: background 0.2s;">';
            tableHTML += `<td class="px-4 py-3 font-medium" style="color: var(--text-main);">${escapeHtml(formatTitle(finding.title))}</td>`;
            tableHTML += `<td class="px-4 py-3" style="color: #fca5a5;">${escapeHtml(cleanDescription(finding.description))}</td>`;
            tableHTML += `<td class="px-4 py-3"><span class="px-2.5 py-1 rounded-md text-xs font-medium" style="background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); white-space: nowrap; display: inline-block;">${escapeHtml(formatScannerName(finding.source_scanner))}</span></td>`;
            tableHTML += '</tr>';
        });
        tableHTML += '</tbody></table></div>';
    }
    
    tableHTML += '</div>';
    
    document.getElementById('securityChecksTable').innerHTML = tableHTML;
    
    // Update count
    const totalChecks = passedChecks.length + failedChecks.length;
    const countBadge = document.getElementById('securityChecksCount');
    if (countBadge) {
        if (totalChecks > 0) {
            const itemText = totalChecks === 1 ? 'check' : 'checks';
            countBadge.textContent = `${totalChecks} ${itemText}`;
            countBadge.classList.remove('hidden');
        } else {
            countBadge.textContent = '';
            countBadge.classList.add('hidden');
        }
    }
}

function extractVersion(description) {
    // Try to extract version from description
    const versionMatch = description.match(/version\s+([^\s,]+)/i);
    if (versionMatch) {
        const version = versionMatch[1];
        // Don't return if it's "hidden", "intentionally", or "not disclosed"
        if (!version.toLowerCase().includes('hidden') && 
            !version.toLowerCase().includes('intentionally') &&
            !version.toLowerCase().includes('not disclosed')) {
            return version;
        }
    }
    
    return null; // Return null for hidden/unknown versions
}

function formatScannerName(scanner) {
    // Format scanner names nicely - use compact names to prevent wrapping in badges
    const names = {
        'wpscan': 'WPScan',
        'nuclei': 'Nuclei',
        'nmap': 'Nmap',
        'sqlmap': 'SQLMap',
        'wordpress_analyzer': 'WP Analyzer',
        'directory_bruteforcer': 'Dir Bruteforce',
        'parameter_discovery': 'Param Discovery',
        'exploit_intel': 'Exploit Intel',
        'ssl_analyzer': 'SSL',
        'security_headers': 'Sec Headers',
        'dns_security': 'DNS',
        'http_security': 'HTTP',
        'cookie_security': 'Cookies',
        'rate_limiting': 'Rate Limit',
        'api_security': 'API',
        'content_security': 'Content',
        'backup_files': 'Backups',
        'website_info': 'Website Info',
        'subdomain_enum': 'Subdomains',
        'wordpress_offensive': 'WP Offensive'
    };
    return names[scanner.toLowerCase()] || scanner.charAt(0).toUpperCase() + scanner.slice(1).replace(/_/g, ' ');
}

function formatCategory(category) {
    // Format category names nicely
    return category.split('_').map(word => 
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function formatPluginName(name) {
    // Remove "Detected: " prefix and format nicely
    name = name.replace(/^detected:\s*/i, '');
    // Convert hyphens to spaces and capitalize
    return name.split('-').map(word => 
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function formatTitle(title) {
    // Remove common prefixes and format to title case
    title = title.replace(/^(WordPress\s+)?(Plugin|Theme)\s+Detected:\s*/i, '');
    title = title.replace(/^Exposed\s+/i, '');
    
    // Convert to title case
    return title.split(/[\s-]+/).map(word => {
        if (word.length === 0) return '';
        // Handle acronyms (keep uppercase if all caps)
        if (word === word.toUpperCase() && word.length > 1) {
            return word;
        }
        return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    }).join(' ');
}

function cleanDescription(description) {
    if (!description) return '';
    
    // Preserve newlines for exploit lists
    const hasExploitList = description.includes('Found Exploits:') || description.includes('\n\n');
    
    if (hasExploitList) {
        // For exploit lists, preserve structure but clean up
        // Remove version mentions in parentheses
        description = description.replace(/\s*\(version\s+[^)]+\)/gi, '');
        // Remove standalone CVE mentions in parentheses, keep CVE numbers inline
        description = description.replace(/\s*\(CVE:\s*([^)]+)\)/gi, ' - CVE $1');
        // Clean up multiple spaces but preserve newlines
        description = description.replace(/[ \t]+/g, ' ').replace(/\n\s*\n/g, '\n\n');
        // Capitalize first letter
        if (description.length > 0) {
            description = description.charAt(0).toUpperCase() + description.slice(1);
        }
        return description;
    }
    
    // For regular descriptions, clean more aggressively
    // Remove version mentions in parentheses
    description = description.replace(/\s*\(version\s+[^)]+\)/gi, '');
    // Remove standalone CVE mentions in parentheses, keep CVE numbers inline
    description = description.replace(/\s*\(CVE:\s*([^)]+)\)/gi, ' - CVE $1');
    // Remove other unnecessary parentheses
    description = description.replace(/\s*\([^)]*\)/g, '');
    // Clean up multiple spaces
    description = description.replace(/\s+/g, ' ').trim();
    // Capitalize first letter
    if (description.length > 0) {
        description = description.charAt(0).toUpperCase() + description.slice(1);
    }
    return description;
}

function extractPluginName(title) {
    const match = title.match(/Plugin[:\s]+(.+)/i);
    return match ? match[1] : title.replace('WordPress Plugin Detected: ', '');
}

function extractThemeName(title) {
    const match = title.match(/Theme[:\s]+(.+)/i);
    return match ? match[1] : title.replace('WordPress Theme Detected: ', '');
}

// Track if toggle is already set up to prevent duplicate listeners
let informationToggleSetup = false;
let securityChecksToggleSetup = false;

function setupInformationToggle() {
    const toggle = document.getElementById('informationToggle');
    const content = document.getElementById('informationContent');
    const icon = document.getElementById('informationToggleIcon');
    
    if (toggle && content && icon && !informationToggleSetup) {
        // Set initial state (collapsed by default)
        content.classList.add('hidden');
        icon.classList.add('fa-chevron-down');
        icon.classList.remove('fa-chevron-up');
        
        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const isHidden = content.classList.contains('hidden');
            if (isHidden) {
                content.classList.remove('hidden');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
                // Smooth scroll to content
                setTimeout(() => {
                    content.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }, 100);
            } else {
                content.classList.add('hidden');
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
            }
        });
        
        informationToggleSetup = true;
    }
}

function setupSecurityChecksToggle() {
    const toggle = document.getElementById('securityChecksToggle');
    const content = document.getElementById('securityChecksContent');
    const icon = document.getElementById('securityChecksToggleIcon');
    
    if (toggle && content && icon && !securityChecksToggleSetup) {
        // Set initial state (collapsed by default)
        content.classList.add('hidden');
        icon.classList.add('fa-chevron-down');
        icon.classList.remove('fa-chevron-up');
        
        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const isHidden = content.classList.contains('hidden');
            if (isHidden) {
                content.classList.remove('hidden');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
                // Smooth scroll to content
                setTimeout(() => {
                    content.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }, 100);
            } else {
                content.classList.add('hidden');
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
            }
        });
        
        securityChecksToggleSetup = true;
    }
}

// Duplicate displaySecurityChecks function removed - using the one at line 1312

function getSeverityColor(severity) {
    const colors = {
        critical: 'text-red-600',
        high: 'text-orange-600',
        medium: 'text-yellow-600',
        low: 'text-blue-600',
        info: 'text-gray-600',
    };
    return colors[severity.toLowerCase()] || 'text-gray-600';
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function resetForm() {
    const startBtn = document.getElementById('startScanBtn');
    if (startBtn) {
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-play mr-2"></i>Start Scan';
    }
    // Don't clear the form fields - let user keep their input
}

// Update risk warning based on scan mode
function updateRiskLevelInfo(mode) {
    const defensiveInfo = document.getElementById('defensiveInfo');
    const riskWarning = document.getElementById('riskWarning');
    const comprehensiveInfo = document.getElementById('comprehensiveInfo');
    const riskWarningText = document.getElementById('riskWarningText');
    
    if (!defensiveInfo || !riskWarning || !comprehensiveInfo) {
        // Elements not ready yet
        return;
    }
    
    if (mode === 'defensive') {
        defensiveInfo.classList.remove('hidden');
        riskWarning.classList.add('hidden');
        comprehensiveInfo.classList.add('hidden');
    } else if (mode === 'offensive') {
        defensiveInfo.classList.add('hidden');
        riskWarning.classList.remove('hidden');
        comprehensiveInfo.classList.add('hidden');
        if (riskWarningText) {
            riskWarningText.textContent = 'Offensive mode will attempt to exploit vulnerabilities';
        }
        riskWarning.className = 'warning-box mt-2 text-sm';
    } else if (mode === 'comprehensive') {
        defensiveInfo.classList.add('hidden');
        riskWarning.classList.add('hidden');  // Hide warning box
        comprehensiveInfo.classList.remove('hidden');  // Show comprehensive info
    }
}

// Setup scan mode change listener
function setupScanModeListener() {
    const scanModeSelect = document.getElementById('scanMode');
    if (!scanModeSelect) {
        return;
    }
    
    // Attach change event listener directly to select element
    scanModeSelect.addEventListener('change', function(e) {
        updateRiskLevelInfo(e.target.value);
    });
    
    // Initialize based on current selection
    updateRiskLevelInfo(scanModeSelect.value);
}

// Filter buttons
document.getElementById('filterAll')?.addEventListener('click', () => {
    // Implement filtering logic
    console.log('Filter: All');
});

// Initialize Information toggle on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupInformationToggle);
} else {
    setupInformationToggle();
}

document.getElementById('filterCritical')?.addEventListener('click', () => {
    console.log('Filter: Critical');
});

document.getElementById('filterHigh')?.addEventListener('click', () => {
    console.log('Filter: High');
});

function createVisualizations(results, findings) {
    // Destroy existing charts if they exist
    if (riskGaugeChart) riskGaugeChart.destroy();
    if (severityChart) severityChart.destroy();
    if (categoryChart) categoryChart.destroy();
    if (scannerChart) scannerChart.destroy();
    
    // Chart.js color scheme matching DarkAI theme
    const chartColors = {
        background: 'rgba(17, 24, 39, 0.8)',
        border: 'rgba(255, 255, 255, 0.1)',
        text: '#f2f3f5',
        muted: '#9aa0a6',
        critical: 'rgba(239, 68, 68, 0.8)',
        high: 'rgba(249, 115, 22, 0.8)',
        medium: 'rgba(234, 179, 8, 0.8)',
        low: 'rgba(59, 130, 246, 0.8)',
        info: 'rgba(107, 114, 128, 0.8)',
        accent: 'rgba(255, 107, 107, 0.8)',
    };
    
    // Chart.js default configuration
    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = chartColors.text;
        Chart.defaults.borderColor = chartColors.border;
        Chart.defaults.backgroundColor = chartColors.background;
        
        // 1. Risk Score Gauge Chart
        const riskScore = results.risk_score.overall_score;
        const riskCtx = document.getElementById('riskGaugeChart');
        if (riskCtx) {
            riskGaugeChart = new Chart(riskCtx, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [riskScore, 100 - riskScore],
                        backgroundColor: [
                            riskScore >= 70 ? chartColors.critical :
                            riskScore >= 50 ? chartColors.high :
                            riskScore >= 30 ? chartColors.medium :
                            riskScore >= 10 ? chartColors.low : chartColors.info,
                            'rgba(255, 255, 255, 0.1)'
                        ],
                        borderWidth: 0,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    cutout: '75%',
                    plugins: {
                        legend: { display: false },
                        tooltip: { enabled: false },
                        title: {
                            display: true,
                            text: `${riskScore.toFixed(1)}/100`,
                            position: 'center',
                            font: { size: 24, weight: 'bold' },
                            color: chartColors.text,
                        }
                    }
                }
            });
        }
        
        // 2. Findings by Severity Chart
        const severityData = {};
        findings.forEach(f => {
            const sev = f.severity.toLowerCase();
            severityData[sev] = (severityData[sev] || 0) + 1;
        });
        
        const severityCtx = document.getElementById('severityChart');
        if (severityCtx && Object.keys(severityData).length > 0) {
            const severityLabels = Object.keys(severityData);
            const severityCounts = Object.values(severityData);
            const severityColors = severityLabels.map(sev => {
                if (sev === 'critical') return chartColors.critical;
                if (sev === 'high') return chartColors.high;
                if (sev === 'medium') return chartColors.medium;
                if (sev === 'low') return chartColors.low;
                return chartColors.info;
            });
            
            severityChart = new Chart(severityCtx, {
                type: 'bar',
                data: {
                    labels: severityLabels.map(s => s.charAt(0).toUpperCase() + s.slice(1)),
                    datasets: [{
                        label: 'Findings',
                        data: severityCounts,
                        backgroundColor: severityColors,
                        borderColor: severityColors.map(c => c.replace('0.8', '1')),
                        borderWidth: 1,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: chartColors.background,
                            titleColor: chartColors.text,
                            bodyColor: chartColors.text,
                            borderColor: chartColors.border,
                            borderWidth: 1,
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: chartColors.muted, stepSize: 1 },
                            grid: { color: chartColors.border }
                        },
                        x: {
                            ticks: { color: chartColors.muted },
                            grid: { display: false }
                        }
                    }
                }
            });
        }
        
        // 3. Findings by Category Chart
        const categoryData = {};
        findings.forEach(f => {
            const cat = f.category.toLowerCase().replace(/_/g, ' ');
            categoryData[cat] = (categoryData[cat] || 0) + 1;
        });
        
        const categoryCtx = document.getElementById('categoryChart');
        if (categoryCtx && Object.keys(categoryData).length > 0) {
            const categoryLabels = Object.keys(categoryData);
            const categoryCounts = Object.values(categoryData);
            
            categoryChart = new Chart(categoryCtx, {
                type: 'pie',
                data: {
                    labels: categoryLabels.map(c => c.charAt(0).toUpperCase() + c.slice(1)),
                    datasets: [{
                        data: categoryCounts,
                        backgroundColor: [
                            chartColors.critical,
                            chartColors.high,
                            chartColors.medium,
                            chartColors.low,
                            chartColors.info,
                            chartColors.accent,
                            'rgba(139, 92, 246, 0.8)',
                            'rgba(236, 72, 153, 0.8)',
                        ],
                        borderColor: chartColors.border,
                        borderWidth: 1,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: chartColors.text,
                                font: { size: 11 },
                                padding: 10,
                            }
                        },
                        tooltip: {
                            backgroundColor: chartColors.background,
                            titleColor: chartColors.text,
                            bodyColor: chartColors.text,
                            borderColor: chartColors.border,
                            borderWidth: 1,
                        }
                    }
                }
            });
        }
        
        // 4. Scanner Activity Chart
        const scannerData = {};
        findings.forEach(f => {
            const scanner = f.source_scanner || 'unknown';
            scannerData[scanner] = (scannerData[scanner] || 0) + 1;
        });
        
        const scannerCtx = document.getElementById('scannerChart');
        if (scannerCtx && Object.keys(scannerData).length > 0) {
            // Sort by count and take top 8
            const sortedScanners = Object.entries(scannerData)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8);
            
            const scannerLabels = sortedScanners.map(([name]) => {
                // Format scanner names
                return name.replace(/_/g, ' ')
                    .replace(/\b\w/g, l => l.toUpperCase());
            });
            const scannerCounts = sortedScanners.map(([, count]) => count);
            
            scannerChart = new Chart(scannerCtx, {
                type: 'bar',
                data: {
                    labels: scannerLabels,
                    datasets: [{
                        label: 'Findings',
                        data: scannerCounts,
                        backgroundColor: chartColors.accent,
                        borderColor: chartColors.accent.replace('0.8', '1'),
                        borderWidth: 1,
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: chartColors.background,
                            titleColor: chartColors.text,
                            bodyColor: chartColors.text,
                            borderColor: chartColors.border,
                            borderWidth: 1,
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            ticks: { color: chartColors.muted, stepSize: 1 },
                            grid: { color: chartColors.border }
                        },
                        y: {
                            ticks: { color: chartColors.muted },
                            grid: { display: false }
                        }
                    }
                }
            });
        }
    }
}

document.getElementById('filterMedium')?.addEventListener('click', () => {
    console.log('Filter: Medium');
});

