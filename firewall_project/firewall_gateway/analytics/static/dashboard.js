/**
 * Collatz Firewall Analytics Dashboard - Windows 7 Style
 * Real-time visualization and pattern analysis
 */

// ============================================================================
// Global State
// ============================================================================

const Dashboard = {
    data: {
        stats: {
            total_verifications: 0,
            allowed: 0,
            blocked: 0,
            avg_verification_time_ms: 0
        },
        patterns: {},
        suggestions: [],
        sequences: [],
        history: []
    },

    config: {
        updateInterval: 2000,  // 2 seconds
        historyLimit: 100,
        chartRefreshRate: 100
    },

    activeView: 'overview'
};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('Dashboard initializing...');

    // Initialize UI components
    initializeSidebar();
    initializeCharts();
    initializeEventListeners();

    // Start data polling
    startDataPolling();

    // Initial data load
    updateDashboard();

    console.log('Dashboard ready');
});

// ============================================================================
// Sidebar Navigation
// ============================================================================

function initializeSidebar() {
    const sidebarItems = document.querySelectorAll('.sidebar-item');

    sidebarItems.forEach(item => {
        item.addEventListener('click', (e) => {
            // Remove active from all
            sidebarItems.forEach(i => i.classList.remove('active'));

            // Add active to clicked
            item.classList.add('active');

            // Switch view
            const view = item.dataset.view;
            switchView(view);
        });
    });

    // Set first item as active
    if (sidebarItems.length > 0) {
        sidebarItems[0].classList.add('active');
    }
}

function switchView(view) {
    Dashboard.activeView = view;

    const panels = document.querySelectorAll('[data-panel]');
    panels.forEach(panel => {
        const panelView = panel.dataset.panel;
        panel.style.display = (panelView === view) ? 'flex' : 'none';
    });

    // Update charts for new view
    if (view === 'patterns') {
        updatePatternCharts();
    } else if (view === 'innovations') {
        updateInnovationCards();
    }
}

// ============================================================================
// Event Listeners
// ============================================================================

function initializeEventListeners() {
    // Window control buttons
    const btnClose = document.querySelector('.btn-close');
    if (btnClose) {
        btnClose.addEventListener('click', () => {
            alert('Close application? (This would close the dashboard)');
        });
    }

    // Auto-refresh toggle
    const refreshToggle = document.getElementById('auto-refresh');
    if (refreshToggle) {
        refreshToggle.addEventListener('change', (e) => {
            if (e.target.checked) {
                startDataPolling();
            } else {
                stopDataPolling();
            }
        });
    }

    // Manual refresh button
    const refreshBtn = document.getElementById('manual-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', updateDashboard);
    }
}

// ============================================================================
// Data Polling & Updates
// ============================================================================

let pollInterval = null;

function startDataPolling() {
    if (pollInterval) clearInterval(pollInterval);

    pollInterval = setInterval(() => {
        updateDashboard();
    }, Dashboard.config.updateInterval);
}

function stopDataPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

async function updateDashboard() {
    try {
        // In production, this would fetch from API
        // For now, simulate data
        simulateData();

        updateStatsPanels();
        updateSequenceChart();
        updatePerformanceMetrics();
        updateStatusBar();

    } catch (error) {
        console.error('Error updating dashboard:', error);
        showError('Failed to update dashboard');
    }
}

// ============================================================================
// Data Simulation (Replace with API calls in production)
// ============================================================================

function simulateData() {
    // Simulate random verifications
    const isAllowed = Math.random() > 0.3;
    Dashboard.data.stats.total_verifications++;

    if (isAllowed) {
        Dashboard.data.stats.allowed++;
    } else {
        Dashboard.data.stats.blocked++;
    }

    Dashboard.data.stats.avg_verification_time_ms =
        (Math.random() * 3) + 0.5;  // 0.5-3.5ms

    // Simulate Collatz sequence
    const sequence = generateRandomCollatzSequence();
    Dashboard.data.sequences.push(sequence);

    // Keep only recent sequences
    if (Dashboard.data.sequences.length > Dashboard.config.historyLimit) {
        Dashboard.data.sequences.shift();
    }

    // Update patterns
    updatePatternAnalysis();
}

function generateRandomCollatzSequence() {
    const startNum = Math.floor(Math.random() * 1000000) + 1;
    const sequence = [];
    let current = startNum;
    let maxVal = current;

    while (current !== 1 && sequence.length < 1000) {
        sequence.push(current);
        if (current % 2 === 0) {
            current = current / 2;
        } else {
            current = (3 * current + 1);
        }
        maxVal = Math.max(maxVal, current);
    }
    sequence.push(1);

    return {
        sequence,
        length: sequence.length,
        max_value: maxVal,
        steps_to_one: sequence.length - 1,
        timestamp: new Date()
    };
}

// ============================================================================
// Stats Panels Update
// ============================================================================

function updateStatsPanels() {
    const stats = Dashboard.data.stats;

    updateStatValue('stat-total', stats.total_verifications);
    updateStatValue('stat-allowed', stats.allowed);
    updateStatValue('stat-blocked', stats.blocked);
    updateStatValue('stat-time', stats.avg_verification_time_ms.toFixed(2) + 'ms');

    // Update percentages
    const total = stats.total_verifications || 1;
    const allowRate = ((stats.allowed / total) * 100).toFixed(1);
    updateStatValue('stat-allow-rate', allowRate + '%');
}

function updateStatValue(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        const oldValue = element.textContent;
        element.textContent = value;

        // Flash effect
        if (oldValue !== value) {
            element.style.animation = 'none';
            setTimeout(() => {
                element.style.animation = 'flash 0.5s';
            }, 10);
        }
    }
}

// Add flash animation
const style = document.createElement('style');
style.textContent = `
    @keyframes flash {
        0%, 100% { color: #0078d7; }
        50% { color: #ff6600; }
    }
`;
document.head.appendChild(style);

// ============================================================================
// Charts
// ============================================================================

let sequenceChart = null;
let performanceChart = null;
let patternChart = null;

function initializeCharts() {
    // This would use Chart.js or similar library in production
    console.log('Charts initialized');
}

function updateSequenceChart() {
    const canvas = document.getElementById('sequence-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const sequences = Dashboard.data.sequences.slice(-10);

    // Draw a simple visualization
    const width = canvas.width;
    const height = canvas.height;

    ctx.fillStyle = '#f5f5f5';
    ctx.fillRect(0, 0, width, height);

    if (sequences.length === 0) return;

    // Draw axes
    ctx.strokeStyle = '#999';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(30, height - 20);
    ctx.lineTo(width - 10, height - 20);
    ctx.stroke();

    // Draw sequences as sparklines
    const colors = ['#0078d7', '#00aa00', '#ff6600', '#cc0000'];
    const spacing = (width - 40) / sequences.length;

    sequences.forEach((seq, idx) => {
        ctx.strokeStyle = colors[idx % colors.length];
        ctx.lineWidth = 2;
        ctx.beginPath();

        const points = seq.sequence.slice(0, 20); // Sample first 20 points
        const maxVal = Math.max(...points);
        const minVal = Math.min(...points);
        const range = maxVal - minVal || 1;

        points.forEach((val, i) => {
            const x = 30 + (spacing * idx) + (i * spacing / 20);
            const y = height - 20 - ((val - minVal) / range) * (height - 40);

            if (i === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });

        ctx.stroke();
    });
}

function updatePerformanceMetrics() {
    const canvas = document.getElementById('performance-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const stats = Dashboard.data.stats;

    ctx.fillStyle = '#f5f5f5';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw bar chart for allowed vs blocked
    const width = canvas.width;
    const height = canvas.height;
    const barWidth = 40;
    const spacing = 20;

    const allowPct = (stats.allowed / (stats.total_verifications || 1)) * 100;
    const blockPct = 100 - allowPct;

    // Allowed bar
    ctx.fillStyle = '#00aa00';
    const allowHeight = (allowPct / 100) * (height - 40);
    ctx.fillRect(spacing, height - 20 - allowHeight, barWidth, allowHeight);

    // Blocked bar
    ctx.fillStyle = '#ff3333';
    const blockHeight = (blockPct / 100) * (height - 40);
    ctx.fillRect(spacing + barWidth + 20, height - 20 - blockHeight, barWidth, blockHeight);

    // Labels
    ctx.fillStyle = '#333';
    ctx.font = '11px Segoe UI';
    ctx.textAlign = 'center';
    ctx.fillText('Allowed', spacing + barWidth / 2, height - 5);
    ctx.fillText('Blocked', spacing + barWidth + 20 + barWidth / 2, height - 5);

    // Values
    ctx.fillStyle = '#0078d7';
    ctx.font = 'bold 12px Segoe UI';
    ctx.fillText(allowPct.toFixed(1) + '%', spacing + barWidth / 2, height - 25 - allowHeight);
    ctx.fillText(blockPct.toFixed(1) + '%', spacing + barWidth + 20 + barWidth / 2, height - 25 - blockHeight);
}

// ============================================================================
// Pattern Analysis
// ============================================================================

function updatePatternAnalysis() {
    if (Dashboard.data.sequences.length === 0) return;

    const patterns = {};

    Dashboard.data.sequences.forEach(seq => {
        const pattern = analyzeSequencePattern(seq.sequence);

        if (!patterns[pattern]) {
            patterns[pattern] = 0;
        }
        patterns[pattern]++;
    });

    Dashboard.data.patterns = patterns;
}

function analyzeSequencePattern(sequence) {
    if (sequence.length < 2) return 'unknown';

    let ascending = 0, descending = 0;

    for (let i = 0; i < sequence.length - 1; i++) {
        if (sequence[i] < sequence[i + 1]) ascending++;
        else if (sequence[i] > sequence[i + 1]) descending++;
    }

    if (ascending > descending) return 'ascending';
    if (descending > ascending) return 'descending';
    return 'mixed';
}

function updatePatternCharts() {
    const container = document.getElementById('pattern-items');
    if (!container) return;

    container.innerHTML = '';

    Object.entries(Dashboard.data.patterns).forEach(([pattern, count]) => {
        const div = document.createElement('div');
        div.className = 'pattern-item';
        div.innerHTML = `
            <div class="pattern-type">${pattern.toUpperCase()}</div>
            <div class="pattern-stats">
                <div>Occurrences: ${count}</div>
                <div>Ratio: ${(count / Dashboard.data.sequences.length * 100).toFixed(1)}%</div>
            </div>
        `;
        container.appendChild(div);
    });
}

// ============================================================================
// Innovation Suggestions
// ============================================================================

function updateInnovationCards() {
    // Simulate suggestions (in production, would come from backend)
    const suggestions = [
        {
            title: "Pattern-Based Hash Optimization",
            description: "Use detected sequence patterns to cache results",
            category: "performance",
            impact: "high",
            benefit: "20-40% faster"
        },
        {
            title: "Behavioral Anomaly Detection",
            description: "ML-based detection of suspicious IPs",
            category: "security",
            impact: "high",
            benefit: "15-30% more attacks detected"
        },
        {
            title: "GPU-Accelerated Computation",
            description: "Leverage GPU SIMD for parallel processing",
            category: "performance",
            impact: "high",
            benefit: "500+ MB/s"
        },
        {
            title: "Distributed Firewall Network",
            description: "Deploy across multiple servers globally",
            category: "detection",
            impact: "medium",
            benefit: "10k+ concurrent"
        }
    ];

    const container = document.getElementById('suggestion-items');
    if (!container) return;

    container.innerHTML = '';

    suggestions.forEach(sugg => {
        const div = document.createElement('div');
        div.className = 'suggestion-item';
        div.innerHTML = `
            <div class="suggestion-title">${sugg.title}</div>
            <div class="suggestion-description">${sugg.description}</div>
            <div class="suggestion-impact">
                <span class="impact-badge ${sugg.impact}">${sugg.impact.toUpperCase()}</span>
                <span class="impact-badge">${sugg.benefit}</span>
            </div>
        `;
        container.appendChild(div);
    });
}

// ============================================================================
// Status Bar
// ============================================================================

function updateStatusBar() {
    const uptime = formatUptime();
    const status = Dashboard.data.stats.total_verifications > 0 ? 'Online' : 'Initializing';

    const statusElement = document.getElementById('status-time');
    if (statusElement) {
        statusElement.textContent = `Status: ${status} | Uptime: ${uptime}`;
    }
}

function formatUptime() {
    const now = new Date();
    const pageStart = new Date(document.documentElement.dataset.startTime || now);
    const diff = Math.floor((now - pageStart) / 1000);

    const hours = Math.floor(diff / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    const seconds = diff % 60;

    return `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

// ============================================================================
// Utilities
// ============================================================================

function showError(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert-box error';
    alertDiv.textContent = '⚠ ' + message;

    const container = document.querySelector('.content-area');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);

        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
}

function showSuccess(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert-box success';
    alertDiv.textContent = '✓ ' + message;

    const container = document.querySelector('.content-area');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);

        setTimeout(() => {
            alertDiv.remove();
        }, 3000);
    }
}

// Start uptime tracking
document.documentElement.dataset.startTime = new Date().toISOString();

console.log('Dashboard script loaded');
