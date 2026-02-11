// ============ 全局变量 ============
let selectedSources = [];
let updateInterval = null;
let isRunning = false;

// ============ API请求函数 ============
async function apiRequest(endpoint, options = {}) {
    try {
        const response = await fetch(`/api/${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API请求失败:', error);
        showNotification('请求失败: ' + error.message, 'error');
        return null;
    }
}

// ============ 初始化 ============
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
    startAutoUpdate();
});

async function initializeApp() {
    await loadCrawlers();
    await updateStatus();
    await loadLogs();
    await loadFiles();
    updateLastUpdateTime();
}

// ============ 加载爬虫列表 ============
async function loadCrawlers() {
    const data = await apiRequest('crawlers');
    
    if (data && data.success) {
        const crawlerList = document.getElementById('crawlerList');
        crawlerList.innerHTML = '';
        
        data.crawlers.forEach(crawler => {
            const item = createCrawlerItem(crawler);
            crawlerList.appendChild(item);
        });
        
        updateSystemInfo('crawlerCount', data.crawlers.length);
    }
}

function createCrawlerItem(crawler) {
    const div = document.createElement('div');
    div.className = 'crawler-item';
    
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.id = `crawler-${crawler.name}`;
    checkbox.value = crawler.name;
    checkbox.checked = crawler.enabled;
    
    checkbox.addEventListener('change', (e) => {
        if (e.target.checked) {
            selectedSources.push(crawler.name);
            div.classList.add('active');
        } else {
            selectedSources = selectedSources.filter(s => s !== crawler.name);
            div.classList.remove('active');
        }
    });
    
    if (crawler.enabled) {
        selectedSources.push(crawler.name);
        div.classList.add('active');
    }
    
    const label = document.createElement('label');
    label.htmlFor = `crawler-${crawler.name}`;
    label.className = 'crawler-name';
    label.textContent = crawler.display_name;
    label.style.cursor = 'pointer';
    
    const status = document.createElement('span');
    status.className = 'crawler-status';
    status.textContent = crawler.enabled ? '启用' : '禁用';
    
    div.appendChild(checkbox);
    div.appendChild(label);
    div.appendChild(status);
    
    return div;
}

// ============ 更新状态 ============
async function updateStatus() {
    const data = await apiRequest('status');
    
    if (data && data.success) {
        const status = data.status;
        isRunning = status.running;
        
        // 更新按钮状态
        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        
        startBtn.disabled = isRunning;
        stopBtn.disabled = !isRunning;
        
        // 更新系统状态
        const systemStatus = document.getElementById('systemStatus');
        if (isRunning) {
            systemStatus.innerHTML = '<i class="fas fa-circle"></i> 爬取中...';
            systemStatus.style.background = 'rgba(249, 115, 22, 0.3)';
        } else {
            systemStatus.innerHTML = '<i class="fas fa-circle"></i> 系统就绪';
            systemStatus.style.background = 'rgba(255, 255, 255, 0.2)';
        }
        
        // 更新当前状态
        updateSystemInfo('currentStatus', 
            isRunning ? `爬取中: ${status.current_source || '准备中'}` : '空闲'
        );
        
        // 更新进度
        if (status.progress && Object.keys(status.progress).length > 0) {
            updateProgress(status.progress);
        } else if (!isRunning) {
            showEmptyProgress();
        }
    }
}

// ============ 更新进度显示 ============
function updateProgress(progress) {
    const container = document.getElementById('progressContainer');
    container.innerHTML = '';
    
    let totalCount = 0;
    
    for (const [source, info] of Object.entries(progress)) {
        const item = createProgressItem(source, info);
        container.appendChild(item);
        totalCount += info.count || 0;
    }
    
    updateSystemInfo('totalResults', totalCount);
    updateStats(progress);
}

function createProgressItem(source, info) {
    const div = document.createElement('div');
    div.className = 'progress-item';
    
    const header = document.createElement('div');
    header.className = 'progress-header';
    
    const title = document.createElement('div');
    title.className = 'progress-title';
    title.textContent = source.toUpperCase();
    
    const count = document.createElement('div');
    count.className = 'progress-count';
    count.textContent = `${info.count || 0} 条数据`;
    
    header.appendChild(title);
    header.appendChild(count);
    
    const progressBar = document.createElement('div');
    progressBar.className = 'progress-bar';
    
    const progressFill = document.createElement('div');
    progressFill.className = 'progress-fill';
    
    if (info.status === 'completed') {
        progressFill.classList.add('completed');
        progressFill.style.width = '100%';
    } else if (info.status === 'error') {
        progressFill.classList.add('error');
        progressFill.style.width = '100%';
    } else if (info.status === 'running') {
        progressFill.style.width = '50%';
    } else {
        progressFill.style.width = '0%';
    }
    
    progressBar.appendChild(progressFill);
    
    div.appendChild(header);
    div.appendChild(progressBar);
    
    return div;
}

function showEmptyProgress() {
    const container = document.getElementById('progressContainer');
    container.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-clock"></i>
            <p>暂无运行中的任务</p>
        </div>
    `;
}

// ============ 更新统计 ============
function updateStats(progress) {
    const container = document.getElementById('statsContainer');
    container.innerHTML = '';
    
    for (const [source, info] of Object.entries(progress)) {
        const card = document.createElement('div');
        card.className = 'stat-card';
        
        const value = document.createElement('div');
        value.className = 'stat-value';
        value.textContent = info.count || 0;
        
        const label = document.createElement('div');
        label.className = 'stat-label';
        label.textContent = source.toUpperCase();
        
        card.appendChild(value);
        card.appendChild(label);
        container.appendChild(card);
    }
}

// ============ 加载日志 ============
async function loadLogs() {
    const data = await apiRequest('logs?limit=50');
    
    if (data && data.success) {
        const container = document.getElementById('logContainer');
        container.innerHTML = '';
        
        if (data.logs.length === 0) {
            container.innerHTML = `
                <div class="log-entry log-info">
                    <span class="log-time">${new Date().toLocaleString('zh-CN')}</span>
                    <span class="log-level">INFO</span>
                    <span class="log-source">system</span>
                    <span class="log-message">系统启动完成</span>
                </div>
            `;
        } else {
            data.logs.forEach(log => {
                const entry = createLogEntry(log);
                container.appendChild(entry);
            });
            
            // 滚动到底部
            container.scrollTop = container.scrollHeight;
        }
    }
}

function createLogEntry(log) {
    const div = document.createElement('div');
    div.className = `log-entry log-${log.level}`;
    
    div.innerHTML = `
        <span class="log-time">${log.timestamp}</span>
        <span class="log-level">${log.level.toUpperCase()}</span>
        <span class="log-source">${log.source}</span>
        <span class="log-message">${log.message}</span>
    `;
    
    return div;
}

// ============ 加载结果 ============
async function loadResults() {
    const data = await apiRequest('results');
    
    if (data && data.success) {
        const container = document.getElementById('resultsContainer');
        
        if (Object.keys(data.results).length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-inbox"></i>
                    <p>暂无结果数据</p>
                </div>
            `;
        } else {
            container.innerHTML = '';
            
            for (const [source, results] of Object.entries(data.results)) {
                const section = createResultsSection(source, results);
                container.appendChild(section);
            }
        }
    }
}

function createResultsSection(source, results) {
    const div = document.createElement('div');
    div.className = 'results-source';
    
    const header = document.createElement('div');
    header.className = 'results-header';
    header.innerHTML = `
        <h3>${source.toUpperCase()}</h3>
        <span>${results.length} 条结果</span>
    `;
    
    const list = document.createElement('div');
    list.className = 'results-list';
    
    results.slice(0, 20).forEach(result => {
        const item = document.createElement('div');
        item.className = 'result-item';
        item.innerHTML = `
            <div class="result-title">${result.title || '无标题'}</div>
            <div class="result-meta">
                ${result.author || ''} | ${result.publish_time || ''} | ${result.url || ''}
            </div>
        `;
        list.appendChild(item);
    });
    
    div.appendChild(header);
    div.appendChild(list);
    
    return div;
}

// ============ 加载文件列表 ============
async function loadFiles() {
    const data = await apiRequest('files');
    
    if (data && data.success) {
        const tbody = document.querySelector('#fileTable tbody');
        tbody.innerHTML = '';
        
        if (data.files.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                        暂无文件
                    </td>
                </tr>
            `;
        } else {
            data.files.forEach(file => {
                const row = createFileRow(file);
                tbody.appendChild(row);
            });
        }
    }
}

function createFileRow(file) {
    const tr = document.createElement('tr');
    
    const sizeKB = (file.size / 1024).toFixed(2);
    
    tr.innerHTML = `
        <td>${file.name}</td>
        <td>${file.source.toUpperCase()}</td>
        <td>${sizeKB} KB</td>
        <td>${file.modified}</td>
    `;
    
    return tr;
}

// ============ 事件监听器 ============
function setupEventListeners() {
    // 开始按钮
    document.getElementById('startBtn').addEventListener('click', startCrawl);
    
    // 停止按钮
    document.getElementById('stopBtn').addEventListener('click', stopCrawl);
    
    // 全选按钮
    document.getElementById('selectAllBtn').addEventListener('click', selectAll);
    
    // 清空日志
    document.getElementById('clearLogsBtn').addEventListener('click', () => {
        document.getElementById('logContainer').innerHTML = '';
    });
    
    // 刷新状态
    document.getElementById('refreshBtn').addEventListener('click', () => {
        updateStatus();
        loadLogs();
        showNotification('状态已刷新', 'success');
    });
    
    // Tab切换
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
}

// ============ 开始爬取 ============
async function startCrawl() {
    const query = document.getElementById('queryInput').value.trim();
    const maxPages = parseInt(document.getElementById('maxPagesInput').value);
    
    if (selectedSources.length === 0) {
        showNotification('请至少选择一个数据源', 'warning');
        return;
    }
    
    if (!query) {
        showNotification('请输入搜索关键词', 'warning');
        return;
    }
    
    const data = await apiRequest('start', {
        method: 'POST',
        body: JSON.stringify({
            sources: selectedSources,
            query: query,
            max_pages: maxPages
        })
    });
    
    if (data && data.success) {
        showNotification('爬取任务已启动', 'success');
        // 增加更新频率
        startFastUpdate();
    }
}

// ============ 停止爬取 ============
async function stopCrawl() {
    const data = await apiRequest('stop', {
        method: 'POST'
    });
    
    if (data && data.success) {
        showNotification('正在停止爬取...', 'warning');
    }
}

// ============ 全选 ============
function selectAll() {
    const checkboxes = document.querySelectorAll('.crawler-item input[type="checkbox"]');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    
    checkboxes.forEach(checkbox => {
        checkbox.checked = !allChecked;
        checkbox.dispatchEvent(new Event('change'));
    });
}

// ============ Tab切换 ============
function switchTab(tabName) {
    // 更新按钮状态
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // 更新面板显示
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(`${tabName}-panel`).classList.add('active');
    
    // 加载对应数据
    if (tabName === 'results') {
        loadResults();
    } else if (tabName === 'files') {
        loadFiles();
    } else if (tabName === 'hindsight') {
        loadHindsightData();
    }
}

// ============ Hindsight 数据加载 ============
async function loadHindsightData() {
    // 1. 获取统计
    const stats = await apiRequest('hindsight/stats');
    if (stats && stats.status === 'success') {
        document.getElementById('hindsightLogCount').textContent = stats.log_files_count;
        document.getElementById('hindsightLastRun').textContent = stats.last_processed;
    }

    // 2. 获取样本
    const data = await apiRequest('hindsight/data');
    if (data && data.status === 'success') {
        document.getElementById('hindsightSampleCount').textContent = data.total;
        
        const tableBody = document.getElementById('hindsightSamplesTable');
        tableBody.innerHTML = '';
        
        if (data.samples.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center">暂无样本，请运行 processors.auto_labeler_v2</td></tr>';
            return;
        }

        data.samples.forEach(sample => {
            const tr = document.createElement('tr');
            
            // 评分颜色
            const relScore = sample.relevance_score || 0;
            const scoreClass = relScore > 0.6 ? 'text-success' : (relScore > 0.3 ? 'text-primary' : 'text-warning');
            
            // 标签徽章
            const labelBadge = sample.label === 1.0 
                ? '<span class="status-badge" style="background:#00f2fe; color:#000">POSITIVE</span>'
                : '<span class="status-badge" style="background:#555">NEGATIVE</span>';

            tr.innerHTML = `
                <td><div class="query-cell">${sample.query}</div></td>
                <td><span class="${scoreClass}">${(relScore * 100).toFixed(1)}%</span></td>
                <td>${labelBadge}</td>
                <td><small class="context-cell">${sample.context || 'N/A'}</small></td>
            `;
            tableBody.appendChild(tr);
        });
    }
}

// ============ 自动更新 ============
function startAutoUpdate() {
    // 普通更新频率: 每3秒
    updateInterval = setInterval(() => {
        updateStatus();
        loadLogs();
        updateLastUpdateTime();
    }, 3000);
}

function startFastUpdate() {
    // 爬取时更新频率: 每1秒
    if (updateInterval) {
        clearInterval(updateInterval);
    }
    
    updateInterval = setInterval(() => {
        updateStatus();
        loadLogs();
        updateLastUpdateTime();
        
        // 如果不在运行，恢复普通频率
        if (!isRunning) {
            clearInterval(updateInterval);
            startAutoUpdate();
        }
    }, 1000);
}

// ============ 辅助函数 ============
function updateSystemInfo(key, value) {
    const element = document.getElementById(key);
    if (element) {
        element.textContent = value;
    }
}

function updateLastUpdateTime() {
    const element = document.getElementById('lastUpdate');
    if (element) {
        element.textContent = new Date().toLocaleTimeString('zh-CN');
    }
}

function showNotification(message, type = 'info') {
    // 简单的通知实现
    console.log(`[${type.toUpperCase()}] ${message}`);
    
    // 可以添加更复杂的通知UI
    const colors = {
        success: '#059669',
        warning: '#d97706',
        error: '#dc2626',
        info: '#0891b2'
    };
    
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type] || colors.info};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// 添加CSS动画
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
