// ============ 模型进化训练逻辑 ============

document.addEventListener('DOMContentLoaded', () => {
    setupTrainingEventListeners();
});

function setupTrainingEventListeners() {
    const startTrainingBtn = document.getElementById('startTrainingBtn');
    if (startTrainingBtn) {
        startTrainingBtn.addEventListener('click', startTraining);
    }
}

async function startTraining() {
    const confirmStart = confirm("此操作将分析所有攻击日志并重新训练重排序模型，可能耗时较长 (几分钟)，确定启动吗？");
    if (!confirmStart) return;

    const startTrainingBtn = document.getElementById('startTrainingBtn');
    const container = document.getElementById('trainingStatusContainer');
    
    // UI 状态
    startTrainingBtn.disabled = true;
    container.style.display = 'block';
    addTrainingLog("[SYSTEM] 正在启动全流程进化训练...");

    const data = await apiRequest('training/start', { method: 'POST' });
    
    if (data && data.success) {
        showNotification('训练任务已启动', 'success');
        startTrainingUpdate();
    } else {
        startTrainingBtn.disabled = false;
        showNotification('启动训练失败', 'error');
    }
}

let trainingUpdateInterval = null;

function startTrainingUpdate() {
    if (trainingUpdateInterval) clearInterval(trainingUpdateInterval);
    trainingUpdateInterval = setInterval(updateTrainingStatus, 2000);
}

async function updateTrainingStatus() {
    const data = await apiRequest('training/status');
    if (!data || !data.success) return;

    const status = data.status;
    const phase = document.getElementById('trainingPhase');
    const progressText = document.getElementById('trainingProgressText');
    const progressBar = document.getElementById('trainingProgressBar');
    const message = document.getElementById('trainingMessage');
    const logsContainer = document.getElementById('trainingLogs');

    // 更新文本和进度
    phase.textContent = getPhaseName(status.phase);
    progressText.textContent = status.progress + '%';
    progressBar.style.width = status.progress + '%';
    message.textContent = status.message;

    // 更新日志
    if (status.logs && status.logs.length > 0) {
        logsContainer.innerHTML = '';
        status.logs.forEach(log => {
            const entry = document.createElement('div');
            entry.textContent = log;
            if (log.includes('❌')) entry.style.color = '#ff6b6b';
            if (log.includes('✓')) entry.style.color = '#51cf66';
            if (log.includes('>>>')) entry.style.color = '#fcc419';
            logsContainer.appendChild(entry);
        });
        logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    // 检查是否结束
    if (!status.running && status.phase !== 'idle' && status.phase !== 'labeling' && status.phase !== 'training') {
        clearInterval(trainingUpdateInterval);
        document.getElementById('startTrainingBtn').disabled = false;
        if (status.phase === 'completed') {
            showNotification('模型进化完成！系统已升级。', 'success');
        } else if (status.phase === 'error') {
            showNotification('训练过程出现错误', 'error');
        }
    }
}

function getPhaseName(phase) {
    const phases = {
        'idle': '空闲',
        'labeling': 'HER 样本标注阶段',
        'training': 'Cross-Encoder 训练阶段',
        'completed': '进化完成',
        'error': '训练异常'
    };
    return phases[phase] || phase;
}

function addTrainingLog(message) {
    const logsContainer = document.getElementById('trainingLogs');
    const entry = document.createElement('div');
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logsContainer.appendChild(entry);
    logsContainer.scrollTop = logsContainer.scrollHeight;
}
