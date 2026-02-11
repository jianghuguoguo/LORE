/**
 * 智能检索系统 - 前端交互逻辑
 * System 2 Reflection Visualization
 */

class AdaptiveSearchVisualizer {
    constructor() {
        this.currentIteration = 0;
        this.workflowData = null;
        this.animationDelay = 800; // ms
        
        this.init();
    }
    
    init() {
        // 绑定事件
        document.getElementById('startAdaptiveBtn')?.addEventListener('click', () => {
            this.startAdaptiveSearch();
        });

        // 绑定 RAGFlow 推送按钮
        document.getElementById('pushToRagflowBtn')?.addEventListener('click', () => {
            this.pushExperienceToRagflow();
        });
        
        console.log('✅ 自适应检索可视化系统已初始化');
    }

    async pushExperienceToRagflow() {
        const btn = document.getElementById('pushToRagflowBtn');
        const originalHTML = btn.innerHTML;
        
        try {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 总结并推送中...';
            
            const response = await fetch('/api/ragflow/push_summary', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showNotification('✅ 经验总结已成功推送至 RAGFlow 经验库！', 'success');
                // 弹出总结内容预览（可选）
                console.log('Summary:', data.summary);
            } else {
                this.showNotification('❌ 推送失败: ' + data.message, 'error');
            }
        } catch (error) {
            console.error('推送错误:', error);
            this.showNotification('网络错误，请重试', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalHTML;
        }
    }
    
    /**
     * 启动自适应检索
     */
    async startAdaptiveSearch() {
        const query = document.getElementById('adaptiveQuery').value.trim();
        const maxIterations = parseInt(document.getElementById('maxIterations').value);
        
        if (!query) {
            this.showNotification('请输入检索查询', 'error');
            return;
        }
        
        // 禁用按钮
        const btn = document.getElementById('startAdaptiveBtn');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 检索中...';
        
        // 清空之前的结果
        this.clearResults();
        
        // 显示加载状态
        this.showLoading();
        
        try {
            const response = await fetch('/api/adaptive-search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    query: query,
                    max_iterations: maxIterations
                })
            });
            
            const data = await response.json();
            
            if (data.iterations) {
                this.workflowData = data;
                await this.visualizeWorkflow(data);
                
                if (data.success) {
                    this.showNotification('检索成功完成！', 'success');
                } else {
                    this.showNotification('检索已结束（未达到最佳精度）', 'warning');
                }
                
                // 只要有过程，就显示推送按钮
                const pushBtn = document.getElementById('pushToRagflowBtn');
                if (pushBtn) pushBtn.style.display = 'block';
            } else {
                this.showNotification(data.message || '检索出现严重异常', 'error');
            }
        } catch (error) {
            console.error('检索错误:', error);
            this.showNotification('网络错误，请重试', 'error');
        } finally {
            // 恢复按钮
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-rocket"></i> 启动智能检索';
        }
    }
    
    /**
     * 可视化工作流
     */
    async visualizeWorkflow(data) {
        // 1. 显示流程步骤
        await this.renderWorkflowSteps(data.iterations);
        
        // 2. 显示迭代历史
        await this.renderIterationHistory(data.iterations);
        
        // 3. 显示最终结果
        this.renderFinalResults(data.final_results);
        
        // 4. 显示统计信息
        this.renderStats(data);
    }
    
    /**
     * 渲染工作流步骤
     */
    async renderWorkflowSteps(iterations) {
        const container = document.getElementById('workflowViz');
        
        // 创建流程步骤容器
        const stepsHTML = `
            <div class="workflow-steps">
                <div class="workflow-connector">
                    <div class="workflow-connector-progress" id="workflowProgress"></div>
                </div>
                <div class="workflow-step" data-step="search">
                    <div class="workflow-step-icon">
                        <i class="fas fa-search"></i>
                    </div>
                    <div class="workflow-step-label">检索 (Search)</div>
                    <div class="workflow-step-desc">执行初始查询</div>
                </div>
                <div class="workflow-step" data-step="detect">
                    <div class="workflow-step-icon">
                        <i class="fas fa-radar"></i>
                    </div>
                    <div class="workflow-step-label">检测 (Detect)</div>
                    <div class="workflow-step-desc">失败检测</div>
                </div>
                <div class="workflow-step" data-step="diagnose">
                    <div class="workflow-step-icon">
                        <i class="fas fa-stethoscope"></i>
                    </div>
                    <div class="workflow-step-label">诊断 (Diagnose)</div>
                    <div class="workflow-step-desc">分析失败原因</div>
                </div>
                <div class="workflow-step" data-step="rewrite">
                    <div class="workflow-step-icon">
                        <i class="fas fa-edit"></i>
                    </div>
                    <div class="workflow-step-label">重写 (Rewrite)</div>
                    <div class="workflow-step-desc">生成新查询</div>
                </div>
            </div>
        `;
        
        container.innerHTML = stepsHTML;
        
        // 动画展示每个步骤
        const steps = container.querySelectorAll('.workflow-step');
        for (let i = 0; i < steps.length; i++) {
            await this.sleep(this.animationDelay);
            steps[i].classList.add('active');
            steps[i].style.animationDelay = `${i * 0.1}s`;
            
            // 更新进度条
            const progress = ((i + 1) / steps.length) * 100;
            document.getElementById('workflowProgress').style.width = `${progress}%`;
        }
        
        // 根据最终结果更新状态
        const lastIteration = iterations[iterations.length - 1];
        if (!lastIteration.is_failed) {
            steps[1].classList.add('success'); // Detect成功
        } else {
            steps[1].classList.add('failure'); // Detect失败
        }
    }
    
    /**
     * 渲染迭代历史
     */
    async renderIterationHistory(iterations) {
        const container = document.getElementById('iterationHistory');
        container.innerHTML = '';
        
        for (let i = 0; i < iterations.length; i++) {
            const iter = iterations[i];
            await this.sleep(this.animationDelay / 2);
            
            const card = this.createIterationCard(iter, i);
            container.appendChild(card);
        }
    }
    
    /**
     * 创建迭代卡片
     */
    createIterationCard(iteration, index) {
        const card = document.createElement('div');
        card.className = 'iteration-card';
        card.style.animationDelay = `${index * 0.1}s`;
        
        const statusClass = iteration.is_failed ? 'failed' : 'success';
        const statusText = iteration.is_failed ? '失败 - 需要重写' : '成功';
        
        let diagnosisHTML = '';
        if (iteration.diagnosis) {
            const reasons = iteration.failure_reasons ? iteration.failure_reasons.join(', ') : '未知';
            diagnosisHTML = `
                <div class="diagnosis-section">
                    <span class="diagnosis-label">🔍 诊断结果</span>
                    <div class="diagnosis-content">
                        <strong>失败原因:</strong> ${reasons}<br>
                        <strong>诊断类型:</strong> ${iteration.diagnosis.type || 'General'}<br>
                        <strong>建议:</strong> ${iteration.diagnosis.suggestion || '尝试更具体的查询'}
                    </div>
                </div>
            `;
        }
        
        let rewrittenHTML = '';
        if (iteration.rewritten_queries && iteration.rewritten_queries.length > 0) {
            const queries = iteration.rewritten_queries
                .map(q => `<span class="rewritten-query">${q}</span>`)
                .join('');
            rewrittenHTML = `
                <div style="margin-top: 10px;">
                    <span class="diagnosis-label">✏️ 重写查询</span>
                    <div class="rewritten-queries">${queries}</div>
                </div>
            `;
        }
        
        card.innerHTML = `
            <div class="iteration-header">
                <span class="iteration-number">第 ${iteration.iteration} 轮迭代</span>
                <span class="iteration-status ${statusClass}">${statusText}</span>
            </div>
            <div class="iteration-query">
                <strong>查询:</strong> ${iteration.query}
            </div>
            <div style="color: rgba(255,255,255,0.6); font-size: 12px;">
                <i class="fas fa-database"></i> 结果数量: ${iteration.results_count} 条
                <i class="fas fa-clock" style="margin-left: 15px;"></i> 耗时: ${iteration.time_ms}ms
            </div>
            ${diagnosisHTML}
            ${rewrittenHTML}
        `;
        
        return card;
    }
    
    /**
     * 渲染最终结果
     */
    renderFinalResults(results) {
        const container = document.getElementById('finalResults');
        
        if (!results || results.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-inbox"></i>
                    <p>未找到结果</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = '';
        
        results.forEach((result, index) => {
            setTimeout(() => {
                const item = this.createResultItem(result, index);
                container.appendChild(item);
            }, index * 100);
        });
    }
    
    /**
     * 创建结果项
     */
    createResultItem(result, index) {
        const item = document.createElement('div');
        item.className = 'result-item';
        
        // 计算评分等级
        const score = result.score || 0;
        let scoreLevel = 'low';
        if (score >= 0.7) scoreLevel = 'high';
        else if (score >= 0.4) scoreLevel = 'medium';
        
        item.setAttribute('data-score-level', scoreLevel);
        item.style.animationDelay = `${index * 0.05}s`;
        
        item.innerHTML = `
            <div class="result-header">
                <span class="result-id">${result.id}</span>
                <div class="utility-score">
                    <span class="score-label">效用分数</span>
                    <span class="score-value">${score.toFixed(2)}</span>
                </div>
            </div>
            <div class="score-bar">
                <div class="score-fill" style="width: ${score * 100}%"></div>
            </div>
            <div class="result-content">
                ${result.content}
                <div style="margin-top: 8px; color: rgba(255,255,255,0.4); font-size: 12px;">
                    <i class="fas fa-file-alt"></i> 长度: ${result.length} 字符
                </div>
            </div>
        `;
        
        return item;
    }
    
    /**
     * 渲染统计信息
     */
    renderStats(data) {
        const container = document.getElementById('workflowViz');
        
        const totalIterations = data.iterations.length;
        const totalTime = data.total_time;
        const avgTime = Math.round(totalTime / totalIterations);
        const successRate = data.iterations.filter(i => !i.is_failed).length / totalIterations * 100;
        
        const statsHTML = `
            <div class="stats-summary">
                <div class="stat-item">
                    <span class="stat-value">${totalIterations}</span>
                    <span class="stat-label">总迭代次数</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${totalTime}ms</span>
                    <span class="stat-label">总耗时</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${avgTime}ms</span>
                    <span class="stat-label">平均耗时/轮</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${successRate.toFixed(0)}%</span>
                    <span class="stat-label">成功率</span>
                </div>
            </div>
        `;
        
        container.insertAdjacentHTML('beforeend', statsHTML);
    }
    
    /**
     * 显示加载状态
     */
    showLoading() {
        const container = document.getElementById('workflowViz');
        container.innerHTML = `
            <div class="loading-container">
                <div class="loading-spinner"></div>
                <div class="loading-text">正在执行智能检索...</div>
            </div>
        `;
    }
    
    /**
     * 清空结果
     */
    clearResults() {
        document.getElementById('iterationHistory').innerHTML = '';
        document.getElementById('finalResults').innerHTML = `
            <div class="empty-state">
                <i class="fas fa-inbox"></i>
                <p>暂无结果</p>
            </div>
        `;
        // 隐藏推送按钮
        const pushBtn = document.getElementById('pushToRagflowBtn');
        if (pushBtn) pushBtn.style.display = 'none';
    }
    
    /**
     * 显示通知
     */
    showNotification(message, type = 'info') {
        // 简单的通知实现，可以替换为更好的通知库
        const colors = {
            success: '#38ef7d',
            error: '#f45c43',
            info: '#00ffff'
        };
        
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${colors[type]};
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 10000;
            animation: slide-in 0.3s ease;
        `;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slide-in 0.3s ease reverse';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    /**
     * 延迟函数
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    window.adaptiveSearchViz = new AdaptiveSearchVisualizer();
});
