/* ═══════════════════════════════════════════════════════════
  LORE Dashboard — main.js
   ═══════════════════════════════════════════════════════════ */

/* ── Page routing ─────────────────────────────────────────── */
const PAGE_LAYER = {
  factual:    'FACTUAL',
  pos:        'PROCEDURAL_POS',
  neg:        'PROCEDURAL_NEG',
  meta:       'METACOGNITIVE',
  conceptual: 'CONCEPTUAL',
};
const LAYER_COLOUR = {
  FACTUAL:       '#38bdf8',
  PROCEDURAL_POS:'#4ade80',
  PROCEDURAL_NEG:'#f87171',
  METACOGNITIVE: '#fbbf24',
  CONCEPTUAL:    '#c084fc',
};
const LAYER_LABEL = {
  FACTUAL:       'FACTUAL',
  PROCEDURAL_POS:'POS',
  PROCEDURAL_NEG:'NEG',
  METACOGNITIVE: 'META',
  CONCEPTUAL:    'CONCEPT',
};

let currentPage = 'overview';
// per-layer pagination state
const pageState = {};
Object.keys(PAGE_LAYER).forEach(k => { pageState[k] = 1; });
let searchQuery = '';

function navigate(page) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });
  document.querySelectorAll('.page').forEach(el => {
    el.classList.toggle('active', el.id === `page-${page}`);
  });

  const searchEl = document.getElementById('sidebarSearch');
  const showSearch = PAGE_LAYER[page] !== undefined;
  searchEl.style.display = showSearch ? '' : 'none';

  // 显示/隐藏刷新按钮（仅经验页显示）
  const refreshBtn = document.getElementById('expRefreshBtn');
  if (refreshBtn) refreshBtn.style.display = showSearch ? '' : 'none';

  currentPage = page;

  if (page === 'overview') loadOverview();
  else if (page === 'sessions') loadSessions();
  else if (page === 'pipeline') loadPipelineStatus();
  else if (page === 'crawler') loadCrawler();
  else if (page === 'ragflow') { /* 页面已显示，不需要额外加载 */ }
  else if (page === 'consolidated') loadConsolidated();
  else if (page === 'conflicts') navigate('consolidated');  // 已合并入融合经验库页
  else if (page === 'gaps') navigate('consolidated');       // 已合并入融合经验库页
  else if (PAGE_LAYER[page]) loadExpPage(page, pageState[page]);
}

function refreshCurrentExpPage() {
  if (PAGE_LAYER[currentPage]) {
    pageState[currentPage] = 1;
    document.getElementById('globalSearch').value = '';
    searchQuery = '';
    loadExpPage(currentPage, 1);
  }
}

/* ── API helpers ──────────────────────────────────────────── */
async function api(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) {
      console.error(`API ${url} => HTTP ${r.status}`);
      return { success: false };
    }
    return r.json();
  } catch (e) {
    console.error(`API ${url} error:`, e);
    return { success: false };
  }
}

/* ══════════════════════════════════════════════════════════
   OVERVIEW
═══════════════════════════════════════════════════════════ */
let _charts = {};

async function loadOverview() {
  const data = await api('/api/stats');
  if (!data.success) return;

  // Top mini-stat pills
  const lc = data.layer_counts || {};
  document.getElementById('ms-total').textContent   = data.total_experiences;
  document.getElementById('ms-factual').textContent = lc['FACTUAL'] || 0;
  document.getElementById('ms-neg').textContent     = lc['PROCEDURAL_NEG'] || 0;
  document.getElementById('ms-meta').textContent    = lc['METACOGNITIVE'] || 0;
  document.getElementById('ms-sessions').textContent= data.total_sessions;

  // Stat cards
  document.getElementById('sc-total').textContent    = data.total_experiences;
  document.getElementById('sc-factual').textContent  = lc['FACTUAL'] || 0;
  document.getElementById('sc-neg').textContent      = lc['PROCEDURAL_NEG'] || 0;
  document.getElementById('sc-meta').textContent     = lc['METACOGNITIVE'] || 0;
  document.getElementById('sc-concept').textContent  = lc['CONCEPTUAL'] || 0;
  document.getElementById('sc-sessions').textContent = data.total_sessions;

  // Nav badges
  document.getElementById('nb-factual').textContent = lc['FACTUAL'] || 0;
  document.getElementById('nb-pos').textContent     = lc['PROCEDURAL_POS'] || 0;
  document.getElementById('nb-neg').textContent     = lc['PROCEDURAL_NEG'] || 0;
  document.getElementById('nb-meta').textContent    = lc['METACOGNITIVE'] || 0;
  document.getElementById('nb-concept').textContent = lc['CONCEPTUAL'] || 0;

  drawCharts(data);
}

function drawCharts(d) {
  const isDark = true; // always dark

  function initOrGet(id) {
    const el = document.getElementById(id);
    let chart = echarts.getInstanceByDom(el);
    if (!chart) chart = echarts.init(el, 'dark');
    _charts[id] = chart;
    return chart;
  }

  const baseOpt = {
    backgroundColor: 'transparent',
    textStyle: { fontFamily: 'Inter, sans-serif', color: '#94a3b8', fontSize: 11 },
  };

  /* ── Knowledge-layer bar ────────────────── */
  {
    const lc = d.layer_counts || {};
    const labels = Object.keys(LAYER_LABEL);
    const values = labels.map(l => lc[l] || 0);
    const colors = labels.map(l => LAYER_COLOUR[l]);
    initOrGet('chartLayers').setOption({
      ...baseOpt,
      grid: { top: 10, left: 40, right: 20, bottom: 40 },
      xAxis: {
        type: 'category',
        data: labels.map(l => LAYER_LABEL[l]),
        axisLine: { lineStyle: { color: '#334155' } },
        axisLabel: { color: '#94a3b8', fontSize: 11 },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: '#1e293b' } },
        axisLabel: { color: '#64748b' },
      },
      series: [{
        type: 'bar',
        data: values.map((v, i) => ({ value: v, itemStyle: { color: colors[i], borderRadius: [4,4,0,0] } })),
        label: { show: true, position: 'top', color: '#e2e8f0', fontSize: 12 },
      }],
      tooltip: { trigger: 'axis', backgroundColor: '#1e293b', borderColor: '#334155' },
    });
  }

  /* ── Outcomes pie ───────────────────────── */
  {
    const oc = d.outcome_counts || {};
    const palette = { success: '#4ade80', partial_success: '#fbbf24', failure: '#f87171', unknown: '#64748b' };
    const pieData = Object.entries(oc).map(([k, v]) => ({
      name: k, value: v,
      itemStyle: { color: palette[k] || '#94a3b8' },
    }));
    initOrGet('chartOutcomes').setOption({
      ...baseOpt,
      tooltip: { trigger: 'item', backgroundColor: '#1e293b', borderColor: '#334155' },
      legend: { bottom: 0, textStyle: { color: '#94a3b8', fontSize: 10 } },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        data: pieData,
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 13, color: '#e2e8f0' } },
      }],
    });
  }

  /* ── Confidence bar ─────────────────────── */
  {
    const cd = d.confidence_dist || {};
    const keys = Object.keys(cd).sort();
    initOrGet('chartConf').setOption({
      ...baseOpt,
      grid: { top: 10, left: 35, right: 10, bottom: 40 },
      xAxis: {
        type: 'category', data: keys,
        axisLine: { lineStyle: { color: '#334155' } },
        axisLabel: { color: '#94a3b8', fontSize: 10 },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: '#1e293b' } },
        axisLabel: { color: '#64748b' },
      },
      series: [{
        type: 'bar',
        data: keys.map(k => ({
          value: cd[k],
          itemStyle: {
            color: cd[k] > 5 ? '#38bdf8' : '#334155',
            borderRadius: [3,3,0,0],
          },
        })),
      }],
      tooltip: { trigger: 'axis', backgroundColor: '#1e293b', borderColor: '#334155' },
    });
  }

  /* ── Service horizontal bar ─────────────── */
  {
    const sd = d.service_dist || {};
    const entries = Object.entries(sd).sort((a, b) => a[1] - b[1]);
    initOrGet('chartServices').setOption({
      ...baseOpt,
      grid: { top: 6, left: 8, right: 40, bottom: 6, containLabel: true },
      xAxis: { type: 'value', splitLine: { lineStyle: { color: '#1e293b' } }, axisLabel: { color: '#64748b', fontSize: 10 } },
      yAxis: { type: 'category', data: entries.map(e => e[0]), axisLabel: { color: '#94a3b8', fontSize: 10 } },
      series: [{
        type: 'bar',
        data: entries.map(([, v]) => v),
        itemStyle: { color: '#38bdf8', borderRadius: [0,3,3,0] },
        label: { show: true, position: 'right', color: '#94a3b8', fontSize: 10 },
      }],
      tooltip: { trigger: 'axis', backgroundColor: '#1e293b', borderColor: '#334155' },
    });
  }

  /* ── Phase horizontal bar ───────────────── */
  {
    const pd = d.phase_dist || {};
    const entries = Object.entries(pd).sort((a, b) => a[1] - b[1]);
    initOrGet('chartPhases').setOption({
      ...baseOpt,
      grid: { top: 6, left: 8, right: 40, bottom: 6, containLabel: true },
      xAxis: { type: 'value', splitLine: { lineStyle: { color: '#1e293b' } }, axisLabel: { color: '#64748b', fontSize: 10 } },
      yAxis: { type: 'category', data: entries.map(e => e[0]), axisLabel: { color: '#94a3b8', fontSize: 10 } },
      series: [{
        type: 'bar',
        data: entries.map(([, v]) => v),
        itemStyle: { color: '#fbbf24', borderRadius: [0,3,3,0] },
        label: { show: true, position: 'right', color: '#94a3b8', fontSize: 10 },
      }],
      tooltip: { trigger: 'axis', backgroundColor: '#1e293b', borderColor: '#334155' },
    });
  }

  /* ── Source pie ─────────────────────────── */
  {
    const sd = d.source_dist || {};
    const srcPalette = { rule: '#38bdf8', llm: '#c084fc', unknown: '#64748b' };
    const pieData = Object.entries(sd).map(([k, v]) => ({
      name: k, value: v,
      itemStyle: { color: srcPalette[k] || '#94a3b8' },
    }));
    initOrGet('chartSources').setOption({
      ...baseOpt,
      tooltip: { trigger: 'item', backgroundColor: '#1e293b', borderColor: '#334155' },
      legend: { bottom: 0, textStyle: { color: '#94a3b8', fontSize: 10 } },
      series: [{
        type: 'pie',
        radius: ['40%', '68%'],
        center: ['50%', '43%'],
        data: pieData,
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 13, color: '#e2e8f0' } },
      }],
    });
  }
}

/* ══════════════════════════════════════════════════════════
   EXPERIENCE LIST PAGES
═══════════════════════════════════════════════════════════ */
async function loadExpPage(pageKey, pageNum = 1) {
  const layer = PAGE_LAYER[pageKey];
  const gridEl = document.getElementById(`grid-${pageKey}`);
  const pgEl   = document.getElementById(`pg-${pageKey}`);
  if (!gridEl) return;

  gridEl.innerHTML = '<div class="loading"><i class="fas fa-circle-notch"></i> 加载中...</div>';
  pageState[pageKey] = pageNum;

  const params = new URLSearchParams({
    layer,
    page:  pageNum,
    size:  24,
    ...(searchQuery ? { search: searchQuery } : {}),
  });

  const data = await api(`/api/experiences?${params}`);
  if (!data.success) { gridEl.innerHTML = '<div class="empty-state"><i class="fas fa-circle-exclamation"></i>加载失败</div>'; return; }

  if (!data.experiences.length) {
    gridEl.innerHTML = '<div class="empty-state"><i class="fas fa-inbox"></i><p>暂无经验数据</p></div>';
    pgEl.innerHTML = '';
    return;
  }

  gridEl.innerHTML = data.experiences.map(expCard).join('');
  renderPagination(pgEl, data.total, data.page, data.size, pageKey);
}

function expCard(e) {
  const layer   = e.knowledge_layer || '';
  const content = e.content || {};
  const meta    = e.metadata || {};
  const conf    = parseFloat(e.confidence || 0);
  const tags    = (meta.tags || []).slice(0, 6);

  // Best snippet text
  let snippet = '';
  if      (content.evidence)            snippet = content.evidence;
  else if (content.remediation_hint)    snippet = content.remediation_hint;
  else if (content.cve_context)         snippet = JSON.stringify(content.cve_context).slice(0, 200);
  else if (content.discovered_facts)    snippet = (content.discovered_facts || []).map(f => `${f.key}: ${f.value}`).join(' • ');
  else                                  snippet = JSON.stringify(content).slice(0, 200);

  // Service / Phase label
  const svc   = (meta.applicable_constraints || {}).target_service || content.target_service || '';
  const phase = content.attack_phase || '';

  // CVE tags
  const cves = ((meta.applicable_constraints || {}).cve_ids || content.cve_ids || []);

  const confClass = conf >= 0.8 ? 'high' : conf >= 0.5 ? 'mid' : 'low';
  const outcome   = meta.session_outcome || '';

  return `
<div class="exp-card ${layer}" onclick="openDetail('${e.exp_id}')">
  <div class="exp-card-header">
    <span class="exp-id">${e.exp_id || ''}</span>
    <span class="exp-conf ${confClass}">${conf.toFixed(2)}</span>
  </div>
  ${svc ? `<div class="exp-service">${html(svc)}${phase ? ` <span style="color:var(--text-dim);font-weight:400;font-size:11px">· ${phase}</span>` : ''}</div>` : ''}
  <div class="exp-snippet">${html(snippet)}</div>
  <div class="exp-tags">
    ${cves.map(c => `<span class="exp-tag cve">${html(c)}</span>`).join('')}
    ${tags.filter(t => !cves.includes(t)).map(t => `<span class="exp-tag">${html(t)}</span>`).join('')}
  </div>
  <div class="exp-footer">
    <span style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${meta.extraction_source || ''}</span>
    ${outcome ? `<span class="outcome-badge ${outcome}" style="font-size:10px;padding:1px 6px">${outcome}</span>` : ''}
  </div>
</div>`;
}

function renderPagination(container, total, page, size, pageKey) {
  const totalPages = Math.ceil(total / size);
  if (totalPages <= 1) { container.innerHTML = ''; return; }

  let btns = `<button class="pg-btn" ${page === 1 ? 'disabled' : ''} onclick="loadExpPage('${pageKey}', ${page - 1})">‹ 上一页</button>`;

  // window of pages
  const start = Math.max(1, page - 2);
  const end   = Math.min(totalPages, page + 2);
  for (let p = start; p <= end; p++) {
    btns += `<button class="pg-btn ${p === page ? 'active' : ''}" onclick="loadExpPage('${pageKey}', ${p})">${p}</button>`;
  }

  btns += `<button class="pg-btn" ${page === totalPages ? 'disabled' : ''} onclick="loadExpPage('${pageKey}', ${page + 1})">下一页 ›</button>`;
  btns += `<span class="pg-info">${total} 条 / 第 ${page} / ${totalPages} 页</span>`;
  container.innerHTML = btns;
}

/* ── Search ───────────────────────────────────────────────── */
function onSearch(val) {
  searchQuery = val.trim().toLowerCase();
  const pageKey = Object.keys(PAGE_LAYER).find(k => currentPage === k);
  if (pageKey) {
    pageState[pageKey] = 1;
    loadExpPage(pageKey, 1);
  }
}

/* ══════════════════════════════════════════════════════════
   SESSIONS PAGE
═══════════════════════════════════════════════════════════ */
async function loadSessions() {
  const data = await api('/api/sessions');
  if (!data.success) return;
  const tbody = document.getElementById('sessionsBody');
  if (!data.sessions.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:40px">暂无会话数据</td></tr>';
    return;
  }
  tbody.innerHTML = data.sessions.map(s => {
    const lc = s.layer_counts || {};
    const pills = [
      lc['FACTUAL']        ? `<span class="layer-pill F">F×${lc['FACTUAL']}</span>` : '',
      lc['PROCEDURAL_POS'] ? `<span class="layer-pill P">P+×${lc['PROCEDURAL_POS']}</span>` : '',
      lc['PROCEDURAL_NEG'] ? `<span class="layer-pill N">N×${lc['PROCEDURAL_NEG']}</span>` : '',
      lc['METACOGNITIVE']  ? `<span class="layer-pill M">M×${lc['METACOGNITIVE']}</span>` : '',
      lc['CONCEPTUAL']     ? `<span class="layer-pill C">C×${lc['CONCEPTUAL']}</span>` : '',
    ].join('');
    const bar = parseFloat(s.bar_score || 0);
    const barColor = bar >= 0.8 ? 'var(--pos)' : bar >= 0.5 ? 'var(--meta)' : 'var(--neg)';
    const cves = (s.cve_ids || []).map(c => `<span class="exp-tag cve" style="font-size:10px">${html(c)}</span>`).join('');
    const date = s.created_at ? s.created_at.slice(0, 16).replace('T', ' ') : '—';
    return `<tr>
      <td><span style="font-family:var(--mono);font-size:12px;color:var(--text-muted)">${s.session_id_short}…</span></td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${html(s.target_service)}">${html(s.target_service || '—')}</td>
      <td>${cves || '—'}</td>
      <td><span class="outcome-badge ${s.outcome}">${s.outcome}</span></td>
      <td><span class="bar-score" style="color:${barColor}">${bar.toFixed(2)}</span></td>
      <td style="font-family:var(--mono);text-align:center">${s.exp_count}</td>
      <td><div class="layer-pills">${pills}</div></td>
      <td style="color:var(--text-dim);font-size:12px">${date}</td>
    </tr>`;
  }).join('');
}

/* ══════════════════════════════════════════════════════════
   PIPELINE PAGE
═══════════════════════════════════════════════════════════ */
async function loadPipelineStatus() {
  const data = await api('/api/pipeline/full/status');
  if (!data.success) return;

  const dot   = document.getElementById('pipelineDot');
  const label = document.getElementById('pipelineLabel');
  const btn   = document.getElementById('btnRunPipeline');

  // Topbar
  dot.className     = 'status-dot ' + (data.running ? 'running' : 'idle');
  label.textContent = data.running
    ? (data.current_step ? data.current_step.slice(0, 16) + '…' : '反思中…')
    : (data.last_run ? `完成 ${data.last_run.slice(0,16)}` : 'Idle');

  // Pipeline page
  document.getElementById('plStatus').innerHTML =
    `<i class="fas fa-circle" style="color:${data.running ? 'var(--pos)' : 'var(--text-dim)'}"></i> ${data.running ? '运行中 — ' + (data.current_step||'') : '空闲'}`;
  document.getElementById('plLastRun').innerHTML =
    `<i class="fas fa-clock"></i> ${data.last_run ? data.last_run.slice(0,16).replace('T',' ') : '从未运行'}`;

  if (data.last_output) {
    document.getElementById('plOutput').textContent = data.last_output;
  }
  if (data.last_error) {
    document.getElementById('plErrBlock').style.display = '';
    document.getElementById('plError').textContent = data.last_error;
  } else {
    document.getElementById('plErrBlock').style.display = 'none';
  }

  btn.disabled = data.running;
}

let _pipelinePoller = null;

async function runPipeline() {
  const btn = document.getElementById('btnRunPipeline');
  btn.disabled = true;

  const resp = await fetch('/api/pipeline/full', { method: 'POST' }).then(r => r.json());
  if (!resp.success) { alert(resp.message); btn.disabled = false; return; }

  // update topbar immediately
  document.getElementById('pipelineDot').className = 'status-dot running';
  document.getElementById('pipelineLabel').textContent = '反思中…';

  // poll every 3s
  clearInterval(_pipelinePoller);
  _pipelinePoller = setInterval(async () => {
    const st = await api('/api/pipeline/full/status');
    if (!st.running) {
      clearInterval(_pipelinePoller);
      btn.disabled = false;
      // 刷新流水线页状态
      document.getElementById('pipelineDot').className = 'status-dot idle';
      document.getElementById('pipelineLabel').textContent = st.last_run ? `完成 ${st.last_run.slice(0,16)}` : 'Idle';
      if (currentPage === 'pipeline') loadPipelineStatus();
      if (currentPage === 'overview') loadOverview();
      if (currentPage === 'consolidated') loadConsolidated();
    } else {
      const step = st.current_step || '反思中';
      document.getElementById('pipelineLabel').textContent = step.slice(0, 16) + '…';
    }
  }, 3000);
}

/* ══════════════════════════════════════════════════════════
   CRAWLER MANAGER
═══════════════════════════════════════════════════════════ */
let _crawlerPoller = null;
let _crawlerSources = [];
let _selectedSources = new Set();   // 当前选中的实时爬虫数据源

let _syncRepos = [];
let _selectedRepos = new Set();     // 当前选中的外部知识库

async function loadCrawler() {
  await Promise.all([
    loadWechatSeeds(), loadWechatCrawlStatus(),
    loadCrawlerSources(), loadCrawlerStatus(),
    loadSyncRepos(), loadSyncStatus(), loadRawData(),
    loadRssStatus()
  ]);
}

/* ══════════════════════════════════════════════════════════
   WECHAT ACCOUNT MANAGER
═══════════════════════════════════════════════════════════ */
let _wechatCategories = {};        // { cat: { label, accounts:[...] } }
let _wechatSelectedAccounts = new Set();
let _wechatCrawlPoller = null;

const WECHAT_PRIORITY_CLASS = { high: 'p-high', normal: 'p-normal', low: 'p-low' };

async function loadWechatSeeds() {
  const data = await api('/api/wechat/seeds');
  if (!data.success) {
    document.getElementById('wechatSeedGrid').innerHTML =
      '<div style="color:var(--text-dim);padding:10px;font-size:12px"><i class="fas fa-circle-exclamation"></i> 无法加载种子账号</div>';
    return;
  }
  _wechatCategories = data.categories || {};

  // 初始全选
  if (_wechatSelectedAccounts.size === 0) {
    Object.values(_wechatCategories).forEach(cat =>
      (cat.accounts || []).forEach(a => _wechatSelectedAccounts.add(a.name))
    );
  }
  renderWechatCards();
}

function renderWechatCards() {
  const grid = document.getElementById('wechatSeedGrid');
  const cats = _wechatCategories;
  const catKeys = Object.keys(cats);

  if (!catKeys.length) {
    grid.innerHTML = '<div style="color:var(--text-dim);padding:10px;font-size:12px">无种子账号</div>';
    return;
  }

  let html = '';
  for (const catKey of catKeys) {
    const cat = cats[catKey];
    const accounts = cat.accounts || [];
    if (!accounts.length) continue;

    html += `<div class="wechat-cat-header">${cat.label || catKey}</div>`;

    for (const acc of accounts) {
      const active   = _wechatSelectedAccounts.has(acc.name);
      const priCls   = WECHAT_PRIORITY_CLASS[acc.priority] || 'p-normal';
      const artLabel = acc.article_count > 0
        ? `<span class="acc-art-count has-articles"><i class="fas fa-newspaper" style="font-size:9px"></i> ${acc.article_count}</span>`
        : `<span class="acc-art-count">0 篇</span>`;
      const previewBtn = acc.article_count > 0
        ? `<button class="acc-preview-btn" title="预览已采集文章"
                  onclick="openWechatArticlePreview(event,'${escHtml(acc.name)}',${acc.article_count})">
             <i class="fas fa-eye"></i>
           </button>`
        : '';
      const tagsHtml = (acc.tags || []).slice(0, 3)
        .map(t => `<span style="font-size:9px;color:var(--text-dim)">${escHtml(t)}</span>`)
        .join(' · ');

      html += `
      <div class="wechat-acc-card ${active ? 'acc-active' : ''}"
           onclick="toggleWechatAccount('${escHtml(acc.name)}')"
           title="${acc.notes ? escHtml(acc.notes) : escHtml(acc.name)}">
        <button class="acc-del-btn" title="从种子库移除"
                onclick="wechatRemoveAccount(event,'${escHtml(acc.name)}','${escHtml(catKey)}')">×</button>
        <div class="acc-card-top">
          <span class="acc-select-dot"></span>
          <span class="acc-priority-dot ${priCls}" title="优先级: ${acc.priority}"></span>
        </div>
        <div class="acc-name">${escHtml(acc.name)}</div>
        <div class="acc-cat-badge">${escHtml(cat.label || catKey)}</div>
        ${tagsHtml ? `<div style="font-size:9px;color:var(--text-dim);line-height:1.4;margin-top:1px">${tagsHtml}</div>` : ''}
        <div class="acc-footer">
          ${artLabel}
          ${previewBtn}
        </div>
      </div>`;
    }
  }

  grid.innerHTML = html;
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function toggleWechatAccount(name) {
  if (_wechatSelectedAccounts.has(name)) _wechatSelectedAccounts.delete(name);
  else _wechatSelectedAccounts.add(name);
  renderWechatCards();
}

function wechatSelectAll(flag) {
  Object.values(_wechatCategories).forEach(cat =>
    (cat.accounts || []).forEach(a => flag
      ? _wechatSelectedAccounts.add(a.name)
      : _wechatSelectedAccounts.delete(a.name))
  );
  renderWechatCards();
}

async function wechatCrawlRun() {
  const accounts = [..._wechatSelectedAccounts];
  if (!accounts.length) { alert('请至少选择一个公众号'); return; }

  const count = parseInt(document.getElementById('wechatCrawlCount').value) || 10;
  const btn   = document.getElementById('btnWechatCrawl');
  btn.disabled = true;

  const resp = await fetch('/api/wechat/crawl', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accounts, count }),
  }).then(r => r.json());

  if (!resp.success) { alert(resp.message); btn.disabled = false; return; }

  document.getElementById('wechatDot').className      = 'status-dot running';
  document.getElementById('wechatLabel').textContent  = `爬取中 — ${accounts.length} 个账号…`;
  document.getElementById('wechatLogBlock').style.display = '';
  document.getElementById('wechatOutput').textContent =
    `正在启动微信爬虫...\n账号: ${accounts.join(', ')}\n每号采集: ${count} 篇`;

  clearInterval(_wechatCrawlPoller);
  _wechatCrawlPoller = setInterval(async () => {
    const st = await api('/api/wechat/crawl/status');
    if (!st.running) {
      clearInterval(_wechatCrawlPoller);
      await loadWechatCrawlStatus();
      await loadWechatSeeds();   // 刷新文章计数
      await loadRawData();
    }
  }, 3000);
}

async function loadWechatCrawlStatus() {
  const data = await api('/api/wechat/crawl/status');
  if (!data.success) return;

  const dot   = document.getElementById('wechatDot');
  const label = document.getElementById('wechatLabel');
  const btn   = document.getElementById('btnWechatCrawl');

  dot.className   = `status-dot ${data.running ? 'running' : 'idle'}`;
  label.textContent = data.running
    ? `爬取中 — ${(data.last_accounts || []).join(', ') || '…'}…`
    : (data.last_run ? `完成 ${data.last_run.slice(0,16).replace('T',' ')}` : '空闲');
  btn.disabled = data.running;

  if (data.last_output || data.last_error) {
    document.getElementById('wechatLogBlock').style.display = '';
  }
  if (data.last_output) document.getElementById('wechatOutput').textContent = data.last_output;
  if (data.last_error) {
    document.getElementById('wechatErrBlock').style.display = '';
    document.getElementById('wechatError').textContent = data.last_error;
  } else {
    document.getElementById('wechatErrBlock').style.display = 'none';
  }
  if (data.last_run) {
    document.getElementById('wechatLastRun').textContent =
      `上次爬取: ${data.last_run.slice(0,16).replace('T',' ')}`;
  }
}

/* ── 文章预览侧面板 ── */
let _currentPreviewAccount = null;

async function openWechatArticlePreview(ev, accountName, count) {
  ev.stopPropagation();

  const panel = document.getElementById('wechatArticlePanel');
  const isSameAccount = _currentPreviewAccount === accountName;

  // 再次点击同账号 → 收起面板
  if (panel.classList.contains('open') && isSameAccount) {
    closeWechatPanel();
    return;
  }

  _currentPreviewAccount = accountName;

  // 填写头部并打开
  const initial = accountName.trim()[0] || '?';
  document.getElementById('wapAvatar').textContent        = initial;
  document.getElementById('wapAccountName').textContent   = accountName;
  document.getElementById('wapCountBar').textContent      = `已采集 ${count} 篇文章`;
  document.getElementById('wapList').innerHTML =
    '<div class="wap-loading"><i class="fas fa-spinner fa-spin"></i> 加载中…</div>';
  panel.classList.add('open');

  // 滚动到面板可见
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  const data     = await api(`/api/wechat/articles?account=${encodeURIComponent(accountName)}`);
  const articles = (data.groups || {})[accountName] || [];

  if (!articles.length) {
    document.getElementById('wapList').innerHTML = `
      <div class="wap-empty">
        <i class="fab fa-weixin"></i>
        <span>该账号暂无已采集文章</span>
      </div>`;
    return;
  }

  document.getElementById('wapCountBar').textContent =
    `已采集 ${articles.length} 篇 · 最新: ${(articles[0].publish_time || '').slice(0,10) || '–'}`;

  const items = articles.slice(0, 30).map((a, i) => {
    const dateStr = (a.publish_time || '').slice(0, 10);
    const chars   = a.char_count > 0 ? `${(a.char_count / 1000).toFixed(1)}k 字` : '';
    const titleHtml = a.url
      ? `<a href="${escHtml(a.url)}" target="_blank" rel="noopener">${escHtml(a.title || '（无标题）')}</a>`
      : escHtml(a.title || '（无标题）');

    return `
    <div class="wap-article-item">
      <div class="wap-art-index">${i + 1}</div>
      <div class="wap-art-body">
        <div class="wap-art-title">${titleHtml}</div>
        <div class="wap-art-meta">
          ${dateStr ? `<span><i class="fas fa-clock"></i> ${dateStr}</span>` : ''}
          ${chars   ? `<span><i class="fas fa-book-open"></i> ${chars}</span>` : ''}
        </div>
        ${a.preview ? `<div class="wap-art-excerpt">${escHtml(a.preview)}</div>` : ''}
        ${a.url ? `<a class="wap-art-link" href="${escHtml(a.url)}" target="_blank" rel="noopener">
          <i class="fas fa-arrow-up-right-from-square" style="font-size:9px"></i> 阅读原文
        </a>` : ''}
      </div>
    </div>`;
  });

  // 每条之间加分隔线
  document.getElementById('wapList').innerHTML =
    items.join('<div class="wap-divider"></div>');
}

function closeWechatPanel() {
  _currentPreviewAccount = null;
  document.getElementById('wechatArticlePanel').classList.remove('open');
}

// 向后兼容旧名称
function closeWechatArticleModal() { closeWechatPanel(); }


/* ── 添加账号 Modal ── */
function showWechatAddForm() {
  document.getElementById('addAccName').value    = '';
  document.getElementById('addAccTags').value    = '';
  document.getElementById('addAccNotes').value   = '';
  document.getElementById('wechatAddOverlay').style.display = 'flex';
  setTimeout(() => document.getElementById('addAccName').focus(), 80);
}

function closeWechatAddModal() {
  document.getElementById('wechatAddOverlay').style.display = 'none';
}

async function submitWechatAddAccount() {
  const name     = document.getElementById('addAccName').value.trim();
  const category = document.getElementById('addAccCategory').value;
  const priority = document.getElementById('addAccPriority').value;
  const tagsRaw  = document.getElementById('addAccTags').value;
  const notes    = document.getElementById('addAccNotes').value.trim();
  const tags     = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);

  if (!name) { alert('请填写公众号名称'); return; }

  const resp = await fetch('/api/wechat/seeds/update', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'add', category, name, tags, priority, notes }),
  }).then(r => r.json());

  if (!resp.success) { alert(resp.message); return; }
  closeWechatAddModal();
  _wechatSelectedAccounts.add(name);
  await loadWechatSeeds();
}

async function wechatRemoveAccount(ev, name, category) {
  ev.stopPropagation();
  if (!confirm(`确定从种子库移除账号 "${name}"？`)) return;

  const resp = await fetch('/api/wechat/seeds/update', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'remove', category, name }),
  }).then(r => r.json());

  if (!resp.success) { alert(resp.message); return; }
  _wechatSelectedAccounts.delete(name);
  await loadWechatSeeds();
}

/* ── 实时爬虫数据源 ─────────────────────────────────────── */
async function loadCrawlerSources() {
  const data = await api('/api/crawler/sources');
  if (!data.success) return;
  _crawlerSources = data.sources;

  // 初始全选
  if (_selectedSources.size === 0) {
    data.sources.forEach(s => _selectedSources.add(s.id));
  }

  renderSourceCards();
}

function renderSourceCards() {
  const grid = document.getElementById('crawlerSources');
  grid.innerHTML = _crawlerSources.map(s => {
    const active  = _selectedSources.has(s.id);
    const needCfg = s.needs_config && !s.configured;
    return `
    <div class="crawler-src-card ${active ? 'card-active' : ''} ${needCfg ? 'card-warn' : (s.file_count > 0 ? 'has-data' : '')}"
         onclick="toggleSource('${s.id}')" title="${needCfg ? '⚠️ 需在 config.py 中填写 Cookie 才可使用' : '点击切换选中'}">
      <div class="src-card-top">
        <span class="src-select-dot ${active ? 'dot-on' : ''}"></span>
        ${needCfg ? '<span class="src-badge-warn">需配置</span>' : ''}
      </div>
      <div class="src-name">${s.label}</div>
      <div class="src-id">${s.id}</div>
      <div class="src-files">
        <i class="fas fa-file-code"></i>
        <strong>${s.file_count}</strong> 个文件
      </div>
      ${needCfg ? `<div class="src-cfg-tip">在 <code>wechat_article_crawler/config.py</code><br>中填写 COOKIE 等参数后可用</div>` : ''}
    </div>`;
  }).join('');
}

function toggleSource(id) {
  if (_selectedSources.has(id)) _selectedSources.delete(id);
  else _selectedSources.add(id);
  renderSourceCards();
}

function crawlerSelectAll(flag) {
  _crawlerSources.forEach(s => flag ? _selectedSources.add(s.id) : _selectedSources.delete(s.id));
  renderSourceCards();
}

async function loadCrawlerStatus() {
  const data = await api('/api/crawler/status');
  if (!data.success) return;

  const dot   = document.getElementById('crawlerDot');
  const label = document.getElementById('crawlerLabel');
  const btn   = document.getElementById('btnCrawlRun');

  dot.className   = `status-dot ${data.running ? 'running' : 'idle'}`;
  label.textContent = data.running
    ? `运行中 — ${data.last_query || '全量'}…`
    : (data.last_run ? `完成 ${data.last_run.slice(0,16).replace('T',' ')}` : '空闲');
  btn.disabled = data.running;

  if (data.last_output) document.getElementById('crawlerOutput').textContent = data.last_output;
  if (data.last_error) {
    document.getElementById('crawlerErrBlock').style.display = '';
    document.getElementById('crawlerError').textContent = data.last_error;
  } else {
    document.getElementById('crawlerErrBlock').style.display = 'none';
  }
  if (data.last_run) {
    document.getElementById('crawlerLastRun').textContent =
      `上次运行: ${data.last_run.slice(0,16).replace('T',' ')}`;
  }
}

async function crawlRun() {
  const query    = (document.getElementById('crawlQuery').value || '').trim();
  const maxPages = parseInt(document.getElementById('crawlMaxPages').value) || 5;
  const checked  = [..._selectedSources];

  if (!checked.length) { alert('请至少选择一个数据源'); return; }

  const btn = document.getElementById('btnCrawlRun');
  btn.disabled = true;

  const resp = await fetch('/api/crawler/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, sources: checked, max_pages: maxPages }),
  }).then(r => r.json());

  if (!resp.success) { alert(resp.message); btn.disabled = false; return; }

  document.getElementById('crawlerDot').className  = 'status-dot running';
  document.getElementById('crawlerLabel').textContent = `运行中 — ${query || '全量'}…`;
  document.getElementById('crawlerOutput').textContent =
    `正在启动爬虫...\n数据源: ${checked.join(', ')}\n关键词: ${query || '(无)'}`;

  clearInterval(_crawlerPoller);
  _crawlerPoller = setInterval(async () => {
    const st = await api('/api/crawler/status');
    if (!st.running) {
      clearInterval(_crawlerPoller);
      await loadCrawlerStatus();
      await loadCrawlerSources();
      await loadRawData();
    }
  }, 3000);
}

/* ── 外部知识库同步 ─────────────────────────────────────── */
async function loadSyncRepos() {
  const data = await api('/api/sync/repos');
  if (!data.success) {
    document.getElementById('syncRepoGrid').innerHTML =
      '<p style="color:var(--text-dim);padding:12px"><i class="fas fa-circle-exclamation"></i> 无法加载知识库列表</p>';
    return;
  }
  _syncRepos = data.repos;

  // 将服务端返回的所有仓库纳入选中集（幂等：已选中的保持不变，新增仓库自动选中）
  data.repos.forEach(r => _selectedRepos.add(r.id));
  renderRepoCards();
}

function renderRepoCards() {
  const grid = document.getElementById('syncRepoGrid');
  grid.innerHTML = _syncRepos.map(r => {
    const active = _selectedRepos.has(r.id);
    const synced = r.exists && r.file_count > 0;
    return `
    <div class="sync-repo-card ${active ? 'card-active' : ''} ${synced ? 'has-data' : ''}"
         onclick="toggleRepo('${r.id}')" title="${r.desc}">
      <div class="src-card-top">
        <span class="src-select-dot ${active ? 'dot-on' : ''}"></span>
        ${synced ? `<span class="src-badge-synced"><i class="fas fa-check"></i></span>` : ''}
      </div>
      <div class="src-name">${r.label}</div>
      <div class="src-id" style="color:var(--text-dim)">${r.desc}</div>
      <div class="src-files" style="margin-top:6px">
        ${synced
          ? `<i class="fas fa-hard-drive" style="color:var(--pos)"></i>
             <strong style="color:var(--pos)">${r.file_count}</strong> 个文件 · ${r.size_kb} KB
             <span class="repo-mtime">${r.mtime}</span>`
          : `<i class="fas fa-circle-xmark" style="color:var(--text-dim)"></i>
             <span style="color:var(--text-dim)">尚未同步</span>`
        }
      </div>
      ${synced ? `
      <button class="btn-icon-del repo-del-btn" onclick="syncDeleteRepo(event,'${r.id}')">
        <i class="fas fa-trash"></i>
      </button>` : ''}
    </div>`;
  }).join('');
}

function toggleRepo(id) {
  if (_selectedRepos.has(id)) _selectedRepos.delete(id);
  else _selectedRepos.add(id);
  renderRepoCards();
}

function syncSelectAll(flag) {
  _syncRepos.forEach(r => flag ? _selectedRepos.add(r.id) : _selectedRepos.delete(r.id));
  renderRepoCards();
}

let _syncPoller = null;

async function loadSyncStatus() {
  const data = await api('/api/sync/status');
  if (!data.success) return;

  const dot   = document.getElementById('syncDot');
  const label = document.getElementById('syncLabel');
  const btn   = document.getElementById('btnSyncRun');

  dot.className = `status-dot ${data.running ? 'running' : 'idle'}`;
  label.textContent = data.running
    ? `同步中 — ${(data.last_repos || []).join(', ') || '…'}…`
    : (data.last_run ? `完成 ${data.last_run.slice(0,16).replace('T',' ')}` : '空闲');
  btn.disabled = data.running;

  if (data.last_output) document.getElementById('syncOutput').textContent = data.last_output;
  if (data.last_error) {
    document.getElementById('syncErrBlock').style.display = '';
    document.getElementById('syncError').textContent = data.last_error;
  } else {
    document.getElementById('syncErrBlock').style.display = 'none';
  }
  if (data.last_run) {
    document.getElementById('syncLastRun').textContent =
      `上次同步: ${data.last_run.slice(0,16).replace('T',' ')}`;
  }
}

async function syncRun() {
  const repos = [..._selectedRepos];
  if (!repos.length) { alert('请至少选择一个知识库'); return; }

  const btn = document.getElementById('btnSyncRun');
  btn.disabled = true;

  const resp = await fetch('/api/sync/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repos }),
  }).then(r => r.json());

  if (!resp.success) { alert(resp.message); btn.disabled = false; return; }

  document.getElementById('syncDot').className = 'status-dot running';
  document.getElementById('syncLabel').textContent = `同步中 — ${repos.join(', ')}…`;
  document.getElementById('syncOutput').textContent =
    `正在启动同步...\n目标仓库: ${repos.join(', ')}`;

  clearInterval(_syncPoller);
  _syncPoller = setInterval(async () => {
    const st = await api('/api/sync/status');
    if (!st.running) {
      clearInterval(_syncPoller);
      await loadSyncStatus();
      await loadSyncRepos();
      await loadRawData();    // 同步完成同步刷新 RAG 源文件管理
    }
  }, 5000);
}

async function syncDeleteRepo(ev, repoId) {
  ev.stopPropagation();
  const repo = _syncRepos.find(r => r.id === repoId);
  if (!repo || !confirm(`确定删除 ${repo.label} 的本地同步数据？`)) return;
  const resp = await fetch('/api/sync/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_id: repoId }),
  }).then(r => r.json());
  alert(resp.message);
  await loadSyncRepos();
  await loadRawData();    // 删除同步库同步刷新 RAG 源文件管理
}

/* ══════════════════════════════════════════════════════════
   RSS FEED 自动订阅
═══════════════════════════════════════════════════════════ */
let _rssPoller = null;

async function loadRssStatus() {
  const data = await api('/api/rss/status');
  if (!data || !data.success) return;

  // 填充调度参数
  const intervalEl = document.getElementById('rssInterval');
  const maxItemsEl = document.getElementById('rssMaxItems');
  if (intervalEl) intervalEl.textContent = data.interval_hours;
  if (maxItemsEl) maxItemsEl.textContent  = data.max_items;

  // 渲染 feed 卡片
  const grid = document.getElementById('rssFeedCards');
  if (!grid) return;
  grid.innerHTML = (data.feeds || []).map(f => {
    const hasFetched = !!f.last_fetch;
    const timeStr = hasFetched
      ? f.last_fetch.slice(0, 16).replace('T', ' ')
      : '从未同步';
    return `
    <div class="rss-feed-card ${hasFetched ? 'rfc-ok' : 'rfc-never'}">
      <div class="rfc-header">
        <div class="rfc-icon"><i class="fas fa-rss"></i></div>
        <div class="rfc-name">${f.label}</div>
        ${hasFetched ? '<span class="rfc-ok-badge">已同步</span>' : ''}
      </div>
      <div class="rfc-stats">
        <div class="rfc-stat">
          <span class="rfc-stat-val">${f.seen_count}</span>
          <span class="rfc-stat-lbl">已追踪条目</span>
        </div>
        <div class="rfc-stat">
          <span class="rfc-stat-val">${f.file_count}</span>
          <span class="rfc-stat-lbl">本地文件</span>
        </div>
      </div>
      <div class="rfc-time"><i class="fas fa-clock"></i>${timeStr}</div>
    </div>`;
  }).join('');
}

async function rssSync() {
  const btn  = document.getElementById('btnRssSync');
  const dot  = document.getElementById('rssDot');
  const lbl  = document.getElementById('rssLabel');
  if (!btn) return;

  btn.disabled = true;
  const resp = await fetch('/api/rss/sync', { method: 'POST' }).then(r => r.json());
  if (!resp.success) {
    alert(resp.message);
    btn.disabled = false;
    return;
  }
  dot.className   = 'status-dot running';
  lbl.textContent = '同步中…';

  clearInterval(_rssPoller);
  _rssPoller = setInterval(async () => {
    const st = await api('/api/rss/sync/status');
    if (!st || !st.running) {
      clearInterval(_rssPoller);
      dot.className   = 'status-dot idle';
      lbl.textContent = st && st.last_error
        ? `错误: ${st.last_error}`
        : (st && st.last_run
          ? `完成 ${st.last_run.slice(0,16).replace('T',' ')}`
          : '完成');
      btn.disabled = false;
      await loadRssStatus();
      await loadRawData();
    }
  }, 3000);
}

/* ── RAW DATA ───────────────────────────────────────────── */
async function loadRawData() {
  const data = await api('/api/crawler/rawdata');
  if (!data.success) return;

  const crawlCount = Object.values(data.groups || {}).reduce((s, v) => s + v.length, 0)
                   + (data.other || []).length;
  const syncCount  = (data.sync_summaries || []).reduce((s, r) => s + r.file_count, 0);
  document.getElementById('rawdataTotalLabel').textContent =
    `共 ${data.total_files} 个原始数据文件（爬虫 ${crawlCount}、同步库 ${syncCount}）`;

  const container = document.getElementById('rawdataGroups');
  const groups    = data.groups || {};
  const srcs      = Object.entries(groups).filter(([, files]) => files.length > 0);
  const syncs     = data.sync_summaries || [];

  if (!srcs.length && !syncs.length && !(data.other || []).length) {
    container.innerHTML = '<div style="color:var(--text-dim);padding:12px 0;font-size:13px">暂无原始数据文件</div>';
    return;
  }

  // ── 爬虫数据源（逐文件列举）────────────────────────────────────
  const crawlHtml = srcs.map(([src, files]) => {
    const srcLabel = (_crawlerSources.find(s => s.id === src) || {}).label || src;
    const rows = files.map(f => {
      const safePath = f.path.replace(/\\/g, '/').replace(/'/g, "\\'");
      return `
      <tr>
        <td style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">${f.path}</td>
        <td style="color:var(--text-dim);white-space:nowrap">${f.mtime}</td>
        <td style="color:var(--text-dim);white-space:nowrap">${(f.size/1024).toFixed(1)} KB</td>
        <td><button class="btn-icon-del" onclick="crawlDeleteFile('${safePath}')">
          <i class="fas fa-trash"></i>
        </button></td>
      </tr>`;
    }).join('');
    return `
    <div class="rawdata-group">
      <div class="rawdata-group-header">
        <span class="rawdata-src-label">${srcLabel}</span>
        <span style="color:var(--text-dim);font-size:12px">${files.length} 个文件</span>
        <button class="btn-danger-sm" onclick="crawlDeleteSource('${src}')">
          <i class="fas fa-trash-can"></i> 清理
        </button>
      </div>
      <table class="rawdata-table"><tbody>${rows}</tbody></table>
    </div>`;
  }).join('');

  // ── 外部知识库同步摘要（卡片，不枚举单文件）──────────────────────
  const syncHtml = syncs.length ? `
    <div class="rawdata-group" style="margin-top:14px">
      <div class="rawdata-group-header">
        <span class="rawdata-src-label" style="color:var(--pos)">
          <i class="fas fa-database"></i> 外部知识库同步数据
        </span>
        <span style="color:var(--text-dim);font-size:12px">${syncs.length} 个库 · ${syncCount} 个文件</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px;padding:8px 0">
        ${syncs.map(r => `
          <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 12px">
            <div style="font-weight:600;font-size:13px;margin-bottom:3px">${r.label}</div>
            <div style="font-size:11px;color:var(--text-dim);margin-bottom:6px">${r.desc}</div>
            <div style="font-size:12px;color:var(--text-muted)">
              <i class="fas fa-hard-drive" style="color:var(--pos)"></i>
              ${r.file_count} 个文件 · ${r.size_kb} KB
            </div>
            ${r.mtime ? `<div style="font-size:11px;color:var(--text-dim);margin-top:3px">${r.mtime}</div>` : ''}
          </div>`).join('')}
      </div>
    </div>` : '';

  container.innerHTML = crawlHtml + syncHtml;
}

async function crawlDeleteSource(src) {
  if (!confirm(`确定清理所有 ${src} 的原始数据文件？`)) return;
  const resp = await fetch('/api/crawler/rawdata/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source: src }),
  }).then(r => r.json());
  alert(resp.message || (resp.success ? '已清理' : '操作失败'));
  await loadCrawlerSources();
  await loadRawData();
}

async function crawlDeleteFile(path) {
  const resp = await fetch('/api/crawler/rawdata/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  }).then(r => r.json());
  if (resp.success) { await loadCrawlerSources(); await loadRawData(); }
  else alert(resp.message);
}

async function crawlDeleteAll() {
  if (!confirm('确定清空全部原始数据文件？此操作不可恢复！')) return;
  const resp = await fetch('/api/crawler/rawdata/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ all: true }),
  }).then(r => r.json());
  alert(resp.message || (resp.success ? '已清空' : '操作失败'));
  await loadCrawlerSources();
  await loadRawData();
}

/* ══════════════════════════════════════════════════════════
   DETAIL MODAL
═══════════════════════════════════════════════════════════ */
async function openDetail(expId) {
  const data = await api(`/api/experiences/${expId}`);
  if (!data.success) return;
  const e = data.experience;

  const layer   = e.knowledge_layer || '';
  const content = e.content || {};
  const meta    = e.metadata || {};
  const colour  = LAYER_COLOUR[layer] || '#94a3b8';

  document.getElementById('mLayer').textContent = layer;
  document.getElementById('mLayer').style.cssText =
    `background:${colour}20;color:${colour};`;
  document.getElementById('mId').textContent = e.exp_id || '';

  document.getElementById('mBody').innerHTML = buildModalBody(e, layer, content, meta);
  document.getElementById('modalOverlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('open');
}

function buildModalBody(e, layer, content, meta) {
  const sections = [];

  // ── Metadata summary ──────────────────────────────────────
  const ac = meta.applicable_constraints || {};
  const date = (meta.created_at || '').slice(0, 16).replace('T', ' ');
  sections.push(`
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-circle-info"></i> 元数据</div>
  <dl class="modal-kv">
    <dt>Session</dt><dd style="font-family:var(--mono);font-size:12px">${html(meta.source_session_id || '—')}</dd>
    <dt>结果</dt><dd><span class="outcome-badge ${meta.session_outcome}">${meta.session_outcome || '—'}</span></dd>
    <dt>BAR Score</dt><dd style="font-family:var(--mono)">${meta.session_bar_score ?? '—'}</dd>
    <dt>置信度</dt><dd style="font-family:var(--mono)">${e.confidence ?? '—'}</dd>
    <dt>提取方式</dt><dd>${meta.extraction_source || '—'}</dd>
    <dt>目标服务</dt><dd>${html(ac.target_service || content.target_service || '—')}</dd>
    ${ac.cve_ids?.length ? `<dt>CVE</dt><dd>${ac.cve_ids.map(c=>`<span class="exp-tag cve">${html(c)}</span>`).join(' ')}</dd>` : ''}
    ${ac.target_version ? `<dt>版本</dt><dd style="font-family:var(--mono)">${html(ac.target_version)}</dd>` : ''}
    <dt>创建时间</dt><dd style="color:var(--text-dim)">${date}</dd>
  </dl>
</div>`);

  // ── Layer-specific content ─────────────────────────────────
  if (layer === 'FACTUAL') {
    sections.push(buildFactualSection(content));
  } else if (layer === 'PROCEDURAL_NEG') {
    sections.push(buildNegSection(content));
  } else if (layer === 'PROCEDURAL_POS') {
    sections.push(buildPosSection(content));
  } else if (layer === 'METACOGNITIVE') {
    sections.push(buildMetaSection(content));
  } else if (layer === 'CONCEPTUAL') {
    sections.push(buildConceptSection(content));
  }

  // ── Tags ──────────────────────────────────────────────────
  const tags = meta.tags || [];
  if (tags.length) {
    sections.push(`
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-tags"></i> 标签</div>
  <div class="tag-row">${tags.map(t => `<span class="exp-tag">${html(t)}</span>`).join('')}</div>
</div>`);
  }

  return sections.join('');
}

function buildFactualSection(c) {
  const facts = (c.discovered_facts || []).map(f =>
    `<tr><td style="font-family:var(--mono);color:var(--factual);font-size:12px">${html(f.key)}</td>
         <td style="font-family:var(--mono);font-size:12px">${html(f.value||'')}</td>
         <td style="color:var(--text-dim);font-size:11px">${html(f.service||'')} ${f.version ? `<br><small>${html(f.version)}</small>` : ''}</td></tr>`
  ).join('');

  const cveCtx = c.cve_context;

  return `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-magnifying-glass"></i> 发现的事实</div>
  ${facts ? `<table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="color:var(--text-dim);font-size:11px;text-transform:uppercase;border-bottom:1px solid var(--border)">
        <th style="padding:6px 10px 6px 0">Key</th><th style="padding:6px 10px">Value</th><th style="padding:6px 0">Service</th>
      </tr></thead><tbody>${facts}</tbody></table>` : ''}
  ${cveCtx ? `<div style="margin-top:12px">
    <div class="modal-section-title" style="margin-bottom:6px"><i class="fas fa-bug"></i> CVE Context</div>
    <div class="code-block">${html(JSON.stringify(cveCtx, null, 2))}</div></div>` : ''}
</div>
${c.raw_evidence ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-terminal"></i> 原始证据</div>
  <div class="code-block">${html(c.raw_evidence)}</div>
</div>` : ''}`;
}

function buildNegSection(c) {
  const dr = c.decision_rule || {};
  const thenSteps = Array.isArray(dr.THEN) ? dr.THEN : (dr.THEN ? [dr.THEN] : []);
  const nextActions = Array.isArray(dr.next_actions) ? dr.next_actions : [];
  const fpd = c.failure_pattern_detail || {};

  return `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-circle-xmark" style="color:var(--neg)"></i> 失败分析</div>
  <dl class="modal-kv">
    <dt>失败维度</dt><dd><span style="font-weight:700;color:var(--neg)">${html(c.failure_dimension || '—')}</span></dd>
    <dt>子维度</dt><dd>${html(c.failure_sub_dimension || '—')}</dd>
    <dt>工具</dt><dd style="font-family:var(--mono)">${html(c.tool_name || '—')}</dd>
    <dt>攻击阶段</dt><dd>${html(c.attack_phase || '—')}</dd>
    ${fpd.certainty ? `<dt>确定性</dt><dd>${html(fpd.certainty)}</dd>` : ''}
  </dl>
</div>
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-terminal"></i> 失败命令</div>
  <div class="code-block">${html(c.failed_command || '（无）')}</div>
</div>
<div class="neg-detail-row">
  ${c.evidence ? `<div>
    <div class="modal-section-title"><i class="fas fa-file-lines"></i> 证据</div>
    <div class="alert-block">${html(c.evidence)}</div></div>` : ''}
  ${c.remediation_hint ? `<div>
    <div class="modal-section-title"><i class="fas fa-lightbulb"></i> 修复建议</div>
    <div class="success-block">${html(c.remediation_hint)}</div></div>` : ''}
</div>
${fpd.trigger_condition ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-triangle-exclamation"></i> 失败模式详情</div>
  <dl class="modal-kv">
    <dt>触发条件</dt><dd>${html(fpd.trigger_condition)}</dd>
    ${fpd.interpretation ? `<dt>解读</dt><dd>${html(fpd.interpretation)}</dd>` : ''}
  </dl>
</div>` : ''}
${(dr.IF || thenSteps.length || dr.NOT) ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-code-branch"></i> 决策规则</div>
  <div class="rule-block">
    <div class="rule-part if-part">
      <div class="rule-part-label">IF 触发条件</div>
      ${html(dr.IF || '—')}
    </div>
    <div class="rule-part then-part">
      <div class="rule-part-label">THEN 建议动作</div>
      ${thenSteps.length ? `<ul style="margin:0;padding-left:14px">${thenSteps.map(s => `<li style="margin:3px 0">${html(s)}</li>`).join('')}</ul>` : '—'}
    </div>
    <div class="rule-part not-part">
      <div class="rule-part-label">NOT 禁止行为</div>
      ${html(dr.NOT || '—')}
    </div>
  </div>
  ${nextActions.length ? `<div style="margin-top:14px">
    <div class="modal-section-title" style="margin-bottom:8px"><i class="fas fa-list-ol"></i> 具体执行步骤</div>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="color:var(--text-dim);font-size:10px;text-transform:uppercase;border-bottom:1px solid var(--border)">
        <th style="padding:5px 8px 5px 0;text-align:left">步骤</th>
        <th style="padding:5px 8px;text-align:left">命令</th>
        <th style="padding:5px 0;text-align:left">期望信号</th>
      </tr></thead><tbody>
      ${nextActions.map(a => `<tr style="border-bottom:1px solid rgba(255,255,255,.04)">
        <td style="padding:5px 8px 5px 0;color:var(--text-dim);white-space:nowrap">Step ${a.step}</td>
        <td style="padding:5px 8px;font-family:var(--mono);color:#a8c7fa">${html(a.command || '')}</td>
        <td style="padding:5px 0;color:var(--text-muted);font-size:11px">${html(a.expected_signal || '')}</td>
      </tr>`).join('')}
      </tbody></table></div>` : ''}
</div>` : ''}
${c.avoid_pattern ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-ban"></i> 规避模式</div>
  <div class="alert-block">${html(c.avoid_pattern)}</div>
</div>` : ''}
${c.frc_reasoning ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-microscope"></i> 根因推理详情</div>
  <div class="info-block" style="font-size:12px;line-height:1.7">${html(c.frc_reasoning)}</div>
</div>` : ''}`;
}

function buildPosSection(c) {
  const preconditions = Array.isArray(c.preconditions) ? c.preconditions : [];
  const indicators    = Array.isArray(c.success_indicators) ? c.success_indicators : [];
  const nextActions   = Array.isArray(c.next_actions) ? c.next_actions : [];
  const cves          = Array.isArray(c.cve_ids) ? c.cve_ids : [];

  return `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-circle-check" style="color:var(--pos)"></i> 成功路径</div>
  <dl class="modal-kv">
    <dt>工具</dt><dd style="font-family:var(--mono)">${html(c.tool_name || '—')}</dd>
    <dt>攻击阶段</dt><dd>${html(c.attack_phase || '—')}</dd>
    ${c.target_service ? `<dt>目标服务</dt><dd>${html(c.target_service)}</dd>` : ''}
    ${cves.length ? `<dt>CVE</dt><dd>${cves.map(v => `<span class="exp-tag cve">${html(v)}</span>`).join(' ')}</dd>` : ''}
  </dl>
</div>
${c.command_template ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-terminal"></i> 参数化命令模板</div>
  <div class="code-block">${html(c.command_template)}</div>
</div>` : ''}
${c.original_command ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-terminal" style="color:var(--text-dim)"></i> 原始命令</div>
  <div class="code-block" style="border-color:var(--bg4);opacity:0.8">${html(c.original_command)}</div>
</div>` : ''}
${c.successful_command ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-terminal"></i> 成功命令</div>
  <div class="code-block">${html(c.successful_command)}</div>
</div>` : ''}
${c.evidence ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-check-circle"></i> 成功证据</div>
  <div class="success-block">${html(c.evidence)}</div>
</div>` : ''}
${preconditions.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-list-check"></i> 前置条件</div>
  <ul style="list-style:none;padding:0;margin:0">
    ${preconditions.map(p => `<li style="padding:4px 0;color:var(--text-muted);border-bottom:1px solid var(--bg3)">• ${html(p)}</li>`).join('')}
  </ul>
</div>` : ''}
${indicators.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-flag" style="color:var(--pos)"></i> 成功指标</div>
  <ul style="list-style:none;padding:0;margin:0">
    ${indicators.map(s => `<li style="padding:4px 0;color:var(--pos)">✓ ${html(s)}</li>`).join('')}
  </ul>
</div>` : ''}
${nextActions.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-forward"></i> 后续动作建议</div>
  <ul style="list-style:none;padding:0;color:var(--text-muted)">
    ${nextActions.map(a => `<li style="margin:4px 0">${html(typeof a === 'string' ? a : JSON.stringify(a))}</li>`).join('')}
  </ul>
</div>` : ''}`;
}

function buildMetaSection(c) {
  const mistakes = Array.isArray(c.decision_mistakes) ? c.decision_mistakes : [];
  const lessons  = Array.isArray(c.key_lessons) ? c.key_lessons : [];
  const missed   = Array.isArray(c.missed_opportunities) ? c.missed_opportunities : [];
  const optPath  = Array.isArray(c.optimal_decision_path) ? c.optimal_decision_path : [];
  const phaseDist = c.phase_distribution || {};
  const stuckCnt  = c.stuck_counts || {};

  return `
${c.failure_pattern ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-triangle-exclamation" style="color:var(--neg)"></i> 失败模式</div>
  <div class="alert-block">${html(c.failure_pattern)}</div>
</div>` : ''}
${lessons.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-graduation-cap" style="color:var(--meta)"></i> 关键教训 (Key Lessons)</div>
  <ul class="meta-lessons-list">
    ${lessons.map(l => `<li class="meta-lesson-item"><span class="meta-lesson-rule">${html(l)}</span></li>`).join('')}
  </ul>
</div>` : ''}
${mistakes.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-brain" style="color:var(--meta)"></i> 决策失误分析</div>
  ${mistakes.map((m, i) => `
  <div class="meta-mistake-block">
    <div class="meta-mistake-num">#${i + 1}</div>
    <div class="meta-mistake-body">
      <div class="meta-mistake-text">${html(m.mistake || '')}</div>
      ${m.consequence ? `<div class="meta-mistake-consequence"><i class="fas fa-arrow-right" style="color:var(--neg);font-size:10px"></i> ${html(m.consequence)}</div>` : ''}
      ${m.rule ? `<div class="meta-mistake-rule"><code>${html(m.rule)}</code></div>` : ''}
    </div>
  </div>`).join('')}
</div>` : ''}
${optPath.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-route" style="color:var(--pos)"></i> 最优决策路径</div>
  <ol class="meta-path-list">
    ${optPath.map(s => `<li>${html(s)}</li>`).join('')}
  </ol>
</div>` : ''}
${missed.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-circle-dot" style="color:var(--factual)"></i> 错失机会</div>
  <ul class="meta-path-list">
    ${missed.map(s => `<li>${html(s)}</li>`).join('')}
  </ul>
</div>` : ''}
${Object.keys(phaseDist).length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-chart-bar"></i> 阶段分布</div>
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px">
    ${Object.entries(phaseDist).sort((a,b) => b[1]-a[1]).map(([phase, cnt]) => {
      const isStuck = stuckCnt[phase] && stuckCnt[phase] > 2;
      return `<div style="background:${isStuck?'rgba(248,113,113,.12)':'rgba(255,255,255,.05)'};border:1px solid ${isStuck?'rgba(248,113,113,.3)':'var(--border)'};border-radius:6px;padding:6px 12px;font-size:12px">
        <div style="color:var(--text-dim);font-size:10px;font-weight:700;text-transform:uppercase">${html(phase)}</div>
        <div style="font-family:var(--mono);font-size:16px;font-weight:700;color:${isStuck?'var(--neg)':'var(--text)'}">${cnt}</div>
        ${isStuck?'<div style="color:var(--neg);font-size:10px">🔴 卡住</div>':''}
      </div>`;
    }).join('')}
  </div>
</div>` : ''}
${c.rag_effectiveness ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-database"></i> RAG 效用评估</div>
  <div class="info-block" style="font-size:12px;line-height:1.7">${html(c.rag_effectiveness)}</div>
</div>` : ''}`;
}

function buildConceptSection(c) {
  const ac = c.applicable_conditions || {};
  const pos = Array.isArray(ac.positive) ? ac.positive : [];
  const neg = Array.isArray(ac.negative) ? ac.negative : [];
  const triggers = Array.isArray(ac.retrieval_triggers) ? ac.retrieval_triggers : [];
  const evidence = Array.isArray(c.supporting_evidence) ? c.supporting_evidence : [];

  return `
${c.core_insight ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-lightbulb" style="color:var(--concept)"></i> 核心洞察</div>
  <div class="info-block" style="line-height:1.8">${html(c.core_insight)}</div>
</div>` : ''}
${(pos.length || neg.length) ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-filter"></i> 适用条件</div>
  ${pos.length ? `<div style="margin-bottom:8px">
    <div style="font-size:10px;font-weight:700;color:var(--pos);text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px">✅ 正向条件</div>
    <ul style="list-style:none;padding:0;margin:0">
      ${pos.map(s => `<li style="padding:3px 0 3px 14px;border-left:2px solid var(--pos);margin-bottom:4px;font-size:13px">${html(s)}</li>`).join('')}
    </ul></div>` : ''}
  ${neg.length ? `<div>
    <div style="font-size:10px;font-weight:700;color:var(--neg);text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px">❌ 反向条件（排除）</div>
    <ul style="list-style:none;padding:0;margin:0">
      ${neg.map(s => `<li style="padding:3px 0 3px 14px;border-left:2px solid var(--neg);margin-bottom:4px;font-size:13px">${html(s)}</li>`).join('')}
    </ul></div>` : ''}
</div>` : ''}
${triggers.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-magnifying-glass"></i> 检索触发关键词</div>
  <div style="display:flex;flex-wrap:wrap;gap:6px">
    ${triggers.map(t => `<span class="exp-tag" style="background:rgba(192,132,252,.12);border-color:rgba(192,132,252,.35);color:#e9d5ff;font-size:12px">${html(t)}</span>`).join('')}
  </div>
</div>` : ''}
${evidence.length ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-file-lines"></i> 支撑证据</div>
  <ul style="list-style:none;padding:0;margin:0">
    ${evidence.map(e => `<li style="padding:4px 0 4px 14px;border-left:2px solid var(--factual);margin-bottom:5px;font-size:12px;color:var(--text-muted)">${html(e)}</li>`).join('')}
  </ul>
</div>` : ''}
${c.confidence_basis ? `
<div class="modal-section">
  <div class="modal-section-title"><i class="fas fa-circle-info"></i> 置信度说明</div>
  <div style="font-size:12px;color:var(--text-dim);padding:8px 12px;background:var(--bg3);border-radius:6px">${html(c.confidence_basis)}</div>
</div>` : ''}`;
}

/* ── HTML escape helper ──────────────────────────────────── */
function html(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
const esc = html; // alias

/* ═══════════════════════════════════════════════════════════
   CONSOLIDATED PAGE (Layer 3)
═══════════════════════════════════════════════════════════ */

let _consData = null;
let _consFilterLayer = '';
let _consFilterMaturity = '';

async function loadConsolidated () {
  const grid = document.getElementById('consGrid');
  grid.innerHTML = '<div class="cons-loading"><i class="fas fa-spinner fa-spin"></i> 加载融合经验库...</div>';

  const d = await api('/api/consolidated');
  if (!d.success) {
    grid.innerHTML = '<div class="cons-empty">加载失败，请检查后端服务</div>';
    return;
  }
  _consData = d;

  // Fill pipeline banner / stat cards
  const s = d.summary;
  setEl('fpl-raw',      (s.total_raw_exps   || '—') + ' 条');
  setEl('fpl-merged',   (s.total_consolidated||'—') + ' 条');
  setEl('fpl-avgp',     s.avg_p_fused != null ? s.avg_p_fused.toFixed(2) : '—');
  setEl('fpl-consolidated', (s.maturity_counts.consolidated||0) + ' consolidated');
  setEl('css-ratio',    s.compression_ratio != null ? s.compression_ratio.toFixed(1)+'×' : '—');
  setEl('css-consolidated', (s.maturity_counts.consolidated||0) + ' 条');
  setEl('css-validated',    (s.maturity_counts.validated   ||0) + ' 条');
  setEl('css-avgp',     s.avg_p_fused != null ? s.avg_p_fused.toFixed(3) : '—');

  // Badge count
  const nb = document.getElementById('nb-consolidated');
  if (nb) nb.textContent = s.total_consolidated || 0;

  // Attach filter listeners (once)
  if (!document.getElementById('consFilterLayer').dataset.bound) {
    document.getElementById('consFilterLayer').dataset.bound = '1';
    document.querySelectorAll('.cons-filter-btn').forEach(btn => {
      btn.addEventListener('click', function () {
        const grp = this.closest('.cons-filter-group');
        grp.querySelectorAll('.cons-filter-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        if (this.dataset.filter === 'layer')    _consFilterLayer    = this.dataset.val;
        if (this.dataset.filter === 'maturity') _consFilterMaturity = this.dataset.val;
        renderConsolidatedGrid();
      });
    });
  }

  renderConsolidatedGrid();

  // 融合页底部内嵌：知识健康 + 缺口分析
  loadKlmHealth();
  loadGapsInline();
}

function setEl(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}

function renderConsolidatedGrid () {
  const grid = document.getElementById('consGrid');
  if (!_consData) return;
  let items = _consData.items;
  if (_consFilterLayer)    items = items.filter(i => i.layer === _consFilterLayer);
  if (_consFilterMaturity) items = items.filter(i => i.maturity === _consFilterMaturity);
  if (!items.length) {
    grid.innerHTML = '<div class="cons-empty">没有匹配的经验记录</div>';
    return;
  }
  grid.innerHTML = items.map(renderConsCard).join('');
}

const LAYER_BADGE_CLASS = {
  PROCEDURAL_NEG: 'lbadge-neg',
  PROCEDURAL_POS: 'lbadge-pos',
  FACTUAL:        'lbadge-frule',
  METACOGNITIVE:  'lbadge-meta',
  CONCEPTUAL:     'lbadge-conc',
  RAG_EVALUATION: 'lbadge-rag',
};
const LAYER_SHORT = {
  PROCEDURAL_NEG: 'NEG',
  PROCEDURAL_POS: 'POS',
  FACTUAL:        'FACTUAL',
  METACOGNITIVE:  'META',
  CONCEPTUAL:     'CONCEPTUAL',
  RAG_EVALUATION: 'RAG_EVAL',
};

function renderConsCard (item) {
  const lbCls  = LAYER_BADGE_CLASS[item.layer] || 'lbadge-neg';
  const lShort = LAYER_SHORT[item.layer] || item.layer;
  const mCls   = 'mat-' + item.maturity;
  const mbCls  = 'mbadge-' + item.maturity;

  // p_fused gauge
  const pf = item.p_fused != null ? item.p_fused : 0;
  const pfCls = pf >= 0.7 ? 'pf-high' : pf >= 0.4 ? 'pf-medium' : 'pf-low';
  const pfPct = Math.round(pf * 100);

  // session tags
  const sessionHTML = (item.sessions || []).map(s =>
    `<span class="cons-session-tag">${esc(s)}</span>`
  ).join('');

  // layer-specific content
  const contentHTML = renderConsContent(item);

  return `
<div class="cons-card ${mCls}">
  <div class="cons-card-header">
    <div class="cons-card-left">
      <span class="cons-layer-badge ${lbCls}">${esc(lShort)}</span>
      <span class="cons-maturity-badge ${mbCls}">${esc(item.maturity)}</span>
    </div>
    <span style="font-size:11px;color:var(--text-muted);font-family:monospace">${esc(item.exp_id.slice(0,12))}…</span>
  </div>
  <div class="cons-merge-counter">
    <span class="cons-merge-src">${item.n_src}</span>
    <span class="cons-merge-arrow"><i class="fas fa-arrow-right-long"></i></span>
    <span class="cons-merge-dst">1</span>
    <span class="cons-merge-lbl">条原始经验融合</span>
    <div class="cons-pfused-bar-wrap">
      <span class="cons-pfused-label">p_fused</span>
      <span class="cons-pfused-val ${pfCls}">${pf.toFixed(3)}</span>
      <div class="cons-pfused-bar ${pfCls}"><div class="cons-pfused-fill" style="width:${pfPct}%"></div></div>
    </div>
  </div>
  <div class="cons-card-content">
    ${sessionHTML ? '<div class="cons-session-tags">' + sessionHTML + '</div>' : ''}
    ${contentHTML}
  </div>
  <div class="cons-exp-id">${esc(item.exp_id)}</div>
</div>`;
}

function renderConsContent (item) {
  const d = item.display || {};
  const layer = item.layer;

  if (layer === 'PROCEDURAL_NEG') {
    const ifTags  = (d.IF   || []).slice(0,4).map(t => `<span class="cons-tag ctag-if">${esc(t)}</span>`).join('');
    const thenTags= (d.THEN || []).slice(0,5).map(t => `<span class="cons-tag ctag-then">${esc(t)}</span>`).join('');
    const notTags = (d.NOT  || []).slice(0,4).map(t => `<span class="cons-tag ctag-not">${esc(t)}</span>`).join('');
    return `
      ${ifTags ? '<div class="cons-content-section"><div class="cons-content-label">IF 前提条件</div><div class="cons-tag-list">' + ifTags + '</div></div>' : ''}
      ${thenTags? '<div class="cons-content-section"><div class="cons-content-label">THEN 负面影响</div><div class="cons-tag-list">' + thenTags+ '</div></div>' : ''}
      ${notTags ? '<div class="cons-content-section"><div class="cons-content-label">NOT 缓解措施</div><div class="cons-tag-list">' + notTags + '</div></div>' : ''}`;
  }

  if (layer === 'PROCEDURAL_POS') {
    const pre = (d.preconditions    || []).slice(0,3).map(t => `<span class="cons-tag ctag-if">${esc(t)}</span>`).join('');
    const suc = (d.success_indicators||[]).slice(0,3).map(t => `<span class="cons-tag ctag-then">${esc(t)}</span>`).join('');
    return `
      ${pre ? '<div class="cons-content-section"><div class="cons-content-label">前提条件</div><div class="cons-tag-list">' + pre + '</div></div>' : ''}
      ${suc ? '<div class="cons-content-section"><div class="cons-content-label">成功指标</div><div class="cons-tag-list">' + suc + '</div></div>' : ''}`;
  }

  if (layer === 'FACTUAL') {
    const sourceHint = d.factual_source ? `<div class="cons-content-label">来源: ${esc(String(d.factual_source).toUpperCase())}</div>` : '';
    const rows = (d.facts || []).slice(0,6).map(f =>
      `<div class="cons-fact-row"><span class="cons-fact-key">${esc(f.key)}</span><span class="cons-fact-val">${esc(String(f.value||''))}</span><span class="cons-fact-cnt">×${f.count||1}</span></div>`
    ).join('');
    const cveTags = (d.cve_map || []).slice(0,6).map(c => {
      const cls = (c.status||'').toLowerCase().includes('confirmed') ? 'cve-confirmed' : '';
      return `<span class="cons-tag ctag-cve ${cls}" title="${esc(c.status)} conf=${c.conf}">${esc(c.cve)}</span>`;
    }).join('');
    const unexplored = (d.cve_unexplored || []).slice(0,4).map(c =>
      `<span class="cons-tag ctag-cve cve-unexplored">${esc(c)}</span>`
    ).join('');
    return `
      ${sourceHint ? '<div class="cons-content-section">' + sourceHint + '</div>' : ''}
      ${rows ? '<div class="cons-content-section"><div class="cons-content-label">关键事实</div>' + rows + '</div>' : ''}
      ${cveTags ? '<div class="cons-content-section"><div class="cons-content-label">CVE 利用情况</div><div class="cons-tag-list">' + cveTags + '</div></div>' : ''}
      ${unexplored ? '<div class="cons-content-section"><div class="cons-content-label">待探索 CVE</div><div class="cons-tag-list">' + unexplored + '</div></div>' : ''}`;
  }

  if (layer === 'METACOGNITIVE') {
    const rows = (d.lessons || []).slice(0,3).map(l =>
      `<div style="margin-bottom:6px"><div style="font-size:11px;color:#fbbf24;font-weight:600">${esc(l.fp)}</div><div style="font-size:12px;color:var(--text);margin-top:2px">${esc(l.insight)}</div></div>`
    ).join('');
    return rows ? `<div class="cons-content-section"><div class="cons-content-label">经验教训</div>${rows}</div>` : '';
  }

  if (layer === 'CONCEPTUAL') {
    const triggers = (d.triggers || []).slice(0,5).map(t => `<span class="cons-tag ctag-fact">${esc(t)}</span>`).join('');
    return `
      ${d.core_insight ? '<div class="cons-content-section"><div class="cons-content-label">核心洞察</div><div class="cons-content-value">' + esc(d.core_insight) + '</div></div>' : ''}
      ${triggers ? '<div class="cons-content-section"><div class="cons-content-label">触发条件</div><div class="cons-tag-list">' + triggers + '</div></div>' : ''}`;
  }

  if (layer === 'RAG_EVALUATION') {
    const pct = d.adoption_rate != null ? Math.round(d.adoption_rate * 100) : 0;
    const avg = d.avg_bar != null ? d.avg_bar.toFixed(3) : '—';
    const recs = (d.recommendations || []).slice(0,2).map(r => `<div style="font-size:11px;color:#fbbf24;margin-bottom:4px">⚠ ${esc(r)}</div>`).join('');
    return `
      <div class="cons-content-section">
        <div class="cons-content-label">RAG 采纳率</div>
        <div class="cons-rag-meter">
          <div class="cons-rag-bar"><div class="cons-rag-fill" style="width:${pct}%"></div></div>
          <span class="cons-rag-val">${pct}%</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px">avg BAR score: <b style="color:var(--text)">${avg}</b>${d.bar_std != null ? ' ±' + d.bar_std.toFixed(3) : ''}</div>
      </div>
      ${recs ? '<div class="cons-content-section"><div class="cons-content-label">改进建议</div>' + recs + '</div>' : ''}`;
  }

  return `<div class="cons-content-section"><div class="cons-content-value">${esc(JSON.stringify(d).slice(0,200))}</div></div>`;
}

/* ══════════════════════════════════════════════════════════
   CONFLICTS — KLM 冲突管理
═══════════════════════════════════════════════════════════ */

async function loadConflicts() {
  // 先加载状态卡片
  const status = await api('/api/klm/status');
  if (status.success) {
    document.getElementById('klm-total').textContent           = status.total ?? '—';
    document.getElementById('klm-active').textContent          = status.lifecycle?.active ?? 0;
    document.getElementById('klm-conflicted').textContent      = status.lifecycle?.conflicted ?? 0;
    document.getElementById('klm-consolidated').textContent    = status.maturity?.consolidated ?? 0;
    document.getElementById('klm-ragflow-synced').textContent  = status.ragflow_synced ?? 0;
    document.getElementById('klm-ragflow-pending').textContent = status.ragflow_pending ?? 0;
    // 更新侧边栏 badge
    const nb = document.getElementById('nb-conflicts');
    if (nb) nb.textContent = status.lifecycle?.conflicted ?? 0;
  }

  // 加载冲突列表
  const data = await api('/api/klm/conflicts');
  if (!data.success) return;

  const badge = document.getElementById('conflicts-count-badge');
  if (badge) badge.textContent = (data.conflicts || []).length;

  // 冲突条目表格
  const tb = document.getElementById('conflictsTbody');
  if ((data.conflicts || []).length === 0) {
    tb.innerHTML = `<tr><td colspan="8" style="text-align:center;color:#4ade80;padding:20px"><i class="fas fa-circle-check"></i> 暂无冲突条目</td></tr>`;
  } else {
    tb.innerHTML = (data.conflicts || []).map(c => `
      <tr>
        <td><code style="font-size:11px">${esc(c.exp_id)}</code></td>
        <td><span class="layer-badge">${esc(c.knowledge_layer)}</span></td>
        <td>${esc(c.maturity)}</td>
        <td>${esc(c.target_service || '—')}</td>
        <td>${(c.cve_ids || []).map(v => `<span class="cons-tag ctag-cve" style="font-size:10px">${esc(v)}</span>`).join('') || '—'}</td>
        <td style="max-width:200px;font-size:12px;color:#fca5a5">${esc(c.conflict_reason || '—')}</td>
        <td style="font-size:11px;color:var(--text-muted)">${esc(c.conflict_triggered_by || '—')}</td>
        <td style="font-size:11px;color:var(--text-muted);white-space:nowrap">${esc((c.conflict_updated_at || '').slice(0,16))}</td>
      </tr>`).join('');
  }

  // RAGFlow 已同步表格
  const rb = document.getElementById('ragflowSyncedTbody');
  if ((data.ragflow_synced || []).length === 0) {
    rb.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:16px">无已同步条目</td></tr>`;
  } else {
    rb.innerHTML = (data.ragflow_synced || []).map(r => `
      <tr>
        <td><code style="font-size:11px">${esc(r.exp_id)}</code></td>
        <td><span class="layer-badge">${esc(r.knowledge_layer)}</span></td>
        <td>${esc(r.target_service || '—')}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:#38bdf8">${esc(r.ragflow_doc_id)}</td>
      </tr>`).join('');
  }
}

/* ══════════════════════════════════════════════════════════
   GAPS — 经验缺口爬虫
═══════════════════════════════════════════════════════════ */

let _gapData = [];

async function loadGaps() {
  const tb = document.getElementById('gapsTbody');
  tb.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:20px"><i class="fas fa-spinner fa-spin"></i> 分析中...</td></tr>`;

  const data = await api('/api/klm/gaps');
  if (!data.success) {
    tb.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#f87171;padding:16px">加载失败</td></tr>`;
    return;
  }

  _gapData = data.gaps || [];
  if (_gapData.length === 0) {
    tb.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#4ade80;padding:20px"><i class="fas fa-circle-check"></i> 暂无明显缺口</td></tr>`;
    return;
  }

  tb.innerHTML = _gapData.map((g, i) => {
    const scoreColor = g.gap_score > 10 ? '#f87171' : g.gap_score > 5 ? '#fbbf24' : '#4ade80';
    const cveTags = (g.cve_list || []).slice(0, 4).map(c =>
      `<span class="cons-tag ctag-cve" style="font-size:10px">${esc(c)}</span>`).join('');
    const kwText = (g.suggested_keywords || []).join(' ');
    return `
      <tr>
        <td style="font-weight:600">${esc(g.target_service)}</td>
        <td>${cveTags || '—'}</td>
        <td style="text-align:center">${g.raw_count}</td>
        <td style="text-align:center">${g.consolidated_count}</td>
        <td style="text-align:center"><span style="color:${scoreColor};font-weight:700">${g.gap_score}</span></td>
        <td style="font-size:11px;color:var(--text-muted)">${esc(kwText)}</td>
        <td>
          <button class="btn-muted" style="font-size:11px;padding:3px 8px"
                  onclick="fillGapCrawl(${i})">
            <i class="fas fa-spider"></i> 填充关键词
          </button>
        </td>
      </tr>`;
  }).join('');
}

function fillGapCrawl(idx) {
  const g = _gapData[idx];
  if (!g) return;
  const kw = (g.suggested_keywords || []).join(' ');
  document.getElementById('gapCrawlKeywords').value = kw;
  document.getElementById('gapCrawlMsg').textContent = `已填入: ${kw}`;
  // 滚动到启动器
  document.getElementById('gapCrawlBtn').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

async function gapCrawlRun() {
  const keywords = (document.getElementById('gapCrawlKeywords')?.value || '').trim();
  const pages    = parseInt(document.getElementById('gapCrawlPages')?.value) || 3;
  const msg      = document.getElementById('gapCrawlMsg');
  const btn      = document.getElementById('gapCrawlBtn');

  if (!keywords) { msg.textContent = '请输入搜索关键词'; msg.style.color = '#f87171'; return; }

  btn.disabled = true;
  msg.textContent = '启动中...';
  msg.style.color = '#fbbf24';

  try {
    const resp = await fetch('/api/gap/crawl', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: keywords,
        max_pages: pages,
        sources: ['csdn', 'github', 'qianxin', 'xianzhi'],
      }),
    });
    const res = await resp.json();
    if (res.success) {
      msg.textContent = '爬取已启动，正在进行...';
      msg.style.color = '#4ade80';
      _pollGapCrawlStatus(btn, msg);
    } else {
      msg.textContent = res.error || '启动失败';
      msg.style.color = '#f87171';
      btn.disabled = false;
    }
  } catch (e) {
    msg.textContent = '网络错误: ' + e.message;
    msg.style.color = '#f87171';
    btn.disabled = false;
  }
}

async function _pollGapCrawlStatus(btn, msg) {
  for (let i = 0; i < 100; i++) {
    await new Promise(r => setTimeout(r, 3000));
    const s = await api('/api/gap/crawl/status');
    if (!s.success) continue;
    if (!s.running) {
      const ok = !s.last_error;
      msg.textContent = ok ? `爬取完成！(关键词: ${s.last_query || ''})` : `出错: ${s.last_error}`;
      msg.style.color = ok ? '#4ade80' : '#f87171';
      btn.disabled = false;
      break;
    } else {
      msg.textContent = `爬取中... ${i > 0 ? Math.round(i*3) + 's' : ''}`;
    }
  }
}

/* ══════════════════════════════════════════════════════════
   KLM HEALTH — 内嵌于融合经验库页
═══════════════════════════════════════════════════════════ */

async function loadKlmHealth() {
  const status = await api('/api/klm/status');
  if (!status.success) return;

  // 状态卡片
  setEl('klm-total',          status.total ?? '—');
  setEl('klm-active',         status.lifecycle?.active ?? 0);
  setEl('klm-conflicted',     status.lifecycle?.conflicted ?? 0);
  setEl('klm-cons-count',     status.maturity?.consolidated ?? 0);
  setEl('klm-ragflow-synced', status.ragflow_synced ?? 0);

  // 生命周期比例条
  const lc = status.lifecycle || {};
  const total = Object.values(lc).reduce((a, b) => a + b, 0) || 1;
  const COLORS = { active: '#4ade80', conflicted: '#f87171', deprecated: '#94a3b8', merged: '#a78bfa' };
  const barEl  = document.getElementById('klmLifecycleBar');
  const legEl  = document.getElementById('klmLifecycleLegend');
  if (barEl) {
    barEl.innerHTML = Object.entries(lc).map(([k, v]) => {
      const pct = (v / total * 100).toFixed(1);
      const col = COLORS[k] || '#64748b';
      return `<div style="width:${pct}%;background:${col};min-width:${v>0?'2px':'0'}" title="${k}: ${v}"></div>`;
    }).join('');
  }
  if (legEl) {
    legEl.innerHTML = Object.entries(lc).map(([k, v]) => {
      const col = COLORS[k] || '#64748b';
      return `<span style="color:${col}"><i class="fas fa-square" style="font-size:8px;margin-right:3px"></i>${k}: ${v}</span>`;
    }).join('');
  }

  // 冲突条目表
  const badge = document.getElementById('conflicts-count-badge');
  const tb    = document.getElementById('conflictsTbody');
  if (!tb) return;

  const data = await api('/api/klm/conflicts');
  if (!data.success) return;

  if (badge) badge.textContent = (data.conflicts || []).length;

  if ((data.conflicts || []).length === 0) {
    tb.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#4ade80;padding:16px">
      <i class="fas fa-circle-check"></i> 暂无冲突条目</td></tr>`;
  } else {
    tb.innerHTML = (data.conflicts || []).slice(0, 20).map(c => `
      <tr>
        <td><code style="font-size:10px">${esc(c.exp_id.slice(0,12))}…</code></td>
        <td><span class="layer-badge">${esc(c.knowledge_layer)}</span></td>
        <td>${esc(c.maturity)}</td>
        <td>${esc(c.target_service || '—')}</td>
        <td style="max-width:180px;font-size:11px;color:#fca5a5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${esc(c.conflict_reason || '')}">${esc(c.conflict_reason || '—')}</td>
        <td style="font-size:10px;color:var(--text-muted);white-space:nowrap">${esc((c.conflict_updated_at || '').slice(0,10))}</td>
      </tr>`).join('');
  }

  // 更新侧边栏 badge
  const nb = document.getElementById('nb-conflicts');
  if (nb) nb.textContent = status.lifecycle?.conflicted ?? 0;
}

/* ══════════════════════════════════════════════════════════
   GAPS INLINE — 水平评分条，内嵌于融合经验库页
═══════════════════════════════════════════════════════════ */

async function loadGapsInline() {
  const wrap = document.getElementById('gapsInlineWrap');
  if (!wrap) return;
  wrap.innerHTML = `<div style="color:var(--text-muted);font-size:13px;text-align:center;padding:14px">
    <i class="fas fa-spinner fa-spin"></i> 分析中...</div>`;

  const data = await api('/api/klm/gaps');
  if (!data.success) {
    wrap.innerHTML = `<div style="color:#f87171;font-size:13px;padding:10px">加载失败</div>`;
    return;
  }

  const gaps = data.gaps || [];
  if (gaps.length === 0) {
    wrap.innerHTML = `<div style="color:#4ade80;font-size:13px;text-align:center;padding:14px">
      <i class="fas fa-circle-check"></i> 暂无明显缺口</div>`;
    return;
  }

  const maxScore = Math.max(...gaps.map(g => g.gap_score), 1);
  wrap.innerHTML = gaps.slice(0, 10).map((g, i) => {
    const pct = Math.max(4, Math.round(g.gap_score / maxScore * 100));
    const col = g.gap_score > 10 ? '#f87171' : g.gap_score > 5 ? '#fbbf24' : '#4ade80';
    const kw  = (g.suggested_keywords || []).join(' ');
    const cves = (g.cve_list || []).slice(0, 3).map(c =>
      `<span class="cons-tag ctag-cve" style="font-size:9px;padding:1px 4px">${esc(c)}</span>`
    ).join('');
    return `
      <div style="margin-bottom:8px;cursor:pointer" onclick="fillGapCrawlInline(${i})" title="点击填入关键词">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
          <span style="font-size:12px;font-weight:600;min-width:140px;color:var(--text)">${esc(g.target_service)}</span>
          ${cves}
          <span style="margin-left:auto;font-size:11px;color:var(--text-muted)">${g.raw_count} raw / ${g.consolidated_count} 融合</span>
          <span style="font-size:12px;font-weight:700;color:${col};min-width:26px;text-align:right">${g.gap_score}</span>
        </div>
        <div style="height:7px;border-radius:4px;background:var(--bg-deeper);overflow:hidden">
          <div style="width:${pct}%;height:100%;background:${col};border-radius:4px;transition:width .4s"></div>
        </div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:2px">${esc(kw)}</div>
      </div>`;
  }).join('');

  // 存全量缺口数据供 fillGapCrawlInline 使用
  window._gapDataInline = gaps;
}

function fillGapCrawlInline(idx) {
  const g = (window._gapDataInline || [])[idx];
  if (!g) return;
  const kw = (g.suggested_keywords || []).join(' ');
  const kwEl = document.getElementById('gapCrawlKeywords');
  const msgEl = document.getElementById('gapCrawlMsg');
  if (kwEl) { kwEl.value = kw; kwEl.focus(); }
  if (msgEl) { msgEl.textContent = `已填入: ${kw}`; msgEl.style.color = '#fbbf24'; }
}

/* ══════════════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  navigate('overview');

  // ESC 关闭 modal 和侧面板
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closeModal();
      closeWechatPanel();
      closeWechatAddModal();
    }
  });

  // Auto-refresh pipeline/crawler/sync status every 5s
  setInterval(() => {
    if (currentPage === 'pipeline') loadPipelineStatus();
    if (currentPage === 'crawler') {
      loadCrawlerStatus();
      loadSyncStatus();
      loadWechatCrawlStatus();
    }
  }, 5000);
});
