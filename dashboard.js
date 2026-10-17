/**
 * CRAWLIZER — Cyberpunk Web Crawler Dashboard Controller
 * Modern Hacker UI with Collapsible Sidebar, Command Palette, Charts & Live Stream
 */

document.addEventListener('DOMContentLoaded', async () => {
  const storage = window.katanaStorage;
  const engine = window.katanaEngine;

  // DOM Elements - Metrics
  const metricTargets = document.getElementById('metric-targets');
  const metricPending = document.getElementById('metric-pending');
  const metricCrawled = document.getElementById('metric-crawled');
  const metricProgressPercent = document.getElementById('metric-progress-percent');
  const metricDiscovered = document.getElementById('metric-discovered');
  const metricNewSession = document.getElementById('metric-new-session');
  const metricQueue = document.getElementById('metric-queue');
  const metricActiveWorkers = document.getElementById('metric-active-workers');
  const metricRps = document.getElementById('metric-rps');
  const metricSubdomains = document.getElementById('metric-subdomains');
  const metricDupes = document.getElementById('metric-dupes');
  const metricErrors = document.getElementById('metric-errors');
  const metricDuration = document.getElementById('metric-duration');
  const metricDurationStatus = document.getElementById('metric-duration-status');
  const progressBarFill = document.getElementById('progress-bar-fill');

  // Header & Status
  const headerStatusDot = document.getElementById('header-status-dot');
  const headerStatusLabel = document.getElementById('header-status-label');
  const btnFocusTab = document.getElementById('btn-focus-tab');
  const btnStart = document.getElementById('btn-start');
  const btnPause = document.getElementById('btn-pause');
  const btnResume = document.getElementById('btn-resume');
  const btnStop = document.getElementById('btn-stop');
  const btnClearDb = document.getElementById('btn-clear-db');

  // Sidebar Elements
  const appSidebar = document.getElementById('app-sidebar');
  const btnSidebarToggle = document.getElementById('btn-sidebar-toggle');
  const topbarTypingTarget = document.getElementById('topbar-typing-target');

  // CAPTCHA Banner
  const captchaBanner = document.getElementById('captcha-banner');
  const captchaTypeTitle = document.getElementById('captcha-type-title');
  const captchaTargetUrl = document.getElementById('captcha-target-url');
  const btnCaptchaFocus = document.getElementById('btn-captcha-focus');
  const btnCaptchaSolved = document.getElementById('btn-captcha-solved');
  const btnCaptchaSkip = document.getElementById('btn-captcha-skip');

  // Export
  const btnExportMenu = document.getElementById('btn-export-menu');
  const exportMenu = document.getElementById('export-menu');
  const exportTxt = document.getElementById('export-txt');
  const exportJson = document.getElementById('export-json');
  const exportCsv = document.getElementById('export-csv');
  const copyClipboard = document.getElementById('copy-clipboard');

  // Navigation Items / Tabs
  const navItems = document.querySelectorAll('.nav-item, .nav-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const tabDiscoveredCount = document.getElementById('tab-discovered-count');

  // Tab 2: Upload & Config
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const targetTextarea = document.getElementById('target-textarea');
  const btnAddPasted = document.getElementById('btn-add-pasted');
  const btnLoadDemo = document.getElementById('btn-load-demo');
  const btnClearTargets = document.getElementById('btn-clear-targets');
  const loadedSeedsBadge = document.getElementById('loaded-seeds-badge');
  const targetsTbody = document.getElementById('targets-tbody');
  const targetsTableCount = document.getElementById('targets-table-count');

  // Config inputs
  const cfgMode = document.getElementById('cfg-mode');
  const cfgScope = document.getElementById('cfg-scope');
  const regexGroup = document.getElementById('regex-group');
  const cfgScopeRegex = document.getElementById('cfg-scope-regex');
  const concurrencyGroup = document.getElementById('concurrency-group');
  const cfgConcurrency = document.getElementById('cfg-concurrency');
  const cfgTabDelay = document.getElementById('cfg-tab-delay');
  const cfgDepth = document.getElementById('cfg-depth');
  const cfgTimeout = document.getElementById('cfg-timeout');
  const cfgSubdomainCrawl = document.getElementById('cfg-subdomain-crawl');
  const cfgOpenInTab = document.getElementById('cfg-open-in-tab');
  const cfgClickButtons = document.getElementById('cfg-click-buttons');
  const cfgCrawlJs = document.getElementById('cfg-crawl-js');
  const cfgRobotsSitemap = document.getElementById('cfg-robots-sitemap');
  const cfgIgnoreMedia = document.getElementById('cfg-ignore-media');
  const cfgUserAgent = document.getElementById('cfg-user-agent');

  // Tab 3: Results & Table
  const tableSearch = document.getElementById('table-search');
  const filterType = document.getElementById('filter-type');
  const filterScope = document.getElementById('filter-scope');
  const filterExt = document.getElementById('filter-ext');
  const filterCount = document.getElementById('filter-count');
  const resultsTbody = document.getElementById('results-tbody');
  const paginationInfo = document.getElementById('pagination-info');
  const btnPagePrev = document.getElementById('btn-page-prev');
  const btnPageNext = document.getElementById('btn-page-next');
  const currentPageDisplay = document.getElementById('current-page-display');
  const selectPageSize = document.getElementById('select-page-size');

  // Tab 5: Terminal
  const terminalBody = document.getElementById('terminal-body');
  const terminalAutoscroll = document.getElementById('terminal-autoscroll');
  const btnClearLogs = document.getElementById('btn-clear-logs');

  // Secrets & Findings Tab Elements
  const metricSecrets = document.getElementById('metric-secrets');
  const metricSecretsBreakdown = document.getElementById('metric-secrets-breakdown');
  const tabSecretsCount = document.getElementById('tab-secrets-count');
  const secretsSearch = document.getElementById('secrets-search');
  const secretsFilterSeverity = document.getElementById('secrets-filter-severity');
  const secretsFilterSource = document.getElementById('secrets-filter-source');
  const secretsCountLabel = document.getElementById('secrets-count-label');
  const secretsTbody = document.getElementById('secrets-tbody');
  const btnExportSecretsJson = document.getElementById('btn-export-secrets-json');
  const btnExportSecretsCsv = document.getElementById('btn-export-secrets-csv');
  const btnCopySecrets = document.getElementById('btn-copy-secrets');
  const btnClearSecrets = document.getElementById('btn-clear-secrets');

  // Command Palette & Matrix Elements
  const btnOpenCmdPalette = document.getElementById('btn-open-cmd-palette');
  const cmdPaletteBackdrop = document.getElementById('cmd-palette-backdrop');
  const cmdPaletteInput = document.getElementById('cmd-palette-input');
  const cmdResultsList = document.getElementById('cmd-results-list');
  const btnToggleMatrix = document.getElementById('btn-toggle-matrix');
  const matrixCanvas = document.getElementById('matrix-canvas');

  // Local Pagination State
  let currentPage = 1;
  let pageSize = 50;
  let cachedResults = [];
  let cachedSecrets = [];

  // ==========================================
  // Sidebar Collapse / Expand
  // ==========================================
  if (btnSidebarToggle && appSidebar) {
    btnSidebarToggle.addEventListener('click', () => {
      appSidebar.classList.toggle('collapsed');
      if (storage && storage.saveSetting) {
        storage.saveSetting('sidebar_collapsed', appSidebar.classList.contains('collapsed'));
      }
    });

    const sidebarBrand = document.querySelector('.sidebar-brand');
    if (sidebarBrand) {
      sidebarBrand.addEventListener('click', (e) => {
        if (appSidebar.classList.contains('collapsed')) {
          e.preventDefault();
          appSidebar.classList.remove('collapsed');
          if (storage && storage.saveSetting) {
            storage.saveSetting('sidebar_collapsed', false);
          }
        }
      });
    }

    if (storage && storage.getSetting) {
      storage.getSetting('sidebar_collapsed', false).then(isCollapsed => {
        if (isCollapsed) appSidebar.classList.add('collapsed');
      }).catch(() => {});
    }
  }

  // Ctrl+B shortcut to toggle sidebar
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
      e.preventDefault();
      if (appSidebar) {
        appSidebar.classList.toggle('collapsed');
        if (storage && storage.saveSetting) {
          storage.saveSetting('sidebar_collapsed', appSidebar.classList.contains('collapsed'));
        }
      }
    }
  });

  // ==========================================
  // Breadcrumb Typing Animation
  // ==========================================
  let typingTimeout = null;
  function typeBreadcrumbText(text) {
    if (!topbarTypingTarget) return;
    clearTimeout(typingTimeout);
    topbarTypingTarget.textContent = '';
    let i = 0;
    function step() {
      if (i < text.length) {
        topbarTypingTarget.textContent += text.charAt(i);
        i++;
        typingTimeout = setTimeout(step, 25);
      }
    }
    step();
  }

  // ==========================================
  // Matrix Rain Background Animation
  // ==========================================
  let matrixInterval = null;
  function initMatrixRain() {
    if (!matrixCanvas) return;
    const ctx = matrixCanvas.getContext('2d');
    let width = (matrixCanvas.width = window.innerWidth);
    let height = (matrixCanvas.height = window.innerHeight);

    window.addEventListener('resize', () => {
      width = matrixCanvas.width = window.innerWidth;
      height = matrixCanvas.height = window.innerHeight;
    });

    const chars = '0123456789ABCDEFアイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    const fontSize = 14;
    const columns = Math.floor(width / fontSize);
    const drops = Array(columns).fill(1);

    function draw() {
      ctx.fillStyle = 'rgba(10, 14, 20, 0.08)';
      ctx.fillRect(0, 0, width, height);

      ctx.fillStyle = '#00f0ff';
      ctx.font = `${fontSize}px monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = chars.charAt(Math.floor(Math.random() * chars.length));
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    }

    if (btnToggleMatrix) {
      btnToggleMatrix.addEventListener('click', () => {
        const isActive = matrixCanvas.classList.toggle('active');
        if (isActive) {
          btnToggleMatrix.style.borderColor = 'var(--neon-green)';
          btnToggleMatrix.style.color = 'var(--neon-green)';
          matrixInterval = setInterval(draw, 45);
        } else {
          btnToggleMatrix.style.borderColor = '';
          btnToggleMatrix.style.color = '';
          clearInterval(matrixInterval);
          ctx.clearRect(0, 0, width, height);
        }
      });
    }
  }
  initMatrixRain();

  // ==========================================
  // Real-time Canvas Charts (Throughput & Donut)
  // ==========================================
  const crawlRateCanvas = document.getElementById('crawl-rate-chart');
  const typesDonutCanvas = document.getElementById('types-donut-chart');
  let rpsHistory = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  let lastDonutCounts = { html: 1, js: 1, api: 1, secrets: 1 };

  function getThemeColors() {
    const cs = getComputedStyle(document.documentElement);
    const chart1 = cs.getPropertyValue('--chart-1').trim() || '#00f0ff';
    const chart2 = cs.getPropertyValue('--chart-2').trim() || '#39ff14';
    const chart3 = cs.getPropertyValue('--chart-3').trim() || '#38bdf8';
    const chart4 = cs.getPropertyValue('--chart-4').trim() || '#ff2bd6';
    const chartGrid = cs.getPropertyValue('--chart-grid').trim() || 'rgba(255, 255, 255, 0.05)';
    const textMain = cs.getPropertyValue('--text-main').trim() || '#f0f6fc';
    const themeType = cs.getPropertyValue('--theme-type').trim() || 'dark';
    const isLight = themeType === 'light';
    return { chart1, chart2, chart3, chart4, chartGrid, textMain, isLight };
  }

  function hexToRgba(hex, alpha = 1) {
    if (!hex) return `rgba(0, 240, 255, ${alpha})`;
    if (hex.startsWith('rgb')) return hex;
    let c = hex.replace('#', '');
    if (c.length === 3) c = c.split('').map(x => x + x).join('');
    const num = parseInt(c, 16);
    if (isNaN(num)) return `rgba(0, 240, 255, ${alpha})`;
    return `rgba(${(num >> 16) & 255}, ${(num >> 8) & 255}, ${num & 255}, ${alpha})`;
  }

  function drawRpsChart() {
    if (!crawlRateCanvas) return;
    const ctx = crawlRateCanvas.getContext('2d');
    const w = (crawlRateCanvas.width = crawlRateCanvas.clientWidth || crawlRateCanvas.width || 300);
    const h = (crawlRateCanvas.height = crawlRateCanvas.clientHeight || crawlRateCanvas.height || 120);
    if (w <= 10 || h <= 10) return;

    const colors = getThemeColors();
    ctx.clearRect(0, 0, w, h);

    // Draw dynamic theme gridlines
    ctx.strokeStyle = colors.chartGrid;
    ctx.lineWidth = 1;
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    const maxVal = Math.max(10, ...rpsHistory);
    const stepX = w / Math.max(1, rpsHistory.length - 1);

    // Area path with theme gradient
    ctx.beginPath();
    ctx.moveTo(0, h);
    rpsHistory.forEach((val, i) => {
      const x = i * stepX;
      const y = h - (val / maxVal) * (h - 20) - 10;
      if (i === 0) ctx.lineTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(w, h);
    ctx.closePath();

    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    gradient.addColorStop(0, hexToRgba(colors.chart1, colors.isLight ? 0.22 : 0.35));
    gradient.addColorStop(1, hexToRgba(colors.chart1, 0.01));
    ctx.fillStyle = gradient;
    ctx.fill();

    // Line stroke with theme glow
    ctx.beginPath();
    rpsHistory.forEach((val, i) => {
      const x = i * stepX;
      const y = h - (val / maxVal) * (h - 20) - 10;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = colors.chart1;
    ctx.lineWidth = 2.5;
    ctx.shadowColor = colors.chart1;
    ctx.shadowBlur = colors.isLight ? 2 : 10;
    ctx.stroke();
    ctx.shadowBlur = 0;
  }

  function drawDonutChart(counts = {}) {
    if (!typesDonutCanvas) return;
    const ctx = typesDonutCanvas.getContext('2d');
    const w = (typesDonutCanvas.width = typesDonutCanvas.clientWidth || typesDonutCanvas.width || 200);
    const h = (typesDonutCanvas.height = typesDonutCanvas.clientHeight || typesDonutCanvas.height || 200);
    const cx = w / 2;
    const cy = h / 2;
    const radius = Math.min(cx, cy) - 12;
    if (radius <= 5) return;
    const innerRadius = Math.max(1, radius * 0.62);

    lastDonutCounts = { ...lastDonutCounts, ...counts };
    const colors = getThemeColors();

    ctx.clearRect(0, 0, w, h);

    const data = [
      { label: 'HTML', val: lastDonutCounts.html || 1, color: colors.chart1 },
      { label: 'JS', val: lastDonutCounts.js || 1, color: colors.chart2 },
      { label: 'APIs', val: lastDonutCounts.api || 1, color: colors.chart3 },
      { label: 'Secrets', val: lastDonutCounts.secrets || 1, color: colors.chart4 }
    ];

    const total = data.reduce((acc, d) => acc + d.val, 0);
    if (total <= 0) return;
    let startAngle = -Math.PI / 2;

    data.forEach(slice => {
      const sliceAngle = (slice.val / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
      ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = slice.color;
      ctx.shadowColor = slice.color;
      ctx.shadowBlur = colors.isLight ? 0 : 8;
      ctx.fill();
      ctx.shadowBlur = 0;
      startAngle += sliceAngle;
    });

    // Center hole text
    ctx.fillStyle = colors.textMain;
    ctx.font = 'bold 13px JetBrains Mono';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`${total > 4 ? total : 0}`, cx, cy);
  }

  // Update SVG sparklines
  function updateSparkline(svgId, currentVal, strokeColor) {
    const svg = document.getElementById(svgId);
    if (!svg) return;
    const path = svg.querySelector('path');
    if (!path) return;
    const v = Math.min(24, Math.max(4, Math.round(currentVal % 20) + 4));
    path.setAttribute('d', `M2,24 L14,${28 - v} L26,${18 + Math.round(v/3)} L38,${24 - v} L50,14 L62,${26 - v} L70,${24 - Math.round(v/1.5)}`);
    if (strokeColor) {
      path.setAttribute('stroke', strokeColor);
    }
  }

  // Multi-Theme Manager Initialization
  if (window.CrawlizerTheme) {
    window.CrawlizerTheme.initThemeDropdown({
      wrap: 'theme-dropdown-wrap',
      button: 'btn-theme-selector',
      popover: 'theme-menu-popover',
      label: 'theme-trigger-label',
      swatch: 'theme-trigger-swatch',
      onSelect: () => {
        drawRpsChart();
        drawDonutChart();
      }
    });
  }

  // Listen to global theme changes to re-render charts immediately
  window.addEventListener('crawlizer:themechange', () => {
    drawRpsChart();
    drawDonutChart();
  });

  // ==========================================
  // Command Palette (Ctrl+K)
  // ==========================================
  const commands = [
    { title: 'Overview & Live Charts', icon: '📊', shortcut: 'TAB 1', action: () => switchTab('tab-overview') },
    { title: 'Targets & Spider Configuration', icon: '🎯', shortcut: 'TAB 2', action: () => switchTab('tab-upload') },
    { title: 'Discovered Endpoints Explorer', icon: '⚡', shortcut: 'TAB 3', action: () => switchTab('tab-results') },
    { title: 'Secrets & Threat Findings', icon: '🗡️', shortcut: 'TAB 4', action: () => switchTab('tab-secrets') },
    { title: 'Supply Chain & Dependency Audit', icon: '📦', shortcut: 'TAB 5', action: () => switchTab('tab-supply-chain') },
    { title: 'Live Stream Terminal Feed', icon: '💻', shortcut: 'TAB 6', action: () => switchTab('tab-terminal') },
    { title: 'Switch Theme (Cycle Alt+T)', icon: '🎨', shortcut: 'THEME', action: () => window.CrawlizerTheme && window.CrawlizerTheme.cycleTheme() },
    { title: 'Theme: Matrix (Cyberpunk Dark)', icon: '🟢', shortcut: 'TH-1', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('matrix') },
    { title: 'Theme: Midnight Blue (Deep Navy)', icon: '🔵', shortcut: 'TH-2', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('midnight') },
    { title: 'Theme: Dracula (Purple-Gray)', icon: '🟣', shortcut: 'TH-3', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('dracula') },
    { title: 'Theme: Crimson Ops (Red Team)', icon: '🔴', shortcut: 'TH-4', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('crimson') },
    { title: 'Theme: Nord Frost (Muted Slate)', icon: '❄️', shortcut: 'TH-5', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('nord') },
    { title: 'Theme: Clean Light (Crisp Slate)', icon: '☀️', shortcut: 'TH-6', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('clean-light') },
    { title: 'Theme: Paper Mint (Warm Mint Light)', icon: '🍃', shortcut: 'TH-7', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('paper-mint') },
    { title: 'Theme: Solar Sand (Amber Cream Light)', icon: '🏜️', shortcut: 'TH-8', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('solar-sand') },
    { title: 'Theme: Auto (Follow System OS)', icon: '⚙️', shortcut: 'AUTO', action: () => window.CrawlizerTheme && window.CrawlizerTheme.applyTheme('auto') },
    { title: 'Audit Active Tab (Supply Chain)', icon: '🔍', shortcut: 'AUDIT', action: () => { switchTab('tab-supply-chain'); scanActiveTabSupplyChain(true); } },
    { title: 'Start / Resume Crawl Engine', icon: '▶️', shortcut: 'START', action: () => btnStart.click() },
    { title: 'Pause Crawl Session', icon: '⏸️', shortcut: 'PAUSE', action: () => btnPause.click() },
    { title: 'Stop Crawl Session', icon: '⏹️', shortcut: 'STOP', action: () => btnStop.click() },
    { title: 'Export Discovered URLs (JSON)', icon: '📦', shortcut: 'EXP', action: () => exportJson.click() },
    { title: 'Export Discovered URLs (CSV)', icon: '📄', shortcut: 'CSV', action: () => exportCsv.click() },
    { title: 'Export Discovered URLs (TXT)', icon: '📝', shortcut: 'TXT', action: () => exportTxt.click() },
    { title: 'Toggle Matrix Rain Effect', icon: '01', shortcut: 'RAIN', action: () => btnToggleMatrix && btnToggleMatrix.click() },
    { title: 'Clear Stored Database', icon: '🗑️', shortcut: 'WIPE', action: () => btnClearDb.click() }
  ];

  function openCommandPalette() {
    if (!cmdPaletteBackdrop) return;
    cmdPaletteBackdrop.classList.add('open');
    if (cmdPaletteInput) {
      cmdPaletteInput.value = '';
      cmdPaletteInput.focus();
    }
    renderCommandList('');
  }

  function closeCommandPalette() {
    if (!cmdPaletteBackdrop) return;
    cmdPaletteBackdrop.classList.remove('open');
  }

  function renderCommandList(query) {
    if (!cmdResultsList) return;
    const q = query.toLowerCase().trim();
    const filtered = commands.filter(c => c.title.toLowerCase().includes(q) || c.shortcut.toLowerCase().includes(q));

    if (filtered.length === 0) {
      cmdResultsList.innerHTML = `<div style="padding: 16px; text-align: center; color: var(--text-muted); font-style: italic;">No matching commands found.</div>`;
      return;
    }

    cmdResultsList.innerHTML = filtered.map((c, i) => `
      <div class="cmd-item ${i === 0 ? 'selected' : ''}" data-idx="${i}">
        <div class="cmd-item-left">
          <span>${c.icon}</span>
          <span>${c.title}</span>
        </div>
        <span class="cmd-item-shortcut">${c.shortcut}</span>
      </div>
    `).join('');

    cmdResultsList.querySelectorAll('.cmd-item').forEach((item, idx) => {
      item.addEventListener('click', () => {
        closeCommandPalette();
        filtered[idx].action();
      });
    });
  }

  if (btnOpenCmdPalette) {
    btnOpenCmdPalette.addEventListener('click', openCommandPalette);
  }

  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (cmdPaletteBackdrop && cmdPaletteBackdrop.classList.contains('open')) {
        closeCommandPalette();
      } else {
        openCommandPalette();
      }
    } else if (e.key === 'Escape' && cmdPaletteBackdrop && cmdPaletteBackdrop.classList.contains('open')) {
      closeCommandPalette();
    }
  });

  if (cmdPaletteBackdrop) {
    cmdPaletteBackdrop.addEventListener('click', (e) => {
      if (e.target === cmdPaletteBackdrop) closeCommandPalette();
    });
  }

  if (cmdPaletteInput) {
    cmdPaletteInput.addEventListener('input', () => {
      renderCommandList(cmdPaletteInput.value);
    });
    cmdPaletteInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const selected = cmdResultsList.querySelector('.cmd-item.selected');
        if (selected) {
          selected.click();
        }
      }
    });
  }

  // ==========================================
  // Tab Switching
  // ==========================================
  function switchTab(tabId) {
    navItems.forEach(t => {
      if (t.dataset.tab === tabId) t.classList.add('active');
      else t.classList.remove('active');
    });

    tabPanes.forEach(p => {
      if (p.id === tabId) p.classList.add('active');
      else p.classList.remove('active');
    });

    const labelMap = {
      'tab-overview': 'mission/telemetry-overview',
      'tab-upload': 'mission/target-configuration',
      'tab-results': 'mission/discovered-endpoints',
      'tab-secrets': 'mission/secret-findings',
      'tab-supply-chain': 'mission/supply-chain-audit',
      'tab-terminal': 'mission/live-terminal'
    };
    typeBreadcrumbText(labelMap[tabId] || 'mission/active');

    if (tabId === 'tab-results') {
      refreshResultsTable();
    } else if (tabId === 'tab-secrets') {
      refreshSecretsTable();
    } else if (tabId === 'tab-supply-chain') {
      refreshSupplyChainView();
    } else if (tabId === 'tab-overview') {
      drawRpsChart();
    }
  }

  navItems.forEach(tab => {
    tab.addEventListener('click', () => {
      switchTab(tab.dataset.tab);
    });
  });

  // ==========================================
  // Crawler Engine Event Hookups & Initial Telemetry Load
  // ==========================================
  async function initDashboardData() {
    try {
      if (storage && storage.init) {
        await storage.init();
      }

      // Restore saved crawler configuration
      try {
        const savedConfig = await storage.getSetting('crawler_config');
        if (savedConfig) {
          if (savedConfig.mode && cfgMode) cfgMode.value = savedConfig.mode;
          if (savedConfig.scopeMode && cfgScope) {
            cfgScope.value = savedConfig.scopeMode;
            if (regexGroup) regexGroup.style.display = savedConfig.scopeMode === 'regex' ? 'flex' : 'none';
          }
          if (savedConfig.scopeRegex && cfgScopeRegex) cfgScopeRegex.value = savedConfig.scopeRegex;
          if (savedConfig.tabRenderDelay && cfgTabDelay) cfgTabDelay.value = savedConfig.tabRenderDelay;
          if (savedConfig.concurrency && cfgConcurrency) cfgConcurrency.value = savedConfig.concurrency;
          if (savedConfig.maxDepth && cfgDepth) cfgDepth.value = savedConfig.maxDepth;
          if (savedConfig.timeout && cfgTimeout) cfgTimeout.value = Math.round(savedConfig.timeout / 1000);
          if (savedConfig.subdomainCrawl !== undefined && cfgSubdomainCrawl) cfgSubdomainCrawl.checked = Boolean(savedConfig.subdomainCrawl);
          if (savedConfig.openFoundUrlsInTab !== undefined && cfgOpenInTab) cfgOpenInTab.checked = Boolean(savedConfig.openFoundUrlsInTab);
          if (savedConfig.autoClickButtons !== undefined && cfgClickButtons) cfgClickButtons.checked = Boolean(savedConfig.autoClickButtons);
          if (savedConfig.crawlJavascript !== undefined && cfgCrawlJs) cfgCrawlJs.checked = Boolean(savedConfig.crawlJavascript);
          if (savedConfig.parseRobotsAndSitemaps !== undefined && cfgRobotsSitemap) cfgRobotsSitemap.checked = Boolean(savedConfig.parseRobotsAndSitemaps);
          if (savedConfig.userAgent && cfgUserAgent) cfgUserAgent.value = savedConfig.userAgent;
        }
      } catch (cfgErr) {
        console.warn('Could not restore saved crawler_config:', cfgErr);
      }

      await refreshMetrics();
      await renderTargetsTable();
      await refreshResultsTable();
      await refreshSecretsTable();
      await refreshSupplyChainTable();
    } catch (err) {
      console.warn('Dashboard initial data loading error:', err);
    }

    try {
      drawRpsChart();
    } catch (e) {}
    typeBreadcrumbText('mission/telemetry-overview');
  }

  initDashboardData();

  let scanTimerInterval = null;
  let totalElapsedSeconds = 0;

  function startScanTimer() {
    clearInterval(scanTimerInterval);
    totalElapsedSeconds = 0;
    metricDuration.textContent = '00:00:00';
    if (metricDurationStatus) metricDurationStatus.textContent = 'Live Session';

    scanTimerInterval = setInterval(() => {
      totalElapsedSeconds++;
      const hrs = String(Math.floor(totalElapsedSeconds / 3600)).padStart(2, '0');
      const mins = String(Math.floor((totalElapsedSeconds % 3600) / 60)).padStart(2, '0');
      const secs = String(totalElapsedSeconds % 60).padStart(2, '0');
      metricDuration.textContent = `${hrs}:${mins}:${secs}`;

      // Update RPS Chart dynamically
      const currentRps = parseFloat(metricRps.textContent) || 0;
      rpsHistory.shift();
      rpsHistory.push(currentRps);
      drawRpsChart();
    }, 1000);
  }

  function pauseScanTimer() {
    if (scanTimerInterval) {
      clearInterval(scanTimerInterval);
      scanTimerInterval = null;
    }
    if (metricDurationStatus) metricDurationStatus.textContent = 'Paused Session';
  }

  function resumeScanTimer() {
    if (!scanTimerInterval) {
      scanTimerInterval = setInterval(() => {
        totalElapsedSeconds++;
        const hrs = String(Math.floor(totalElapsedSeconds / 3600)).padStart(2, '0');
        const mins = String(Math.floor((totalElapsedSeconds % 3600) / 60)).padStart(2, '0');
        const secs = String(totalElapsedSeconds % 60).padStart(2, '0');
        metricDuration.textContent = `${hrs}:${mins}:${secs}`;
      }, 1000);
    }
    if (metricDurationStatus) metricDurationStatus.textContent = 'Live Session';
  }

  function stopScanTimer(updateSummary = false) {
    if (scanTimerInterval) {
      clearInterval(scanTimerInterval);
      scanTimerInterval = null;
    }
    if (updateSummary && totalElapsedSeconds > 0) {
      const mins = Math.floor(totalElapsedSeconds / 60);
      const secs = totalElapsedSeconds % 60;
      const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
      if (metricDurationStatus) metricDurationStatus.textContent = `Finished in ${timeStr}`;
    }
  }

  engine.onLog = (entry) => {
    if (!terminalBody) return;
    const div = document.createElement('div');
    div.className = `log-line ${entry.level} font-mono`;
    div.textContent = entry.message;
    terminalBody.appendChild(div);
    if (terminalAutoscroll.checked) {
      terminalBody.scrollTop = terminalBody.scrollHeight;
    }
  };

  engine.onStatsUpdate = (stats) => {
    metricTargets.textContent = stats.totalTargets;
    metricCrawled.textContent = stats.crawledTargets;
    metricDiscovered.textContent = stats.totalDiscovered;
    metricRps.textContent = stats.rps;
    metricSubdomains.textContent = stats.subdomains;
    metricDupes.textContent = stats.duplicatesFiltered;
    tabDiscoveredCount.textContent = stats.totalDiscovered;

    const progress = stats.totalTargets > 0 ? Math.min(100, Math.round((stats.crawledTargets / stats.totalTargets) * 100)) : 0;
    metricProgressPercent.textContent = `${progress}% Completed`;
    progressBarFill.style.width = `${progress}%`;

    // Sparklines reactivity
    updateSparkline('sparkline-targets', stats.totalTargets, '#00f0ff');
    updateSparkline('sparkline-crawled', stats.crawledTargets, '#39ff14');
    updateSparkline('sparkline-discovered', stats.totalDiscovered, '#00f0ff');
    updateSparkline('sparkline-rps', parseFloat(stats.rps) || 0, '#39ff14');
  };
  engine.onProgress = engine.onStatsUpdate;

  engine.onStateChange = (state) => {
    headerStatusDot.className = 'status-indicator-dot';
    if (state === 'running') {
      if (!scanTimerInterval) startScanTimer();
      else resumeScanTimer();
      headerStatusDot.classList.add('running');
      headerStatusLabel.textContent = 'CRAWLING';
      btnStart.style.display = 'none';
      btnPause.style.display = 'inline-flex';
      btnResume.style.display = 'none';
      btnFocusTab.style.display = 'inline-flex';
    } else if (state === 'paused') {
      pauseScanTimer();
      headerStatusDot.classList.add('paused');
      headerStatusLabel.textContent = 'PAUSED';
      btnStart.style.display = 'none';
      btnPause.style.display = 'none';
      btnResume.style.display = 'inline-flex';
      btnStop.disabled = false;
    } else {
      stopScanTimer(true);
      headerStatusLabel.textContent = 'IDLE';
      btnStart.style.display = 'inline-flex';
      btnPause.style.display = 'none';
      btnResume.style.display = 'none';
      btnStop.disabled = true;
      btnFocusTab.style.display = 'none';
      captchaBanner.style.display = 'none';
      refreshMetrics();
      renderTargetsTable();
      refreshResultsTable();
      refreshSecretsTable();
      refreshSupplyChainTable();
    }
  };

  engine.onCaptchaDetected = (info) => {
    captchaBanner.style.display = 'flex';
    if (captchaTypeTitle) captchaTypeTitle.textContent = `${info.challengeType || info.title || 'CAPTCHA / Challenge'} Detected!`;
    if (captchaTargetUrl) captchaTargetUrl.textContent = info.url;
  };

  engine.onSecretFound = () => {
    refreshMetrics();
    debouncedRefreshSecrets();
  };

  engine.onSupplyChainFinding = () => {
    refreshMetrics();
    debouncedRefreshSupplyChain();
  };

  const SUPPLY_CONFIG_NAMES = ['package.json', 'package-lock.json', '.npmrc', 'requirements.txt', '.env', 'yarn.lock', 'pnpm-lock.yaml', 'Pipfile', 'composer.json', 'pom.xml', 'go.mod', 'Cargo.toml'];
  engine.onUrlFound = async (urlInput) => {
    if (!urlInput) return;
    const urlArray = Array.isArray(urlInput) ? urlInput : [urlInput];
    const newExposedToSave = [];

    for (const urlObj of urlArray) {
      if (!urlObj || !urlObj.url) continue;
      const lower = urlObj.url.toLowerCase();
      for (const name of SUPPLY_CONFIG_NAMES) {
        if (lower.endsWith(name) || lower.includes(`/${name}?`) || lower.includes(`/${name}#`)) {
          if (!supplyState.exposedFiles.some(f => f.url === urlObj.url)) {
            const expItem = {
              key: `exposed:/${name}`,
              type: 'exposed-file',
              name: `/${name}`,
              url: urlObj.url,
              path: `/${name}`,
              status: 200,
              contentType: 'config',
              riskLevel: 'HIGH',
              riskReasons: [`Exposed configuration file: ${urlObj.url}`]
            };
            supplyState.exposedFiles.push(expItem);
            newExposedToSave.push(expItem);
          }
          break;
        }
      }
    }

    if (newExposedToSave.length > 0) {
      try {
        await storage.saveSupplyChainFindings(newExposedToSave);
      } catch (e) {}
      updateSupplyStatsUI();
      if (document.getElementById('tab-supply-chain')?.classList.contains('active')) {
        renderSupplyTable();
      }
    }

    debouncedRefreshResultsTable();
  };

  // ==========================================
  // Local Server & Agent Integration
  // ==========================================
  const agentStatusPill = document.getElementById('agent-status-pill');
  const agentStatusDot = document.getElementById('agent-status-dot');
  const agentStatusLabel = document.getElementById('agent-status-label');
  let isExtensionConnected = false;

  function updateAgentStatusUI(connected, version = '1.2.0') {
    isExtensionConnected = Boolean(connected);
    const sidebarExtStatus = document.getElementById('sidebar-extension-status');
    const sidebarExtDot = document.getElementById('sidebar-ext-dot');
    const sidebarExtText = document.getElementById('sidebar-ext-text');
    const extAlertBanner = document.getElementById('extension-alert-banner');

    if (agentStatusPill) {
      if (connected) {
        agentStatusPill.classList.remove('offline', 'disconnected');
        agentStatusPill.classList.add('connected');
        if (agentStatusDot) {
          agentStatusDot.className = 'agent-indicator-dot online';
        }
        if (agentStatusLabel) {
          agentStatusLabel.textContent = `EXTENSION: CONNECTED`;
        }
        agentStatusPill.title = `Browser Extension Connected (v${version}) - Ready to crawl`;
      } else {
        agentStatusPill.classList.remove('connected');
        agentStatusPill.classList.add('offline', 'disconnected');
        if (agentStatusDot) {
          agentStatusDot.className = 'agent-indicator-dot offline';
        }
        if (agentStatusLabel) {
          agentStatusLabel.textContent = 'EXTENSION: DISCONNECTED';
        }
        agentStatusPill.title = 'Browser Extension Not Connected - Load unpacked extension in Chrome to crawl';
      }
    }

    if (sidebarExtStatus) {
      if (connected) {
        sidebarExtStatus.classList.remove('offline');
        sidebarExtStatus.classList.add('connected');
        sidebarExtStatus.title = `Browser Extension Connected (v${version})`;
        if (sidebarExtDot) sidebarExtDot.className = 'extension-pulse-dot online';
        if (sidebarExtText) sidebarExtText.textContent = `EXT: CONNECTED (v${version})`;
      } else {
        sidebarExtStatus.classList.remove('connected');
        sidebarExtStatus.classList.add('offline');
        sidebarExtStatus.title = 'Browser Extension Disconnected';
        if (sidebarExtDot) sidebarExtDot.className = 'extension-pulse-dot offline';
        if (sidebarExtText) sidebarExtText.textContent = 'EXT: DISCONNECTED';
      }
    }

    if (extAlertBanner) {
      extAlertBanner.style.display = connected ? 'none' : 'flex';
    }
  }

  // Interactive recheck handlers
  if (agentStatusPill) {
    agentStatusPill.addEventListener('click', () => {
      fetch('/api/status')
        .then(r => r.json())
        .then(data => {
          if (data && data.agent) updateAgentStatusUI(data.agent.connected, data.agent.version);
        })
        .catch(() => updateAgentStatusUI(false));
    });
  }

  const btnRecheckExt = document.getElementById('btn-recheck-ext');
  if (btnRecheckExt) {
    btnRecheckExt.addEventListener('click', () => {
      btnRecheckExt.textContent = 'Checking...';
      fetch('/api/status')
        .then(r => r.json())
        .then(data => {
          if (data && data.agent) updateAgentStatusUI(data.agent.connected, data.agent.version);
          setTimeout(() => { btnRecheckExt.textContent = 'Re-check Connection'; }, 800);
        })
        .catch(() => {
          updateAgentStatusUI(false);
          btnRecheckExt.textContent = 'Re-check Connection';
        });
    });
  }

  if (storage && storage.isLocalServer && storage.isLocalServer()) {
    storage.on('agent:status', (data) => {
      updateAgentStatusUI(data.connected, data.version);
    });

    storage.on('init:state', (data) => {
      if (data.agent) updateAgentStatusUI(data.agent.connected, data.agent.version);
      if (data.crawlState === 'running') engine.onStateChange('running');
      else if (data.crawlState === 'paused') engine.onStateChange('paused');
    });

    storage.on('crawl:state', (data) => {
      engine.isRunning = (data.state === 'running');
      engine.isPaused = (data.state === 'paused');
      if (data.state === 'running') engine.onStateChange('running');
      else if (data.state === 'paused') engine.onStateChange('paused');
      else engine.onStateChange('stopped');
    });

    storage.on('crawl:job_started', () => {
      refreshMetrics();
      renderTargetsTable();
    });

    storage.on('crawl:job_finished', () => {
      refreshMetrics();
      renderTargetsTable();
      debouncedRefreshResultsTable();
      debouncedRefreshSecrets();
      debouncedRefreshSupplyChain();
    });

    storage.on('data:urls', () => {
      debouncedRefreshResultsTable();
      refreshMetrics();
    });

    storage.on('data:secrets', () => {
      debouncedRefreshSecrets();
      refreshMetrics();
    });

    storage.on('data:supply', () => {
      debouncedRefreshSupplyChain();
      refreshMetrics();
    });

    storage.on('data:wipe', () => {
      refreshMetrics();
      renderTargetsTable();
      refreshResultsTable();
      refreshSecretsTable();
      refreshSupplyChainTable();
    });

    storage.on('log:new', (data) => {
      if (data.item) {
        engine.onLog(data.item);
      }
    });

    // Initial status fetch
    fetch('/api/status')
      .then(r => r.json())
      .then(data => {
        if (data && data.agent) updateAgentStatusUI(data.agent.connected, data.agent.version);
      })
      .catch(() => updateAgentStatusUI(false));

    // Periodic 3-second heartbeat poll to ensure extension connection status stays 100% accurate
    setInterval(() => {
      fetch('/api/status')
        .then(r => r.json())
        .then(data => {
          if (data && data.agent) {
            updateAgentStatusUI(data.agent.connected, data.agent.version);
          }
        })
        .catch(() => updateAgentStatusUI(false));
    }, 3000);
  }

  // ==========================================
  // Crawler Controls
  // ==========================================
  btnStart.addEventListener('click', async () => {
    await startCrawling();
  });

  btnPause.addEventListener('click', () => {
    engine.pause();
  });

  btnResume.addEventListener('click', () => {
    engine.resume();
  });

  btnStop.addEventListener('click', () => {
    engine.stop();
  });

  btnFocusTab.addEventListener('click', () => {
    engine.focusTab();
  });

  btnCaptchaFocus.addEventListener('click', () => {
    engine.focusTab();
  });

  btnCaptchaSolved.addEventListener('click', () => {
    captchaBanner.style.display = 'none';
    engine.resume();
  });

  btnCaptchaSkip.addEventListener('click', () => {
    captchaBanner.style.display = 'none';
    engine.skipCurrentTarget();
  });

  async function startCrawling() {
    try {
      if (!isExtensionConnected) {
        engine.log('wrn', '[Extension Agent] Notice: Browser extension is currently disconnected. Open Chrome and ensure Crawlizer extension is loaded to enable tab crawling & DOM exploration.');
      }

      // Auto-commit any pasted seeds currently sitting in targetTextarea
      if (targetTextarea && targetTextarea.value.trim()) {
        const rawPasted = targetTextarea.value.trim();
        const urls = parseUrlText(rawPasted);
        if (urls.length > 0) {
          await storage.addTargets(urls);
          targetTextarea.value = '';
          engine.log('inf', `Auto-loaded ${urls.length} targets from input box.`);
          await refreshMetrics();
          await renderTargetsTable();
        }
      }

      const config = {
        mode: cfgMode?.value || 'single-tab',
        scopeMode: cfgScope?.value || 'same-domain',
        scopeRegex: cfgScopeRegex?.value?.trim() || '',
        tabRenderDelay: parseInt(cfgTabDelay?.value, 10) || 400,
        concurrency: (cfgMode?.value === 'single-tab') ? 1 : (parseInt(cfgConcurrency?.value, 10) || 10),
        maxDepth: Math.max(3, parseInt(cfgDepth?.value, 10) || 3),
        timeout: (parseInt(cfgTimeout?.value, 10) || 8) * 1000,
        subdomainCrawl: cfgSubdomainCrawl ? cfgSubdomainCrawl.checked : true,
        openFoundUrlsInTab: cfgOpenInTab ? cfgOpenInTab.checked : true,
        autoClickButtons: cfgClickButtons ? cfgClickButtons.checked : true,
        crawlJavascript: cfgCrawlJs ? cfgCrawlJs.checked : true,
        parseRobotsAndSitemaps: cfgRobotsSitemap ? cfgRobotsSitemap.checked : true,
        userAgent: cfgUserAgent?.value?.trim() || navigator.userAgent
      };

      engine.configure(config);
      await storage.saveSetting('crawler_config', config);

      // Reset any targets stuck in 'crawling' status from a previously aborted session
      const allExistingTargets = await storage.getAllTargets();
      const stuckCrawling = allExistingTargets.filter(t => t.status === 'crawling');
      for (const s of stuckCrawling) {
        await storage.updateTarget(s.id, { status: 'pending' });
      }

      let pending = await storage.getPendingTargets();
      if (pending.length === 0 && allExistingTargets.length > 0) {
        engine.log('inf', `Re-activating ${allExistingTargets.length} seed targets for new crawl session...`);
        await storage.reactivateAllTargets();
        pending = await storage.getPendingTargets();
      }

      if (pending.length === 0) {
        alert('No pending targets to crawl. Please upload a .txt file or paste seed URLs.');
        switchTab('tab-upload');
        return;
      }

      engine.log('inf', `Starting crawl execution with ${pending.length} targets...`);
      await engine.start(pending);
    } catch (err) {
      console.error('startCrawling error:', err);
      engine.log('err', `Start crawl failed: ${err.message}`);
    }
  }

  // ==========================================
  // Target Upload & Text Input
  // ==========================================
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      await processTextFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', async (e) => {
    if (e.target.files.length > 0) {
      await processTextFile(e.target.files[0]);
    }
  });

  async function processTextFile(file) {
    const text = await file.text();
    const urls = parseUrlText(text);
    if (urls.length === 0) {
      alert('No valid URLs found in file.');
      return;
    }
    await storage.addTargets(urls);
    engine.log('inf', `Loaded ${urls.length} targets from ${file.name}`);
    await refreshMetrics();
    await renderTargetsTable();
  }

  btnAddPasted.addEventListener('click', async () => {
    const text = targetTextarea.value.trim();
    if (!text) return;
    const urls = parseUrlText(text);
    if (urls.length === 0) {
      alert('No valid URLs found in textarea.');
      return;
    }
    await storage.addTargets(urls);
    targetTextarea.value = '';
    engine.log('inf', `Added ${urls.length} pasted seed targets`);
    await refreshMetrics();
    await renderTargetsTable();
  });

  btnLoadDemo.addEventListener('click', async () => {
    const sample = [
      'https://example.com',
      'https://httpbin.org',
      'https://api.github.com'
    ];
    await storage.addTargets(sample);
    engine.log('inf', `Loaded ${sample.length} sample targets`);
    await refreshMetrics();
    await renderTargetsTable();
  });

  btnClearTargets.addEventListener('click', async () => {
    if (!confirm('Clear all targets from queue?')) return;
    await storage.clearTargets();
    await refreshMetrics();
    await renderTargetsTable();
    engine.log('inf', 'Cleared all target seeds');
  });

  function parseUrlText(text) {
    return text.split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'));
  }

  if (cfgScope && regexGroup) {
    cfgScope.addEventListener('change', () => {
      regexGroup.style.display = cfgScope.value === 'regex' ? 'flex' : 'none';
    });
  }

  btnClearDb.addEventListener('click', async () => {
    if (confirm('Are you sure you want to completely wipe all targets and discovered data?')) {
      await storage.clearAll();
      await refreshMetrics();
      await renderTargetsTable();
      await refreshResultsTable();
      await refreshSecretsTable();
      await refreshSupplyChainTable();
      engine.log('inf', 'All database storage wiped.');
    }
  });

  // ==========================================
  // Export Menu
  // ==========================================
  btnExportMenu.addEventListener('click', (e) => {
    e.stopPropagation();
    exportMenu.classList.toggle('show');
  });

  document.addEventListener('click', () => {
    exportMenu.classList.remove('show');
  });

  exportTxt.addEventListener('click', async () => {
    const urls = await storage.getDiscoveredUrls();
    if (urls.length === 0) {
      alert('No discovered URLs to export.');
      return;
    }
    const txtContent = urls.map(u => u.url).join('\n');
    downloadFile(txtContent, 'crawlizer-urls.txt', 'text/plain');
    engine.log('inf', `Exported ${urls.length} URLs to crawlizer-urls.txt`);
  });

  exportJson.addEventListener('click', async () => {
    const urls = await storage.getDiscoveredUrls();
    if (urls.length === 0) {
      alert('No discovered URLs to export.');
      return;
    }
    const jsonContent = JSON.stringify(urls, null, 2);
    downloadFile(jsonContent, 'crawlizer-results.json', 'application/json');
    engine.log('inf', `Exported ${urls.length} entries to crawlizer-results.json`);
  });

  exportCsv.addEventListener('click', async () => {
    const urls = await storage.getDiscoveredUrls();
    if (urls.length === 0) {
      alert('No discovered URLs to export.');
      return;
    }
    let csv = 'URL,Type,SourceURL,Scope,DiscoveredAt\n';
    urls.forEach(u => {
      const escapedUrl = `"${(u.url || '').replace(/"/g, '""')}"`;
      const escapedSrc = `"${(u.sourceUrl || '').replace(/"/g, '""')}"`;
      const date = new Date(u.discoveredAt).toISOString();
      csv += `${escapedUrl},"${u.type}",${escapedSrc},"${u.scope}","${date}"\n`;
    });
    downloadFile(csv, 'crawlizer-results.csv', 'text/csv');
    engine.log('inf', `Exported ${urls.length} entries to crawlizer-results.csv`);
  });

  copyClipboard.addEventListener('click', async () => {
    const urls = await storage.getDiscoveredUrls();
    if (urls.length === 0) {
      alert('No discovered URLs to copy.');
      return;
    }
    const txt = urls.map(u => u.url).join('\n');
    await navigator.clipboard.writeText(txt);
    alert(`Copied ${urls.length} discovered URLs to clipboard!`);
  });

  function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ==========================================
  // Metrics & Targets Queue Table
  // ==========================================
  async function refreshMetrics() {
    const stats = await storage.getStats();
    metricTargets.textContent = stats.totalTargets;
    metricPending.textContent = `${stats.pendingTargets} Pending in Queue`;
    metricCrawled.textContent = stats.crawledTargets;
    metricDiscovered.textContent = stats.totalDiscovered;
    tabDiscoveredCount.textContent = stats.totalDiscovered;
    loadedSeedsBadge.textContent = `${stats.totalTargets} Ready`;

    const totalSec = stats.totalSecrets || 0;
    if (metricSecrets) metricSecrets.textContent = totalSec;
    if (tabSecretsCount) tabSecretsCount.textContent = totalSec;

    try {
      const allSecrets = await storage.getSecrets();
      const critCount = allSecrets.filter(s => s.severity === 'critical').length;
      const highCount = allSecrets.filter(s => s.severity === 'high').length;
      if (metricSecretsBreakdown) {
        if (critCount > 0 || highCount > 0) {
          metricSecretsBreakdown.textContent = `${critCount} Crit, ${highCount} High`;
        } else {
          metricSecretsBreakdown.textContent = `${totalSec} Sensitive Findings`;
        }
      }
    } catch {}

    try {
      const allSupply = await storage.getSupplyChainFindings();
      const threats = allSupply.filter(s => s.isUnregistered || (s.advisoriesCount > 0)).length;
      if (tabSupplyChainBadge) {
        tabSupplyChainBadge.textContent = threats > 0 ? threats : allSupply.length;
        tabSupplyChainBadge.className = threats > 0 ? 'nav-badge badge-magenta' : 'nav-badge badge-cyan';
      }
    } catch {}

    const progress = stats.totalTargets > 0 ? Math.min(100, Math.round((stats.crawledTargets / stats.totalTargets) * 100)) : 0;
    metricProgressPercent.textContent = `${progress}% Completed`;
    progressBarFill.style.width = `${progress}%`;

    // Update Donut Chart
    try {
      const urls = await storage.getDiscoveredUrls();
      const htmlCount = urls.filter(u => (u.type || '').includes('html')).length;
      const jsCount = urls.filter(u => (u.type || '').includes('js') || (u.type || '').includes('bundle')).length;
      const apiCount = urls.filter(u => (u.type || '').includes('api')).length;
      drawDonutChart({ html: htmlCount, js: jsCount, api: apiCount, secrets: totalSec });
    } catch {}
  }

  async function renderTargetsTable() {
    const targets = await storage.getAllTargets();
    targetsTableCount.textContent = `${targets.length} items`;

    if (targets.length === 0) {
      targetsTbody.innerHTML = `<tr><td colspan="5" class="empty-state">No targets uploaded yet. Upload a .txt file or paste URLs above.</td></tr>`;
      return;
    }

    let rowsHtml = '';
    targets.slice(0, 100).forEach((t, idx) => {
      const statusColor = t.status === 'completed' ? 'var(--neon-green)' : t.status === 'crawling' ? 'var(--neon-cyan)' : t.status === 'failed' ? 'var(--neon-red)' : '#8b949e';
      const crawledTime = t.crawledAt ? new Date(t.crawledAt).toLocaleTimeString() : '-';

      rowsHtml += `
        <tr>
          <td>${idx + 1}</td>
          <td class="url-cell"><a href="${escapeHtml(t.url)}" target="_blank">${escapeHtml(t.url)}</a></td>
          <td><span style="color: ${statusColor}; font-weight: 700; text-transform: uppercase; font-size: 11px; font-family: var(--font-mono);">${t.status}</span></td>
          <td>${t.discoveredCount || 0}</td>
          <td>${crawledTime}</td>
        </tr>
      `;
    });

    if (targets.length > 100) {
      rowsHtml += `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); font-style: italic;">Showing first 100 of ${targets.length} targets...</td></tr>`;
    }

    targetsTbody.innerHTML = rowsHtml;
  }

  // ==========================================
  // Discovered URLs Results Table
  // ==========================================
  let refreshDebounceTimer = null;
  function debouncedRefreshResults() {
    clearTimeout(refreshDebounceTimer);
    refreshDebounceTimer = setTimeout(refreshResultsTable, 300);
  }

  async function refreshResultsTable() {
    const filters = {
      search: tableSearch.value.trim(),
      type: filterType.value,
      scope: filterScope.value,
      extension: filterExt.value
    };

    cachedResults = await storage.getDiscoveredUrls(filters);
    filterCount.textContent = `Showing ${cachedResults.length} URLs`;
    renderResultsPage();
  }

  function renderResultsPage() {
    const totalItems = cachedResults.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;

    paginationInfo.textContent = `Page ${currentPage} of ${totalPages} (${totalItems} items)`;
    currentPageDisplay.textContent = currentPage;
    btnPagePrev.disabled = currentPage <= 1;
    btnPageNext.disabled = currentPage >= totalPages;

    if (totalItems === 0) {
      resultsTbody.innerHTML = `<tr><td colspan="6" class="empty-state">No URLs found matching filters.</td></tr>`;
      return;
    }

    const startIndex = (currentPage - 1) * pageSize;
    const pageItems = cachedResults.slice(startIndex, startIndex + pageSize);

    let html = '';
    pageItems.forEach((item, idx) => {
      const rowNum = startIndex + idx + 1;
      const itemType = (item.type || '').toLowerCase();
      const typeClass = itemType.includes('subdomain') ? 'tag-subdomain' :
                        itemType.includes('button') ? 'tag-btn-click' :
                        itemType.includes('api') ? 'tag-network-api' :
                        itemType.includes('js') ? 'tag-js-endpoint' : 'tag-html-link';
      const scopeClass = (item.scope || '') === 'in-scope' ? 'tag-in-scope' : 'tag-out-of-scope';

      html += `
        <tr>
          <td>${rowNum}</td>
          <td class="url-cell">
            <a href="${escapeHtml(item.url)}" target="_blank" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</a>
          </td>
          <td><span class="badge-tag ${typeClass}">${escapeHtml(item.type)}</span></td>
          <td class="source-cell font-mono text-xs" style="color: var(--text-muted);" title="${escapeHtml(item.sourceUrl || '')}">${escapeHtml(item.sourceUrl || '-')}</td>
          <td><span class="badge-tag ${scopeClass}">${escapeHtml(item.scope)}</span></td>
          <td>
            <button class="btn btn-glass copy-row-btn" style="padding: 3px 8px; font-size: 11px;" data-url="${escapeHtml(item.url)}" title="Copy URL">
              Copy
            </button>
          </td>
        </tr>
      `;
    });

    resultsTbody.innerHTML = html;

    document.querySelectorAll('.copy-row-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        await navigator.clipboard.writeText(btn.dataset.url);
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1200);
      });
    });
  }

  tableSearch.addEventListener('input', () => {
    currentPage = 1;
    debouncedRefreshResults();
  });
  filterType.addEventListener('change', () => {
    currentPage = 1;
    refreshResultsTable();
  });
  filterScope.addEventListener('change', () => {
    currentPage = 1;
    refreshResultsTable();
  });
  filterExt.addEventListener('change', () => {
    currentPage = 1;
    refreshResultsTable();
  });

  btnPagePrev.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      renderResultsPage();
    }
  });

  btnPageNext.addEventListener('click', () => {
    const totalPages = Math.ceil(cachedResults.length / pageSize);
    if (currentPage < totalPages) {
      currentPage++;
      renderResultsPage();
    }
  });

  selectPageSize.addEventListener('change', (e) => {
    pageSize = parseInt(e.target.value, 10);
    currentPage = 1;
    renderResultsPage();
  });

  btnClearLogs.addEventListener('click', () => {
    terminalBody.innerHTML = '';
    engine.log('inf', 'Logs cleared');
  });

  // ==========================================
  // Secrets & Sensitive Findings Operations
  // ==========================================
  let refreshSecretsDebounce = null;
  function debouncedRefreshSecrets() {
    clearTimeout(refreshSecretsDebounce);
    refreshSecretsDebounce = setTimeout(refreshSecretsTable, 300);
  }

  async function refreshSecretsTable() {
    if (!secretsTbody) return;

    const filters = {
      search: secretsSearch ? secretsSearch.value.trim() : '',
      severity: secretsFilterSeverity ? secretsFilterSeverity.value : 'all',
      sourceType: secretsFilterSource ? secretsFilterSource.value : 'all'
    };

    cachedSecrets = await storage.getSecrets(filters);
    if (secretsCountLabel) {
      secretsCountLabel.textContent = `${cachedSecrets.length} findings`;
    }
    renderSecretsTable(cachedSecrets);
  }

  function formatSourceTag(type) {
    const t = (type || 'html').toLowerCase();
    let label = t.toUpperCase();
    let tagClass = 'tag-html-link';
    if (t.includes('bundle') || t.includes('js')) {
      label = 'JS BUNDLE';
      tagClass = 'tag-js-endpoint';
    } else if (t.includes('map')) {
      label = '.MAP';
      tagClass = 'tag-subdomain';
    } else if (t.includes('cdn')) {
      label = 'CDN';
      tagClass = 'tag-header';
    } else if (t.includes('manifest') || t.includes('config') || t.includes('json') || t.includes('package')) {
      label = 'CONFIG';
      tagClass = 'tag-param';
    } else if (t.includes('dom') || t.includes('inline')) {
      label = 'DOM SCRIPT';
      tagClass = 'tag-html-link';
    }
    return `<span class="badge-tag ${tagClass}">${label}</span>`;
  }

  function renderCodeContextBlock(context, matchSecret = '') {
    if (!context) return '';
    const trimmed = String(context).trim();
    if (!trimmed) return '';

    const lineCount = (trimmed.match(/\n/g) || []).length + 1;
    // Genuine overflow check: only long snippets need collapse/expand (> 220 chars or > 2 lines)
    const needsToggle = trimmed.length > 220 || lineCount > 2;

    // Highlight the matched secret inside the snippet so it's instantly identifiable
    let displayHtml = escapeHtml(trimmed);
    if (matchSecret && matchSecret.length >= 4) {
      const escMatch = escapeHtml(matchSecret);
      displayHtml = displayHtml.split(escMatch).join(`<mark class="secret-code-highlight">${escMatch}</mark>`);
    }

    if (!needsToggle) {
      // Short snippet fits completely: do NOT show a useless "View more" button!
      return `
        <div class="secret-context-wrap">
          <div class="secret-context-snippet font-mono">${displayHtml}</div>
          <div class="snippet-actions-row">
            <button class="snippet-copy-btn font-mono" type="button" title="Copy code context snippet">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              <span>Copy</span>
            </button>
          </div>
        </div>
      `;
    }

    // Long snippet: compact view shows 2 lines, clicking expands to show full content
    return `
      <div class="secret-context-wrap has-overflow">
        <div class="secret-context-snippet is-compact font-mono" data-full-text="${escapeHtml(trimmed)}">${displayHtml}</div>
        <div class="snippet-actions-row">
          <button class="snippet-toggle-btn font-mono" type="button" aria-expanded="false" data-chars="${trimmed.length}" title="Expand or collapse code context">
            <span>View full context (${trimmed.length} chars)</span>
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="toggle-icon"><path d="M6 9l6 6 6-6"/></svg>
          </button>
          <button class="snippet-copy-btn font-mono" type="button" title="Copy code context snippet">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span>Copy snippet</span>
          </button>
        </div>
      </div>
    `;
  }

  function renderSourceItem(src, matchSecret = '') {
    return `
      <div class="secret-location-item">
        <div style="display: flex; align-items: center; gap: 8px;">
          ${formatSourceTag(src.type)}
          <a href="${escapeHtml(src.url)}" target="_blank" rel="noopener noreferrer" class="url-cell text-xs" style="color: var(--neon-cyan);">${escapeHtml(src.url)}</a>
        </div>
        ${renderCodeContextBlock(src.context, matchSecret)}
      </div>
    `;
  }

  function renderSupplyChainSourceItem(src) {
    const rawUrl = src.url ? src.url.trim() : '';
    const isLink = /^https?:\/\//i.test(rawUrl);
    const chunkName = src.chunkName ? ` [${escapeHtml(src.chunkName)}]` : '';
    let linkMarkup = '';
    if (isLink) {
      linkMarkup = `<a href="${escapeHtml(rawUrl)}" target="_blank" rel="noreferrer" class="url-cell text-xs" style="color: var(--neon-cyan); word-break: break-all;">${escapeHtml(rawUrl)}${chunkName}</a>`;
    } else if (rawUrl) {
      linkMarkup = `<span class="url-cell text-xs" style="color: var(--neon-cyan); word-break: break-all;">${escapeHtml(rawUrl)}${chunkName}</span>`;
    } else {
      linkMarkup = `<span class="font-mono text-xs" style="color: var(--text-muted);">DOM Script Inline</span>`;
    }

    const typeTag = formatSourceTag(src.type || (rawUrl.includes('.js') ? 'js-bundle' : 'code'));
    const contextHtml = renderCodeContextBlock(src.context);

    return `
      <div class="secret-location-item">
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          ${typeTag}
          ${linkMarkup}
        </div>
        ${contextHtml}
      </div>
    `;
  }

  function renderSecretsTable(secrets) {
    if (!secretsTbody) return;

    if (!secrets || secrets.length === 0) {
      secretsTbody.innerHTML = `<tr><td colspan="7" class="empty-state">No matching sensitive credentials detected. Launch a crawl to scan!</td></tr>`;
      if (secretsCountLabel) secretsCountLabel.textContent = `0 findings`;
      return;
    }

    // Strict in-memory consolidation: prevents duplicate keys from ever displaying
    const uniqueMap = new Map();
    for (const s of secrets) {
      if (!s || !s.match) continue;
      const key = s.match.trim();
      if (!key) continue;

      const rawSources = Array.isArray(s.sources) && s.sources.length > 0
        ? s.sources
        : (s.sourceUrl ? [{ url: s.sourceUrl, type: s.sourceType || 'html', context: s.context || '', discoveredAt: s.discoveredAt || Date.now() }] : []);

      if (uniqueMap.has(key)) {
        const existing = uniqueMap.get(key);
        for (const src of rawSources) {
          if (src.url && !existing.sources.some(e => e.url === src.url)) {
            existing.sources.push(src);
          }
        }
      } else {
        uniqueMap.set(key, {
          ...s,
          match: key,
          sources: [...rawSources]
        });
      }
    }

    const dedupedSecrets = Array.from(uniqueMap.values());
    if (secretsCountLabel) {
      secretsCountLabel.textContent = `${dedupedSecrets.length} unique findings`;
    }

    let rowsHtml = '';
    dedupedSecrets.forEach((s, idx) => {
      const sevClass = s.severity === 'critical' ? 'badge-sev-critical' :
                        s.severity === 'high' ? 'badge-sev-high' :
                        s.severity === 'medium' ? 'badge-sev-medium' : 'badge-sev-info';

      const sources = Array.isArray(s.sources) && s.sources.length > 0
        ? s.sources
        : (s.sourceUrl ? [{ url: s.sourceUrl, type: s.sourceType || 'html', context: s.context || '' }] : []);

      const locCount = sources.length;
      const countBadge = `<span class="secret-loc-count-badge">${locCount} ${locCount === 1 ? 'loc' : 'locs'}</span>`;

      const initialSources = sources.slice(0, 2);
      const remainingSources = sources.slice(2);

      let locationsHtml = `<div class="secret-locations-list">`;
      initialSources.forEach(src => {
        locationsHtml += renderSourceItem(src, s.match);
      });

      if (remainingSources.length > 0) {
        locationsHtml += `<div class="secret-locations-extra" style="display: none;">`;
        remainingSources.forEach(src => {
          locationsHtml += renderSourceItem(src, s.match);
        });
        locationsHtml += `</div>`;
        locationsHtml += `<button class="btn btn-glass secret-more-toggle" style="padding: 2px 8px; font-size: 10px; align-self: flex-start; margin-top: 4px;" data-count="${remainingSources.length}">+ ${remainingSources.length} more location(s)</button>`;
      }
      locationsHtml += `</div>`;

      const dateVal = s.lastDiscoveredAt || s.firstDiscoveredAt || s.discoveredAt;
      const timeStr = dateVal ? new Date(dateVal).toLocaleTimeString() : '-';

      rowsHtml += `
        <tr>
          <td>${idx + 1}</td>
          <td><span class="badge-sev ${sevClass}">${s.severity || 'info'}</span></td>
          <td>
            <strong style="color: var(--text-main); font-family: var(--font-sans);">${escapeHtml(s.ruleName)}</strong>
            ${s.category ? `<div class="text-xs" style="color: var(--text-muted); margin-top: 2px; font-family: var(--font-mono);">${escapeHtml(s.category)}</div>` : ''}
          </td>
          <td>
            <div class="secret-value-box">
              <span class="secret-text font-mono" data-secret="${escapeHtml(s.match)}" data-masked="${escapeHtml(s.masked || '••••••••')}" data-revealed="false">${escapeHtml(s.masked || '••••••••')}</span>
              <button class="secret-toggle-btn" title="Show / Hide raw value">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
              <button class="secret-copy-btn" title="Copy to clipboard">Copy</button>
            </div>
          </td>
          <td>${countBadge}</td>
          <td>${locationsHtml}</td>
          <td class="font-mono text-xs" style="color: var(--text-muted);">${timeStr}</td>
        </tr>
      `;
    });

    secretsTbody.innerHTML = rowsHtml;
  }

  // Event delegation for secrets table interactions
  if (secretsTbody) {
    secretsTbody.addEventListener('click', async (e) => {
      const copyBtn = e.target.closest('.secret-copy-btn');
      if (copyBtn) {
        const box = copyBtn.closest('.secret-value-box');
        const textSpan = box ? box.querySelector('.secret-text') : null;
        if (textSpan && textSpan.dataset.secret) {
          await navigator.clipboard.writeText(textSpan.dataset.secret);
          copyBtn.textContent = 'Copied!';
          setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
        }
        return;
      }

      const toggleBtn = e.target.closest('.secret-toggle-btn');
      if (toggleBtn) {
        const box = toggleBtn.closest('.secret-value-box');
        const textSpan = box ? box.querySelector('.secret-text') : null;
        if (textSpan) {
          const isRevealed = textSpan.dataset.revealed === 'true';
          if (isRevealed) {
            textSpan.textContent = textSpan.dataset.masked;
            textSpan.dataset.revealed = 'false';
          } else {
            textSpan.textContent = textSpan.dataset.secret;
            textSpan.dataset.revealed = 'true';
          }
        }
        return;
      }

      const moreBtn = e.target.closest('.secret-more-toggle');
      if (moreBtn) {
        const extraDiv = moreBtn.previousElementSibling;
        if (extraDiv && extraDiv.classList.contains('secret-locations-extra')) {
          const isExpanded = extraDiv.style.display !== 'none';
          if (isExpanded) {
            extraDiv.style.display = 'none';
            moreBtn.textContent = `+ ${moreBtn.dataset.count} more location(s)`;
          } else {
            extraDiv.style.display = 'flex';
            extraDiv.style.flexDirection = 'column';
            extraDiv.style.gap = '6px';
            moreBtn.textContent = 'Collapse locations';
          }
        }
        return;
      }
    });
  }

  // Global event delegation for compact code context snippet toggles & copy (Secrets & Supply Chain)
  document.addEventListener('click', async (e) => {
    const copySnippetBtn = e.target.closest('.snippet-copy-btn');
    if (copySnippetBtn) {
      const wrap = copySnippetBtn.closest('.secret-context-wrap');
      const snippet = wrap ? wrap.querySelector('.secret-context-snippet') : null;
      if (snippet) {
        const textToCopy = snippet.getAttribute('data-full-text') || snippet.innerText || snippet.textContent || '';
        try {
          await navigator.clipboard.writeText(textToCopy.trim());
          const span = copySnippetBtn.querySelector('span');
          if (span) {
            const oldText = span.textContent;
            span.textContent = 'Copied!';
            setTimeout(() => { span.textContent = oldText; }, 1500);
          }
        } catch (err) {
          console.warn('Failed to copy snippet:', err);
        }
      }
      return;
    }

    const toggleBtn = e.target.closest('.snippet-toggle-btn');
    if (!toggleBtn) return;
    const wrap = toggleBtn.closest('.secret-context-wrap');
    const snippet = wrap ? wrap.querySelector('.secret-context-snippet') : null;
    if (!snippet) return;

    const isCompact = snippet.classList.contains('is-compact');
    const labelSpan = toggleBtn.querySelector('span');
    const icon = toggleBtn.querySelector('.toggle-icon');
    const charCount = toggleBtn.getAttribute('data-chars') || (snippet.textContent ? snippet.textContent.trim().length : 0);

    if (isCompact) {
      snippet.classList.remove('is-compact');
      snippet.classList.add('is-expanded');
      toggleBtn.setAttribute('aria-expanded', 'true');
      if (labelSpan) labelSpan.textContent = 'Collapse context';
      if (icon) icon.innerHTML = '<path d="M18 15l-6-6-6 6"/>';
    } else {
      snippet.classList.add('is-compact');
      snippet.classList.remove('is-expanded');
      toggleBtn.setAttribute('aria-expanded', 'false');
      if (labelSpan) labelSpan.textContent = `View full context (${charCount} chars)`;
      if (icon) icon.innerHTML = '<path d="M6 9l6 6 6-6"/>';
    }
  });

  if (secretsSearch) secretsSearch.addEventListener('input', debouncedRefreshSecrets);
  if (secretsFilterSeverity) secretsFilterSeverity.addEventListener('change', refreshSecretsTable);
  if (secretsFilterSource) secretsFilterSource.addEventListener('change', refreshSecretsTable);

  if (btnExportSecretsJson) {
    btnExportSecretsJson.addEventListener('click', async () => {
      const secrets = await storage.getSecrets();
      if (secrets.length === 0) {
        alert('No secrets found to export.');
        return;
      }
      downloadFile(JSON.stringify(secrets, null, 2), 'crawlizer-secrets.json', 'application/json');
      engine.log('inf', `Exported ${secrets.length} findings to crawlizer-secrets.json`);
    });
  }

  if (btnExportSecretsCsv) {
    btnExportSecretsCsv.addEventListener('click', async () => {
      const secrets = await storage.getSecrets();
      if (secrets.length === 0) {
        alert('No secrets found to export.');
        return;
      }
      let csv = 'Rule,Severity,Category,Secret,LocationCount,SourceURLs\n';
      secrets.forEach(s => {
        const esc = (txt) => `"${(txt || '').toString().replace(/"/g, '""')}"`;
        const sources = Array.isArray(s.sources) && s.sources.length > 0 ? s.sources : (s.sourceUrl ? [{ url: s.sourceUrl }] : []);
        const urlsJoined = sources.map(src => src.url).join('; ');
        csv += `${esc(s.ruleName)},${esc(s.severity)},${esc(s.category)},${esc(s.match)},${sources.length},${esc(urlsJoined)}\n`;
      });
      downloadFile(csv, 'crawlizer-secrets.csv', 'text/csv');
      engine.log('inf', `Exported ${secrets.length} findings to crawlizer-secrets.csv`);
    });
  }

  if (btnCopySecrets) {
    btnCopySecrets.addEventListener('click', async () => {
      const secrets = await storage.getSecrets();
      if (secrets.length === 0) {
        alert('No secrets found to copy.');
        return;
      }
      const text = secrets.map(s => `[${(s.severity || 'INFO').toUpperCase()}] ${s.ruleName}: ${s.match}`).join('\n');
      await navigator.clipboard.writeText(text);
      alert(`Copied ${secrets.length} findings to clipboard!`);
    });
  }

  if (btnClearSecrets) {
    btnClearSecrets.addEventListener('click', async () => {
      if (confirm('Clear all secrets findings?')) {
        await storage.clearSecrets();
        await refreshMetrics();
        await refreshSecretsTable();
        engine.log('inf', 'All secrets cleared from database.');
      }
    });
  }

  // ==========================================
  // Supply Chain & NPM Audit Controller
  // ==========================================
  const btnScanActiveTab = document.getElementById('btn-scan-active-tab');
  const btnSupplyRescan = document.getElementById('btn-supply-rescan');
  const supplyTargetUrl = document.getElementById('supply-target-url');
  const supplyStatusTag = document.getElementById('supply-status-tag');
  const supplyProgressWrap = document.getElementById('supply-progress-wrap');
  const supplyProgressFill = document.getElementById('supply-progress-fill');
  const supplyProgressText = document.getElementById('supply-progress-text');

  const supplyRiskScore = document.getElementById('supply-risk-score');
  const supplyRiskLevelBadge = document.getElementById('supply-risk-level-badge');
  const supplyRiskMeterFill = document.getElementById('supply-risk-meter-fill');
  const supplyStatCritical = document.getElementById('supply-stat-critical');
  const supplyStatCves = document.getElementById('supply-stat-cves');
  const supplyStatSafe = document.getElementById('supply-stat-safe');
  const supplyStatExposed = document.getElementById('supply-stat-exposed');
  const tabSupplyChainBadge = document.getElementById('tab-supply-chain-badge');

  const supplyEcoStrip = document.getElementById('supply-eco-strip');
  const ecoCountNpm = document.getElementById('eco-count-npm');
  const ecoCountPypi = document.getElementById('eco-count-pypi');
  const ecoCountRubygems = document.getElementById('eco-count-rubygems');
  const ecoCountNuget = document.getElementById('eco-count-nuget');
  const ecoCountMaven = document.getElementById('eco-count-maven');
  const ecoCountComposer = document.getElementById('eco-count-composer');
  const ecoCountGolang = document.getElementById('eco-count-golang');
  const ecoCountCrates = document.getElementById('eco-count-crates');

  const btnToggleManualAudit = document.getElementById('btn-toggle-manual-audit');
  const manualAuditBody = document.getElementById('manual-audit-body');
  const manualAuditArrow = document.getElementById('manual-audit-arrow');
  const manualAuditEco = document.getElementById('manual-audit-eco');
  const manualAuditInput = document.getElementById('manual-audit-input');
  const btnRunManualAudit = document.getElementById('btn-run-manual-audit');
  const manualAuditTextarea = document.getElementById('manual-audit-textarea');
  const btnAuditBatch = document.getElementById('btn-audit-batch');
  const btnLoadSampleManifest = document.getElementById('btn-load-sample-manifest');

  const supplySearch = document.getElementById('supply-search');
  const supplyFilterSeverity = document.getElementById('supply-filter-severity');
  const supplyFilterEco = document.getElementById('supply-filter-eco');
  const supplyCountLabel = document.getElementById('supply-count-label');
  const supplyTbody = document.getElementById('supply-tbody');

  const btnExportSupplyHtml = document.getElementById('btn-export-supply-html');
  const btnExportSupplyJson = document.getElementById('btn-export-supply-json');
  const btnExportSupplyCsv = document.getElementById('btn-export-supply-csv');
  const btnCopySupplyBad = document.getElementById('btn-copy-supply-bad');
  const btnClearSupply = document.getElementById('btn-clear-supply');

  const supplyState = {
    targetUrl: '',
    packages: [],
    exposedFiles: [],
    activeTabId: null,
    pollTimer: null,
    pollAttempts: 0,
    filters: {
      search: '',
      severity: 'all',
      eco: 'all'
    }
  };

  function calculateSupplyStats() {
    const packages = supplyState.packages || [];
    const exposedFiles = supplyState.exposedFiles || [];

    let critical = 0;
    let safe = 0;
    let errors = 0;
    let advisories = 0;

    const ecosystems = { npm: 0, pypi: 0, rubygems: 0, nuget: 0, maven: 0, composer: 0, golang: 0, crates: 0 };

    packages.forEach(pkg => {
      if (!pkg) return;
      const eco = (pkg.ecosystem || 'npm').toLowerCase();
      if (ecosystems.hasOwnProperty(eco)) ecosystems[eco]++;

      const advCount = Number(pkg.advisoriesCount || (Array.isArray(pkg.advisories) ? pkg.advisories.length : 0));
      advisories += advCount;

      if (pkg.error) {
        errors++;
      } else if (pkg.isUnregistered) {
        critical++;
      } else {
        safe++;
      }
    });

    const exposedCount = exposedFiles.length;
    // Dominant signals: Unregistered packages (dependency confusion) = 25 pts each, CVEs = 6 pts each, exposed files = 4 pts each
    const score = Math.min(100, (critical * 25) + (advisories * 6) + (exposedCount * 4));

    return {
      score,
      critical,
      safe,
      errors,
      advisories,
      exposedCount,
      ecosystems,
      totalFindings: packages.length + exposedCount
    };
  }

  function updateSupplyStatsUI() {
    const stats = calculateSupplyStats();

    if (supplyRiskScore) supplyRiskScore.textContent = stats.score;
    if (supplyRiskMeterFill) {
      supplyRiskMeterFill.style.width = `${stats.score}%`;
      if (stats.score >= 70 || stats.critical > 0) {
        supplyRiskMeterFill.style.background = 'var(--neon-red)';
      } else if (stats.score >= 40 || stats.advisories > 0) {
        supplyRiskMeterFill.style.background = '#f97316';
      } else {
        supplyRiskMeterFill.style.background = 'var(--neon-green)';
      }
    }

    if (supplyRiskLevelBadge) {
      if (stats.critical > 0 || stats.score >= 75) {
        supplyRiskLevelBadge.textContent = 'CRITICAL';
        supplyRiskLevelBadge.className = 'badge-risk-level level-critical font-mono';
      } else if (stats.advisories > 0 || stats.score >= 45) {
        supplyRiskLevelBadge.textContent = 'HIGH RISK';
        supplyRiskLevelBadge.className = 'badge-risk-level level-high font-mono';
      } else if (stats.score > 0) {
        supplyRiskLevelBadge.textContent = 'MEDIUM';
        supplyRiskLevelBadge.className = 'badge-risk-level level-high font-mono';
      } else {
        supplyRiskLevelBadge.textContent = 'SAFE';
        supplyRiskLevelBadge.className = 'badge-risk-level level-low font-mono';
      }
    }

    if (supplyStatCritical) supplyStatCritical.textContent = stats.critical;
    if (supplyStatCves) supplyStatCves.textContent = stats.advisories;
    if (supplyStatSafe) supplyStatSafe.textContent = stats.safe;
    if (supplyStatExposed) supplyStatExposed.textContent = stats.exposedCount;

    if (tabSupplyChainBadge) {
      const threatCount = stats.critical + stats.advisories;
      tabSupplyChainBadge.textContent = threatCount > 0 ? threatCount : stats.totalFindings;
      if (threatCount > 0) {
        tabSupplyChainBadge.className = 'nav-badge badge-magenta';
      } else {
        tabSupplyChainBadge.className = 'nav-badge badge-cyan';
      }
    }

    // Update ecosystem breakdown counts
    if (ecoCountNpm) ecoCountNpm.textContent = stats.ecosystems.npm;
    if (ecoCountPypi) ecoCountPypi.textContent = stats.ecosystems.pypi;
    if (ecoCountRubygems) ecoCountRubygems.textContent = stats.ecosystems.rubygems;
    if (ecoCountNuget) ecoCountNuget.textContent = stats.ecosystems.nuget;
    if (ecoCountMaven) ecoCountMaven.textContent = stats.ecosystems.maven;
    if (ecoCountComposer) ecoCountComposer.textContent = stats.ecosystems.composer;
    if (ecoCountGolang) ecoCountGolang.textContent = stats.ecosystems.golang;
    if (ecoCountCrates) ecoCountCrates.textContent = stats.ecosystems.crates;
  }

  function getFilteredSupplyFindings() {
    const q = supplyState.filters.search.toLowerCase().trim();
    const sev = supplyState.filters.severity;
    const ecoFilter = supplyState.filters.eco;

    const filteredPackages = supplyState.packages.filter(pkg => {
      if (!pkg) return false;
      const name = (pkg.name || '').toLowerCase();
      const version = (pkg.version || '').toLowerCase();
      const eco = (pkg.ecosystem || 'npm').toLowerCase();
      const advCount = Number(pkg.advisoriesCount || (Array.isArray(pkg.advisories) ? pkg.advisories.length : 0));

      // Ecosystem filter
      if (ecoFilter !== 'all' && eco !== ecoFilter) return false;

      // Severity filter
      if (sev === 'critical' && !pkg.isUnregistered) return false;
      if (sev === 'cve' && advCount === 0) return false;
      if (sev === 'safe' && (pkg.isUnregistered || advCount > 0 || pkg.error)) return false;
      if (sev === 'error' && !pkg.error) return false;
      if (sev === 'exposed') return false; // Handled in exposed files

      // Search match
      if (q) {
        const matchesName = name.includes(q);
        const matchesVer = version.includes(q);
        const matchesAdv = Array.isArray(pkg.advisories) && pkg.advisories.some(a => (a.id || '').toLowerCase().includes(q) || (a.summary || '').toLowerCase().includes(q));
        const matchesSource = Array.isArray(pkg.sources) && pkg.sources.some(s => (s.url || '').toLowerCase().includes(q));
        if (!matchesName && !matchesVer && !matchesAdv && !matchesSource) return false;
      }

      return true;
    });

    const filteredExposed = (sev === 'all' || sev === 'exposed') ? supplyState.exposedFiles.filter(file => {
      if (!file) return false;
      if (ecoFilter !== 'all') return false;
      const path = (file.path || '').toLowerCase();
      if (q && !path.includes(q)) return false;
      return true;
    }) : [];

    return { filteredPackages, filteredExposed };
  }

  function renderSupplyTable() {
    if (!supplyTbody) return;

    const { filteredPackages, filteredExposed } = getFilteredSupplyFindings();
    const totalCount = filteredPackages.length + filteredExposed.length;

    if (supplyCountLabel) {
      supplyCountLabel.textContent = `${totalCount} finding${totalCount === 1 ? '' : 's'}`;
    }

    if (totalCount === 0) {
      if (supplyState.packages.length === 0 && supplyState.exposedFiles.length === 0) {
        supplyTbody.innerHTML = `
          <tr>
            <td colspan="8" class="empty-state">
              No supply chain findings yet. Click <strong>"Audit Active Tab"</strong> or paste packages into the audit console above!
            </td>
          </tr>
        `;
      } else {
        supplyTbody.innerHTML = `
          <tr>
            <td colspan="8" class="empty-state">
              No findings match your active search or severity filter.
            </td>
          </tr>
        `;
      }
      return;
    }

    let rowsHtml = '';
    let rowIdx = 1;

    // 1. Exposed Configuration Files
    filteredExposed.forEach(file => {
      const path = escapeHtml(file.path || 'unknown');
      const status = file.status || 200;
      const contentType = file.contentType || 'text/plain';
      const risk = (file.risk || 'MEDIUM').toUpperCase();

      rowsHtml += `
        <tr class="supply-finding-row" style="background: rgba(0, 240, 255, 0.03);">
          <td class="font-mono" style="color: var(--text-muted);">${rowIdx++}</td>
          <td><span class="eco-pill eco-pill-npm">CONFIG</span></td>
          <td>
            <div class="pkg-name-cell">
              <span class="pkg-name-text glow-cyan" style="font-weight: 700;">${path}</span>
              <span class="pkg-ver-text">HTTP ${status} · ${contentType}</span>
            </div>
          </td>
          <td>
            <span class="badge-risk-high">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              EXPOSED FILE
            </span>
          </td>
          <td>
            <span class="font-mono" style="font-size: 11px; color: var(--text-muted);">Publicly accessible manifest/secret file</span>
          </td>
          <td>
            <span class="font-mono" style="font-size: 11px; color: var(--neon-cyan);">High Exposure</span>
          </td>
          <td>
            <div class="secret-locations-list">
              ${renderSupplyChainSourceItem({ url: file.url || file.sourceUrl || file.path, type: 'config', context: file.context || '' })}
            </div>
          </td>
          <td>
            <div class="action-btn-group">
              <button class="btn btn-glass btn-sm btn-copy-text" data-copy="${escapeHtml(file.url || path)}" title="Copy File URL">Copy</button>
            </div>
          </td>
        </tr>
      `;
    });

    // 2. Analyzed Packages
    filteredPackages.forEach(pkg => {
      const eco = (pkg.ecosystem || 'npm').toLowerCase();
      const name = escapeHtml(pkg.name || 'unknown');
      const version = pkg.version && pkg.version !== '?' ? `@${escapeHtml(pkg.version)}` : '';
      const isUnreg = Boolean(pkg.isUnregistered);
      const advCount = Number(pkg.advisoriesCount || (Array.isArray(pkg.advisories) ? pkg.advisories.length : 0));
      const downloads = pkg.weeklyDownloads != null ? formatNumber(pkg.weeklyDownloads) : '—';

      // Status Badge
      let statusBadge = '';
      if (pkg.error) {
        statusBadge = `<span class="badge-risk-error font-mono">ERROR: ${escapeHtml(pkg.error)}</span>`;
      } else if (isUnreg) {
        statusBadge = `
          <span class="badge-risk-critical">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            CONFUSION (UNREG)
          </span>
        `;
      } else if (advCount > 0) {
        statusBadge = `
          <span class="badge-risk-high">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            ${advCount} VULNERABLE
          </span>
        `;
      } else {
        statusBadge = `
          <span class="badge-risk-safe">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            SAFE
          </span>
        `;
      }

      // Advisories Cell
      let advMarkup = '';
      if (Array.isArray(pkg.advisories) && pkg.advisories.length > 0) {
        advMarkup = `<div class="advisories-cell">` + pkg.advisories.slice(0, 3).map(adv => {
          const sevClass = `adv-sev-${(adv.severity || 'MEDIUM').toLowerCase()}`;
          const advUrl = `https://osv.dev/vulnerability/${encodeURIComponent(adv.id)}`;
          return `
            <a href="${advUrl}" target="_blank" rel="noreferrer" class="adv-badge" title="${escapeHtml(adv.summary || adv.id)}">
              <span class="adv-sev-pill ${sevClass}">${escapeHtml(adv.severity || 'MED')}</span>
              <span>${escapeHtml(adv.id)}</span>
            </a>
          `;
        }).join('') + (pkg.advisories.length > 3 ? `<span class="font-mono" style="font-size: 10px; color: var(--text-muted);">+${pkg.advisories.length - 3} more</span>` : '') + `</div>`;
      } else if (isUnreg) {
        advMarkup = `<span class="font-mono threat-text" style="font-size: 11px;">⚠️ Public claimable namespace (Critical)</span>`;
      } else {
        advMarkup = `<span class="font-mono" style="font-size: 11px; color: var(--neon-green);">✓ No active OSV CVEs</span>`;
      }

      // Health / Downloads Display
      let dlMarkup = '';
      if (isUnreg) {
        dlMarkup = `<span class="health-downloads threat-text">Unregistered</span>`;
      } else if (pkg.weeklyDownloads != null && pkg.weeklyDownloads > 0) {
        dlMarkup = `<span class="health-downloads">${formatNumber(pkg.weeklyDownloads)} dl/wk</span>`;
      } else if (pkg.weeklyDownloads === 0) {
        dlMarkup = `<span class="health-downloads" style="color: var(--text-muted);">Active</span>`;
      } else {
        dlMarkup = `<span class="health-downloads" style="color: var(--text-muted);">—</span>`;
      }

      // Detection Sources Context (Showing Code Snippets Matching Secrets Tab)
      let sourcesMarkup = '—';
      const rawSources = Array.isArray(pkg.sources) && pkg.sources.length > 0
        ? pkg.sources
        : (pkg.sourceUrl ? [{ url: pkg.sourceUrl, type: pkg.sourceType || 'js-bundle', context: pkg.context || '' }] : []);

      const sources = rawSources.map(s => {
        if (!s.context && pkg.context) {
          return { ...s, context: pkg.context };
        }
        return s;
      });

      if (sources.length > 0) {
        const initialSources = sources.slice(0, 2);
        const remainingSources = sources.slice(2);

        let locationsHtml = `<div class="secret-locations-list">`;
        initialSources.forEach(src => {
          locationsHtml += renderSupplyChainSourceItem(src);
        });

        if (remainingSources.length > 0) {
          locationsHtml += `<div class="secret-locations-extra" style="display: none;">`;
          remainingSources.forEach(src => {
            locationsHtml += renderSupplyChainSourceItem(src);
          });
          locationsHtml += `</div>`;
          locationsHtml += `<button class="btn btn-glass supply-more-toggle" style="padding: 2px 8px; font-size: 10px; align-self: flex-start; margin-top: 4px;" data-count="${remainingSources.length}">+ ${remainingSources.length} more location(s)</button>`;
        }
        locationsHtml += `</div>`;
        sourcesMarkup = locationsHtml;
      } else if (pkg.context) {
        sourcesMarkup = `
          <div class="secret-locations-list">
            <div class="secret-location-item">
              ${renderCodeContextBlock(pkg.context)}
            </div>
          </div>
        `;
      }

      // Registry Link
      let regLink = '#';
      if (eco === 'npm') regLink = `https://www.npmjs.com/package/${encodeURIComponent(pkg.name)}`;
      else if (eco === 'pypi') regLink = `https://pypi.org/project/${encodeURIComponent(pkg.name)}/`;
      else if (eco === 'rubygems') regLink = `https://rubygems.org/gems/${encodeURIComponent(pkg.name)}`;
      else if (eco === 'crates') regLink = `https://crates.io/crates/${encodeURIComponent(pkg.name)}`;
      else if (eco === 'composer') regLink = `https://packagist.org/packages/${encodeURIComponent(pkg.name)}`;

      rowsHtml += `
        <tr class="supply-finding-row ${isUnreg ? 'confusion-row' : ''}">
          <td class="font-mono" style="color: var(--text-muted);">${rowIdx++}</td>
          <td><span class="eco-pill eco-pill-${eco}">${eco}</span></td>
          <td>
            <div class="pkg-name-cell">
              <span class="pkg-name-text ${isUnreg ? 'threat-text' : ''}">${name}</span>
              ${version ? `<span class="pkg-ver-text">${version}</span>` : ''}
            </div>
          </td>
          <td>${statusBadge}</td>
          <td>${advMarkup}</td>
          <td>
            <div class="pkg-health-cell">
              ${dlMarkup}
              ${pkg.riskReasons && pkg.riskReasons.length > 0 ? `<span class="health-notes">${escapeHtml(pkg.riskReasons[0])}</span>` : ''}
            </div>
          </td>
          <td>${sourcesMarkup}</td>
          <td>
            <div class="action-btn-group">
              <button class="btn btn-glass btn-sm btn-copy-text" data-copy="${name}" title="Copy Package Name">Copy</button>
              ${regLink !== '#' ? `<a href="${regLink}" target="_blank" rel="noreferrer" class="btn btn-glass btn-sm" title="View in Public Registry">↗</a>` : ''}
            </div>
          </td>
        </tr>
      `;
    });

    supplyTbody.innerHTML = rowsHtml;

    // Attach copy button listeners
    supplyTbody.querySelectorAll('.btn-copy-text').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const text = btn.getAttribute('data-copy');
        if (text) {
          await navigator.clipboard.writeText(text);
          const orig = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(() => { btn.textContent = orig; }, 1200);
        }
      });
    });

    // Attach more locations toggle listeners
    supplyTbody.querySelectorAll('.supply-more-toggle').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const extraDiv = btn.previousElementSibling;
        if (extraDiv && extraDiv.classList.contains('secret-locations-extra')) {
          const isExpanded = extraDiv.style.display !== 'none';
          if (isExpanded) {
            extraDiv.style.display = 'none';
            btn.textContent = `+ ${btn.dataset.count} more location(s)`;
          } else {
            extraDiv.style.display = 'flex';
            extraDiv.style.flexDirection = 'column';
            extraDiv.style.gap = '6px';
            btn.textContent = 'Collapse locations';
          }
        }
      });
    });
  }

  let refreshSupplyChainDebounce = null;
  function debouncedRefreshSupplyChain() {
    clearTimeout(refreshSupplyChainDebounce);
    refreshSupplyChainDebounce = setTimeout(refreshSupplyChainTable, 250);
  }

  async function refreshSupplyChainTable() {
    if (!supplyTbody) return;
    try {
      const allFindings = await storage.getSupplyChainFindings(supplyState.filters);
      supplyState.packages = allFindings.filter(f => f.type === 'package');
      supplyState.exposedFiles = allFindings.filter(f => f.type === 'exposed-file');
      updateSupplyStatsUI();
      renderSupplyTable();
    } catch (e) {
      console.warn('refreshSupplyChainTable error:', e);
    }
  }

  function refreshSupplyChainView() {
    refreshSupplyChainTable();
  }

  // Active Tab Audit (Pattern-based inspection matching secrets finder)
  async function scanActiveTabSupplyChain(forceRescan = false) {
    if (supplyStatusTag) {
      supplyStatusTag.textContent = 'SCANNING...';
      supplyStatusTag.className = 'supply-status-tag active';
    }
    if (supplyProgressWrap) {
      supplyProgressWrap.style.display = 'flex';
      if (supplyProgressFill) supplyProgressFill.style.width = '20%';
      if (supplyProgressText) supplyProgressText.textContent = 'Inspecting active tab DOM & scripts...';
    }

    // LOCAL SERVER MODE: Dispatch to Chrome Extension Agent via WebSocket
    if (storage && storage.isLocalServer && storage.isLocalServer()) {
      if (supplyProgressText) supplyProgressText.textContent = 'Instructing Chrome Extension Agent to audit current active browser tab...';
      try {
        const res = await fetch('/api/crawl/active-tab', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          if (supplyProgressText) supplyProgressText.textContent = 'Chrome Agent auditing tab and streaming findings back...';
        } else {
          if (supplyStatusTag) { supplyStatusTag.textContent = 'AGENT OFFLINE'; supplyStatusTag.className = 'supply-status-tag'; }
          if (supplyProgressText) supplyProgressText.textContent = 'Chrome Extension Agent is standing by. Click the Crawlizer extension icon in your toolbar to activate.';
        }
      } catch (e) {
        if (supplyStatusTag) { supplyStatusTag.textContent = 'SERVER ERROR'; supplyStatusTag.className = 'supply-status-tag'; }
      }
      setTimeout(() => { if (supplyProgressWrap) supplyProgressWrap.style.display = 'none'; }, 4000);
      return;
    }

    try {
      if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) {
        if (supplyStatusTag) { supplyStatusTag.textContent = 'STANDALONE'; supplyStatusTag.className = 'supply-status-tag'; }
        if (supplyProgressText) supplyProgressText.textContent = 'Please use the Manual Audit section below or connect the Crawlizer extension.';
        setTimeout(() => { if (supplyProgressWrap) supplyProgressWrap.style.display = 'none'; }, 4000);
        return;
      }

      const restrictedPrefixes = ['chrome://', 'edge://', 'chrome-extension://', 'about:', 'view-source:'];
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      let tab = tabs[0];

      // If active tab is the dashboard itself or restricted, find a legitimate target web tab!
      if (!tab || restrictedPrefixes.some(p => (tab.url || '').startsWith(p))) {
        if (engine && engine.crawlerTabId) {
          try {
            const cTab = await chrome.tabs.get(engine.crawlerTabId);
            if (cTab && cTab.url && !restrictedPrefixes.some(p => cTab.url.startsWith(p))) {
              tab = cTab;
            }
          } catch {}
        }

        if (!tab || restrictedPrefixes.some(p => (tab.url || '').startsWith(p))) {
          const allTabs = await chrome.tabs.query({});
          const webTabs = allTabs.filter(t => t.url && /^https?:\/\//i.test(t.url));
          if (webTabs.length > 0) {
            tab = webTabs.find(t => t.active) || webTabs[webTabs.length - 1];
          }
        }
      }

      if (!tab || restrictedPrefixes.some(p => (tab.url || '').startsWith(p))) {
        if (supplyStatusTag) { supplyStatusTag.textContent = 'NO WEB TAB'; supplyStatusTag.className = 'supply-status-tag'; }
        if (supplyProgressText) supplyProgressText.textContent = 'No target web tab found. Please open your target website in a browser tab or use the Manual Audit section below.';
        setTimeout(() => { if (supplyProgressWrap) supplyProgressWrap.style.display = 'none'; }, 4000);
        return;
      }

      supplyState.activeTabId = tab.id;
      supplyState.targetUrl = tab.url || 'unknown';
      if (supplyTargetUrl) supplyTargetUrl.textContent = tab.url || '—';

      // Standalone tab extraction function (runs in tab context)
      function inTabDomExtractor() {
        const scripts = [];
        document.querySelectorAll('script').forEach(el => {
          scripts.push({
            src: el.src || el.getAttribute('src') || '',
            content: el.textContent || '',
            type: (el.getAttribute('type') || '').toLowerCase()
          });
        });
        return {
          url: window.location.href,
          html: document.documentElement ? document.documentElement.outerHTML.slice(0, 2000000) : '',
          scripts
        };
      }

      let extractedData = null;
      if (chrome.scripting && chrome.scripting.executeScript) {
        try {
          const res = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: inTabDomExtractor
          });
          if (res && res[0] && res[0].result) {
            extractedData = res[0].result;
          }
        } catch (e) {
          console.warn('Direct tab script execution failed:', e);
        }
      }

      // Fallback: fetch page directly if tab script execution was blocked
      if (!extractedData) {
        try {
          const pageRes = await fetch(tab.url);
          if (pageRes.ok) {
            extractedData = {
              url: tab.url,
              html: await pageRes.text(),
              scripts: []
            };
          }
        } catch (e) {}
      }

      if (!extractedData) {
        throw new Error('Unable to inspect page content in active tab.');
      }

      if (supplyProgressFill) supplyProgressFill.style.width = '45%';
      if (supplyProgressText) supplyProgressText.textContent = 'Pattern scanning packages & dependencies...';

      const scanner = window.katanaSupplyChainScanner || (typeof KatanaSupplyChainScanner !== 'undefined' ? new KatanaSupplyChainScanner() : null);
      if (!scanner) {
        throw new Error('KatanaSupplyChainScanner engine not loaded.');
      }

      const allDiscovered = [];

      // 1. Scan page HTML
      if (extractedData.html) {
        allDiscovered.push(...scanner.scan(extractedData.html, extractedData.url, 'html'));
      }

      // 2. Scan inline scripts & JSON blobs
      const scriptsToFetch = [];
      for (const s of extractedData.scripts || []) {
        if (s.content) {
          const sType = s.type.includes('json') || s.type === 'importmap' ? 'json' : 'rendered-js';
          allDiscovered.push(...scanner.scan(s.content, extractedData.url, sType));
        }
        if (s.src && /^https?:\/\//i.test(s.src)) {
          // Scan script URL itself for CDN packages (jsdelivr, unpkg, cdnjs, etc.)
          allDiscovered.push(...scanner.scan(s.src, s.src, 'cdn-url'));
          scriptsToFetch.push(s.src);
        }
      }

      // 3. Fast-fetch top external JS scripts (up to 12) for deep package extraction
      if (scriptsToFetch.length > 0) {
        if (supplyProgressFill) supplyProgressFill.style.width = '65%';
        if (supplyProgressText) supplyProgressText.textContent = `Scanning ${Math.min(12, scriptsToFetch.length)} external bundles...`;

        const scriptsSample = scriptsToFetch.slice(0, 12);
        await Promise.allSettled(scriptsSample.map(async (scriptUrl) => {
          try {
            const resp = await fetch(scriptUrl);
            if (resp && resp.ok) {
              const jsContent = await resp.text();
              allDiscovered.push(...scanner.scan(jsContent, scriptUrl, 'js-bundle'));
            }
          } catch (e) {}
        }));
      }

      if (supplyProgressFill) supplyProgressFill.style.width = '85%';
      if (supplyProgressText) supplyProgressText.textContent = 'Querying OSV.dev CVE advisories & registries...';

      // Save initial pattern discoveries immediately
      if (allDiscovered.length > 0) {
        await storage.saveSupplyChainFindings(allDiscovered);
        await refreshSupplyChainTable();
      }

      // 4. Background evaluate OSV CVE advisories & dependency confusion
      scanner.queueForEvaluation(allDiscovered, async (evaluated) => {
        if (!evaluated) return;
        await storage.saveSupplyChainFindings([evaluated]);
        debouncedRefreshSupplyChain();
      });

      // Update UI state
      supplyState.packages = allDiscovered.filter(f => f.type === 'package');
      supplyState.exposedFiles = allDiscovered.filter(f => f.type === 'exposed-file');
      updateSupplyStatsUI();
      renderSupplyTable();

      finishSupplyAudit(true);
    } catch (e) {
      console.error('scanActiveTabSupplyChain error:', e);
      if (supplyStatusTag) { supplyStatusTag.textContent = 'ERROR'; supplyStatusTag.className = 'supply-status-tag threat'; }
      if (supplyProgressText) supplyProgressText.textContent = `Audit error: ${e.message}`;
    }
  }

  function finishSupplyAudit(isSuccess) {
    clearInterval(supplyState.pollTimer);
    if (supplyProgressFill) supplyProgressFill.style.width = '100%';
    const stats = calculateSupplyStats();

    if (supplyStatusTag) {
      if (stats.critical > 0) {
        supplyStatusTag.textContent = 'THREAT DETECTED';
        supplyStatusTag.className = 'supply-status-tag threat';
      } else if (stats.advisories > 0) {
        supplyStatusTag.textContent = 'VULNERABLE';
        supplyStatusTag.className = 'supply-status-tag threat';
      } else {
        supplyStatusTag.textContent = 'AUDIT COMPLETE';
        supplyStatusTag.className = 'supply-status-tag clean';
      }
    }

    if (supplyProgressText) {
      supplyProgressText.textContent = `Completed: ${stats.totalFindings} total findings (${stats.critical} unregistered, ${stats.advisories} CVEs).`;
    }

    setTimeout(() => {
      if (supplyProgressWrap) supplyProgressWrap.style.display = 'none';
    }, 3000);

    updateSupplyStatsUI();
    renderSupplyTable();
  }

  // Universal package analysis (works on Local Server & Chrome Extension)
  async function analyzePackageUniversal(name, ecosystem = 'npm', version = '', sources = [{ url: 'Manual Console Audit' }]) {
    // 1. If running on local server, use /api/supply-chain/analyze
    if (storage && storage.isLocalServer && storage.isLocalServer()) {
      try {
        const res = await fetch('/api/supply-chain/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, ecosystem, version })
        });
        if (res.ok) {
          const data = await res.json();
          return {
            ...data,
            sources,
            type: 'package',
            discoveredAt: Date.now()
          };
        }
      } catch (e) {
        console.warn('Local server analyzePackage error:', e);
      }
    }

    // 2. If running inside Chrome Extension, use runtime message
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      return await chrome.runtime.sendMessage({
        action: 'analyzePackage',
        name,
        ecosystem,
        version,
        sources,
        options: { osvLookup: true }
      });
    }

    return null;
  }

  // On-Demand Package / Manifest Audit
  async function runManualPackageAudit(rawInput, eco = 'npm') {
    const input = (rawInput || '').trim();
    if (!input) return;

    // Check version syntax: name@1.2.3 or name
    let name = input;
    let version = '';
    if (input.includes('@') && !input.startsWith('@')) {
      const parts = input.split('@');
      name = parts[0];
      version = parts[1];
    } else if (input.startsWith('@') && input.lastIndexOf('@') > 0) {
      const atIdx = input.lastIndexOf('@');
      name = input.substring(0, atIdx);
      version = input.substring(atIdx + 1);
    }

    if (btnRunManualAudit) {
      btnRunManualAudit.disabled = true;
      btnRunManualAudit.textContent = 'Analyzing...';
    }

    try {
      const analysis = await analyzePackageUniversal(name, eco, version, [{ url: 'Manual Console Audit' }]);

      if (analysis) {
        await storage.saveSupplyChainFindings([analysis]);
        await refreshSupplyChainTable();
        await refreshMetrics();
        engine.log('inf', `Supply chain analysis completed for ${name}: ${analysis.isUnregistered ? 'UNREGISTERED/MISSING' : 'SAFE'} (${analysis.advisoriesCount || 0} CVEs)`);
      } else {
        alert(`Could not analyze package ${name}. Ensure local server or Chrome extension is active.`);
      }
    } catch (e) {
      console.error('Manual package audit failed:', e);
      alert(`Package audit failed: ${e.message}`);
    } finally {
      if (btnRunManualAudit) {
        btnRunManualAudit.disabled = false;
        btnRunManualAudit.textContent = 'Audit Package';
      }
    }
  }

  async function runBatchManifestAudit(rawText) {
    if (!rawText || !rawText.trim()) {
      alert('Please enter or paste package names or a manifest file.');
      return;
    }

    const trimmed = rawText.trim();
    const pkgList = []; // { name, version, eco }
    let detectedEco = (manualAuditEco && manualAuditEco.value) || 'npm';

    // Try parsing as package.json
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const parsed = JSON.parse(trimmed);
        detectedEco = 'npm';
        const allDeps = {
          ...(parsed.dependencies || {}),
          ...(parsed.devDependencies || {}),
          ...(parsed.peerDependencies || {}),
          ...(parsed.optionalDependencies || {})
        };
        for (const [name, ver] of Object.entries(allDeps)) {
          const cleanVer = String(ver).replace(/^[\^~>=<]+/, '');
          pkgList.push({ name, version: cleanVer, eco: 'npm' });
        }
      } catch (e) {
        // Fall back to line-by-line
      }
    }

    // If not JSON, parse line-by-line (requirements.txt or raw list)
    if (pkgList.length === 0) {
      const lines = trimmed.split(/\r?\n/);
      for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;

        // Python requirements.txt: pkg==1.0.0, pkg>=2.0
        if (line.includes('==') || line.includes('>=') || line.includes('~=')) {
          detectedEco = 'pypi';
          const [n, v] = line.split(/[=><~]+/);
          if (n) pkgList.push({ name: n.trim(), version: (v || '').trim(), eco: 'pypi' });
        } else if (line.includes('@') && !line.startsWith('@')) {
          const [n, v] = line.split('@');
          pkgList.push({ name: n.trim(), version: (v || '').trim(), eco: detectedEco });
        } else {
          pkgList.push({ name: line.trim(), version: '', eco: detectedEco });
        }
      }
    }

    if (pkgList.length === 0) {
      alert('No valid packages parsed from input.');
      return;
    }

    if (btnAuditBatch) {
      btnAuditBatch.disabled = true;
      btnAuditBatch.textContent = `Auditing ${pkgList.length} packages...`;
    }

    engine.log('inf', `Beginning batch supply chain analysis of ${pkgList.length} packages...`);

    let done = 0;
    const batchResults = [];
    for (const item of pkgList) {
      try {
        const analysis = await analyzePackageUniversal(item.name, item.eco, item.version, [{ url: 'Batch Manifest Audit' }]);

        if (analysis) {
          batchResults.push(analysis);
        }
      } catch (err) {
        console.warn(`Failed to audit ${item.name}:`, err);
      }
      done++;
      if (btnAuditBatch) btnAuditBatch.textContent = `Audited ${done}/${pkgList.length}...`;
    }

    if (batchResults.length > 0) {
      await storage.saveSupplyChainFindings(batchResults);
      await refreshSupplyChainTable();
      await refreshMetrics();
    }

    if (btnAuditBatch) {
      btnAuditBatch.disabled = false;
      btnAuditBatch.textContent = 'Audit Batch Manifest';
    }

    engine.log('inf', `Batch supply chain audit completed for ${pkgList.length} packages.`);
  }

  // HTML Report Generator
  function generateSupplyChainHtmlReport() {
    const stats = calculateSupplyStats();
    const generatedAt = new Date().toLocaleString();
    const target = supplyState.targetUrl || 'Crawlizer Standalone Audit';

    let pkgRows = '';
    supplyState.packages.forEach((pkg, i) => {
      const advCount = Number(pkg.advisoriesCount || (Array.isArray(pkg.advisories) ? pkg.advisories.length : 0));
      const statusText = pkg.isUnregistered ? 'MISSING / DEPENDENCY CONFUSION' : (advCount > 0 ? `${advCount} CVEs` : 'SAFE');
      const statusColor = pkg.isUnregistered ? '#ff3366' : (advCount > 0 ? '#f97316' : '#00ff88');
      const advisoriesList = Array.isArray(pkg.advisories) ? pkg.advisories.map(a => `${a.id} (${a.severity || 'MED'})`).join(', ') : 'None';

      pkgRows += `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">
          <td style="padding: 10px; font-family: monospace;">${i + 1}</td>
          <td style="padding: 10px; font-family: monospace; text-transform: uppercase;">${escapeHtml(pkg.ecosystem || 'npm')}</td>
          <td style="padding: 10px; font-family: monospace; font-weight: bold;">${escapeHtml(pkg.name)}${pkg.version ? `@${escapeHtml(pkg.version)}` : ''}</td>
          <td style="padding: 10px; font-family: monospace; color: ${statusColor}; font-weight: bold;">${statusText}</td>
          <td style="padding: 10px; font-family: monospace; font-size: 11px;">${escapeHtml(advisoriesList)}</td>
          <td style="padding: 10px; font-family: monospace;">${pkg.weeklyDownloads != null ? formatNumber(pkg.weeklyDownloads) : '—'}</td>
        </tr>
      `;
    });

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Crawlizer Supply Chain Security Report</title>
  <style>
    body { margin: 0; padding: 32px; background: #0a0e14; color: #d0d7de; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
    .container { max-width: 1100px; margin: 0 auto; background: #101622; border: 1px solid #1f293d; border-radius: 12px; padding: 28px; box-shadow: 0 16px 48px rgba(0,0,0,0.7); }
    h1 { margin: 0 0 6px; color: #00f0ff; letter-spacing: -0.5px; }
    .sub { color: #8b949e; font-size: 13px; margin-bottom: 20px; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 20px 0; }
    .card { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 14px; }
    .card-val { font-size: 28px; font-weight: bold; font-family: monospace; margin: 0; }
    .card-lbl { font-size: 11px; text-transform: uppercase; color: #8b949e; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 24px; }
    th { text-align: left; padding: 10px; border-bottom: 2px solid rgba(255,255,255,0.15); color: #00f0ff; font-size: 12px; text-transform: uppercase; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Crawlizer — Supply Chain & NPM Security Audit</h1>
    <div class="sub">Target: ${escapeHtml(target)} · Generated: ${escapeHtml(generatedAt)}</div>
    <div class="stats-grid">
      <div class="card"><div class="card-val" style="color: #00f0ff;">${stats.score}/100</div><div class="card-lbl">Risk Score</div></div>
      <div class="card"><div class="card-val" style="color: #ff3366;">${stats.critical}</div><div class="card-lbl">Dependency Confusion (Missing)</div></div>
      <div class="card"><div class="card-val" style="color: #ff2bd6;">${stats.advisories}</div><div class="card-lbl">OSV CVE / GHSA Advisories</div></div>
      <div class="card"><div class="card-val" style="color: #00ff88;">${stats.safe}</div><div class="card-lbl">Safe Registered Packages</div></div>
    </div>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Ecosystem</th>
          <th>Package Name</th>
          <th>Status / Risk</th>
          <th>OSV Advisories</th>
          <th>Weekly Downloads</th>
        </tr>
      </thead>
      <tbody>
        ${pkgRows || '<tr><td colspan="6" style="padding: 20px; text-align: center; color: #8b949e;">No packages evaluated.</td></tr>'}
      </tbody>
    </table>
  </div>
</body>
</html>`;
  }

  // Bind Event Listeners for Supply Chain Tab
  if (btnScanActiveTab) {
    btnScanActiveTab.addEventListener('click', () => scanActiveTabSupplyChain(true));
  }

  if (btnSupplyRescan) {
    btnSupplyRescan.addEventListener('click', () => scanActiveTabSupplyChain(true));
  }

  if (btnToggleManualAudit && manualAuditBody) {
    btnToggleManualAudit.addEventListener('click', () => {
      const isHidden = manualAuditBody.style.display === 'none';
      manualAuditBody.style.display = isHidden ? 'block' : 'none';
      if (manualAuditArrow) manualAuditArrow.classList.toggle('open', isHidden);
    });
  }

  if (btnRunManualAudit && manualAuditInput) {
    btnRunManualAudit.addEventListener('click', () => {
      const pkg = manualAuditInput.value.trim();
      const eco = (manualAuditEco && manualAuditEco.value) || 'npm';
      if (pkg) {
        runManualPackageAudit(pkg, eco);
      }
    });

    manualAuditInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        btnRunManualAudit.click();
      }
    });
  }

  if (btnAuditBatch && manualAuditTextarea) {
    btnAuditBatch.addEventListener('click', () => {
      runBatchManifestAudit(manualAuditTextarea.value);
    });
  }

  if (btnLoadSampleManifest && manualAuditTextarea) {
    btnLoadSampleManifest.addEventListener('click', () => {
      manualAuditTextarea.value = JSON.stringify({
        "name": "target-vulnerable-app",
        "version": "1.0.0",
        "dependencies": {
          "lodash": "4.17.20",
          "express": "4.18.2",
          "axios": "0.21.1",
          "@corp-internal/sso-authenticator": "1.0.0",
          "internal-private-telemetry": "2.4.1",
          "minimist": "1.2.5"
        },
        "devDependencies": {
          "webpack": "5.76.0"
        }
      }, null, 2);
      if (manualAuditBody && manualAuditBody.style.display === 'none') {
        manualAuditBody.style.display = 'block';
        if (manualAuditArrow) manualAuditArrow.classList.add('open');
      }
    });
  }

  if (supplySearch) {
    supplySearch.addEventListener('input', () => {
      supplyState.filters.search = supplySearch.value;
      debouncedRefreshSupplyChain();
    });
  }

  if (supplyFilterSeverity) {
    supplyFilterSeverity.addEventListener('change', () => {
      supplyState.filters.severity = supplyFilterSeverity.value;
      refreshSupplyChainTable();
    });
  }

  if (supplyFilterEco) {
    supplyFilterEco.addEventListener('change', () => {
      supplyState.filters.eco = supplyFilterEco.value;
      refreshSupplyChainTable();
    });
  }

  // Clickable ecosystem pills in the header strip
  if (supplyEcoStrip) {
    supplyEcoStrip.querySelectorAll('.eco-tag').forEach(tag => {
      tag.addEventListener('click', () => {
        const eco = tag.getAttribute('data-eco');
        if (supplyState.filters.eco === eco) {
          supplyState.filters.eco = 'all';
          tag.classList.remove('active');
          if (supplyFilterEco) supplyFilterEco.value = 'all';
        } else {
          supplyEcoStrip.querySelectorAll('.eco-tag').forEach(t => t.classList.remove('active'));
          supplyState.filters.eco = eco;
          tag.classList.add('active');
          if (supplyFilterEco) supplyFilterEco.value = eco;
        }
        refreshSupplyChainTable();
      });
    });
  }

  if (btnExportSupplyHtml) {
    btnExportSupplyHtml.addEventListener('click', async () => {
      if (supplyState.packages.length === 0 && supplyState.exposedFiles.length === 0) {
        const stored = await storage.getSupplyChainFindings();
        if (stored.length > 0) {
          supplyState.packages = stored.filter(f => f.type === 'package');
          supplyState.exposedFiles = stored.filter(f => f.type === 'exposed-file');
        }
      }
      if (supplyState.packages.length === 0 && supplyState.exposedFiles.length === 0) {
        alert('No supply chain findings to export.');
        return;
      }
      const html = generateSupplyChainHtmlReport();
      downloadFile(html, 'crawlizer-supply-chain-report.html', 'text/html');
      engine.log('inf', 'Exported supply chain audit report to HTML.');
    });
  }

  if (btnExportSupplyJson) {
    btnExportSupplyJson.addEventListener('click', async () => {
      if (supplyState.packages.length === 0 && supplyState.exposedFiles.length === 0) {
        const stored = await storage.getSupplyChainFindings();
        if (stored.length > 0) {
          supplyState.packages = stored.filter(f => f.type === 'package');
          supplyState.exposedFiles = stored.filter(f => f.type === 'exposed-file');
        }
      }
      if (supplyState.packages.length === 0 && supplyState.exposedFiles.length === 0) {
        alert('No supply chain findings to export.');
        return;
      }
      const data = {
        targetUrl: supplyState.targetUrl,
        timestamp: new Date().toISOString(),
        stats: calculateSupplyStats(),
        packages: supplyState.packages,
        exposedFiles: supplyState.exposedFiles
      };
      downloadFile(JSON.stringify(data, null, 2), 'crawlizer-supply-chain.json', 'application/json');
      engine.log('inf', 'Exported supply chain findings to JSON.');
    });
  }

  if (btnExportSupplyCsv) {
    btnExportSupplyCsv.addEventListener('click', async () => {
      if (supplyState.packages.length === 0 && supplyState.exposedFiles.length === 0) {
        const stored = await storage.getSupplyChainFindings();
        if (stored.length > 0) {
          supplyState.packages = stored.filter(f => f.type === 'package');
          supplyState.exposedFiles = stored.filter(f => f.type === 'exposed-file');
        }
      }
      if (supplyState.packages.length === 0 && supplyState.exposedFiles.length === 0) {
        alert('No supply chain findings to export.');
        return;
      }
      let csv = 'Ecosystem,PackageName,Version,IsUnregistered,RiskLevel,OSVAdvisoriesCount,WeeklyDownloads,Sources\n';
      const esc = (txt) => `"${(txt || '').toString().replace(/"/g, '""')}"`;
      supplyState.packages.forEach(p => {
        const advCount = p.advisoriesCount || (p.advisories ? p.advisories.length : 0);
        const sources = Array.isArray(p.sources) ? p.sources.map(s => s.url).join('; ') : '';
        csv += `${esc(p.ecosystem || 'npm')},${esc(p.name)},${esc(p.version)},${p.isUnregistered ? 'YES' : 'NO'},${esc(p.riskLevel)},${advCount},${p.weeklyDownloads || 0},${esc(sources)}\n`;
      });
      downloadFile(csv, 'crawlizer-supply-chain.csv', 'text/csv');
      engine.log('inf', 'Exported supply chain findings to CSV.');
    });
  }

  if (btnCopySupplyBad) {
    btnCopySupplyBad.addEventListener('click', async () => {
      if (supplyState.packages.length === 0) {
        const stored = await storage.getSupplyChainFindings();
        if (stored.length > 0) {
          supplyState.packages = stored.filter(f => f.type === 'package');
          supplyState.exposedFiles = stored.filter(f => f.type === 'exposed-file');
        }
      }
      const bad = supplyState.packages.filter(p => p.isUnregistered);
      if (bad.length === 0) {
        alert('No unregistered / dependency confusion packages found to copy.');
        return;
      }
      const list = bad.map(p => `${p.ecosystem || 'npm'}:${p.name}${p.version ? `@${p.version}` : ''}`).join('\n');
      await navigator.clipboard.writeText(list);
      alert(`Copied ${bad.length} unregistered / missing packages to clipboard!`);
    });
  }

  if (btnClearSupply) {
    btnClearSupply.addEventListener('click', async () => {
      if (confirm('Clear all supply chain findings?')) {
        await storage.clearSupplyChainFindings();
        supplyState.packages = [];
        supplyState.exposedFiles = [];
        await refreshMetrics();
        await refreshSupplyChainTable();
        engine.log('inf', 'Supply chain findings cleared from database.');
      }
    });
  }

  function formatNumber(num) {
    const value = Number(num || 0);
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}K`;
    return `${value}`;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('autostart') === 'true') {
    setTimeout(startCrawling, 500);
  }
});
