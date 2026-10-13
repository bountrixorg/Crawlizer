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
      localStorage.setItem('crawlizer_sidebar_collapsed', appSidebar.classList.contains('collapsed'));
    });

    if (localStorage.getItem('crawlizer_sidebar_collapsed') === 'true') {
      appSidebar.classList.add('collapsed');
    }
  }

  // Ctrl+B shortcut to toggle sidebar
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
      e.preventDefault();
      if (appSidebar) {
        appSidebar.classList.toggle('collapsed');
        localStorage.setItem('crawlizer_sidebar_collapsed', appSidebar.classList.contains('collapsed'));
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

  function drawRpsChart() {
    if (!crawlRateCanvas) return;
    const ctx = crawlRateCanvas.getContext('2d');
    const w = (crawlRateCanvas.width = crawlRateCanvas.clientWidth);
    const h = (crawlRateCanvas.height = crawlRateCanvas.clientHeight);

    ctx.clearRect(0, 0, w, h);

    // Draw dark cyber gridlines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    const maxVal = Math.max(10, ...rpsHistory);
    const stepX = w / (rpsHistory.length - 1);

    // Area path
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
    gradient.addColorStop(0, 'rgba(0, 240, 255, 0.35)');
    gradient.addColorStop(1, 'rgba(0, 240, 255, 0.01)');
    ctx.fillStyle = gradient;
    ctx.fill();

    // Line stroke with neon cyan glow
    ctx.beginPath();
    rpsHistory.forEach((val, i) => {
      const x = i * stepX;
      const y = h - (val / maxVal) * (h - 20) - 10;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#00f0ff';
    ctx.lineWidth = 2.5;
    ctx.shadowColor = '#00f0ff';
    ctx.shadowBlur = 10;
    ctx.stroke();
    ctx.shadowBlur = 0;
  }

  function drawDonutChart(counts) {
    if (!typesDonutCanvas) return;
    const ctx = typesDonutCanvas.getContext('2d');
    const w = (typesDonutCanvas.width = typesDonutCanvas.clientWidth);
    const h = (typesDonutCanvas.height = typesDonutCanvas.clientHeight);
    const cx = w / 2;
    const cy = h / 2;
    const radius = Math.min(cx, cy) - 12;
    const innerRadius = radius * 0.62;

    ctx.clearRect(0, 0, w, h);

    const data = [
      { label: 'HTML', val: counts.html || 1, color: '#00f0ff' },
      { label: 'JS', val: counts.js || 1, color: '#39ff14' },
      { label: 'APIs', val: counts.api || 1, color: '#38bdf8' },
      { label: 'Secrets', val: counts.secrets || 1, color: '#ff2bd6' }
    ];

    const total = data.reduce((acc, d) => acc + d.val, 0);
    let startAngle = -Math.PI / 2;

    data.forEach(slice => {
      const sliceAngle = (slice.val / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
      ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = slice.color;
      ctx.shadowColor = slice.color;
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
      startAngle += sliceAngle;
    });

    // Center hole text
    ctx.fillStyle = '#f0f6fc';
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
    // Generate organic reactive wave
    const v = Math.min(24, Math.max(4, Math.round(currentVal % 20) + 4));
    path.setAttribute('d', `M2,24 L14,${28 - v} L26,${18 + Math.round(v/3)} L38,${24 - v} L50,14 L62,${26 - v} L70,${24 - Math.round(v/1.5)}`);
  }

  // ==========================================
  // Command Palette (Ctrl+K)
  // ==========================================
  const commands = [
    { title: 'Overview & Live Charts', icon: '📊', shortcut: 'TAB 1', action: () => switchTab('tab-overview') },
    { title: 'Targets & Spider Configuration', icon: '🎯', shortcut: 'TAB 2', action: () => switchTab('tab-upload') },
    { title: 'Discovered Endpoints Explorer', icon: '⚡', shortcut: 'TAB 3', action: () => switchTab('tab-results') },
    { title: 'Secrets & Threat Findings', icon: '🗡️', shortcut: 'TAB 4', action: () => switchTab('tab-secrets') },
    { title: 'Live Stream Terminal Feed', icon: '💻', shortcut: 'TAB 5', action: () => switchTab('tab-terminal') },
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
      'tab-terminal': 'mission/live-terminal'
    };
    typeBreadcrumbText(labelMap[tabId] || 'mission/active');

    if (tabId === 'tab-results') {
      refreshResultsTable();
    } else if (tabId === 'tab-secrets') {
      refreshSecretsTable();
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
  // Crawler Engine Event Hookups
  // ==========================================
  await storage.init();
  await refreshMetrics();
  await renderTargetsTable();
  await refreshResultsTable();
  await refreshSecretsTable();
  drawRpsChart();
  typeBreadcrumbText('mission/telemetry-overview');

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
      btnStop.disabled = false;
      if (cfgMode.value === 'single-tab') btnFocusTab.style.display = 'inline-flex';
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
      captchaBanner.style.display = 'none';
      refreshMetrics();
      renderTargetsTable();
      refreshResultsTable();
      refreshSecretsTable();
    }
  };

  engine.onCaptchaDetected = (info) => {
    captchaBanner.style.display = 'flex';
    if (captchaTypeTitle) captchaTypeTitle.textContent = `${info.title || 'CAPTCHA / Challenge'} Detected!`;
    if (captchaTargetUrl) captchaTargetUrl.textContent = info.url;
  };

  engine.onSecretFound = () => {
    refreshMetrics();
    debouncedRefreshSecrets();
  };

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
    const config = {
      mode: cfgMode.value,
      scopeMode: cfgScope.value,
      scopeRegex: cfgScopeRegex.value.trim(),
      tabRenderDelay: parseInt(cfgTabDelay.value, 10) || 400,
      concurrency: cfgMode.value === 'single-tab' ? 1 : (parseInt(cfgConcurrency.value, 10) || 10),
      maxDepth: parseInt(cfgDepth.value, 10) || 3,
      timeout: (parseInt(cfgTimeout.value, 10) || 6) * 1000,
      subdomainCrawl: cfgSubdomainCrawl.checked,
      openFoundUrlsInTab: cfgOpenInTab.checked,
      autoClickButtons: cfgClickButtons.checked,
      crawlJavascript: cfgCrawlJs.checked,
      parseRobotsAndSitemaps: cfgRobotsSitemap.checked,
      userAgent: cfgUserAgent.value.trim()
    };

    engine.configure(config);
    await storage.saveSetting('crawler_config', config);

    let pending = await storage.getPendingTargets();
    if (pending.length === 0) {
      const allTargets = await storage.getAllTargets();
      if (allTargets.length > 0) {
        engine.log('inf', `Re-activating ${allTargets.length} seed targets for new crawl session...`);
        const tx = storage.db.transaction('targets', 'readwrite');
        const store = tx.objectStore('targets');
        for (const t of allTargets) {
          t.status = 'pending';
          store.put(t);
        }
        await new Promise(r => { tx.oncomplete = r; });
        pending = await storage.getPendingTargets();
      }
    }

    if (pending.length === 0) {
      alert('No pending targets to crawl. Please upload a .txt file or paste seed URLs.');
      switchTab('tab-upload');
      return;
    }

    await engine.start(pending);
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
    const tx = storage.db.transaction('targets', 'readwrite');
    tx.objectStore('targets').clear();
    tx.oncomplete = async () => {
      await refreshMetrics();
      await renderTargetsTable();
      engine.log('inf', 'Cleared all target seeds');
    };
  });

  function parseUrlText(text) {
    return text.split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'));
  }

  cfgScope.addEventListener('change', () => {
    regexGroup.style.display = cfgScope.value === 'regex' ? 'flex' : 'none';
  });

  btnClearDb.addEventListener('click', async () => {
    if (confirm('Are you sure you want to completely wipe all targets and discovered data?')) {
      await storage.clearAll();
      await refreshMetrics();
      await renderTargetsTable();
      await refreshResultsTable();
      await refreshSecretsTable();
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

    const progress = stats.totalTargets > 0 ? Math.min(100, Math.round((stats.crawledTargets / stats.totalTargets) * 100)) : 0;
    metricProgressPercent.textContent = `${progress}% Completed`;
    progressBarFill.style.width = `${progress}%`;

    // Update Donut Chart
    try {
      const urls = await storage.getDiscoveredUrls();
      const htmlCount = urls.filter(u => u.type.includes('html')).length;
      const jsCount = urls.filter(u => u.type.includes('js') || u.type.includes('bundle')).length;
      const apiCount = urls.filter(u => u.type.includes('api')).length;
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
      const typeClass = item.type.includes('subdomain') ? 'tag-subdomain' :
                        item.type.includes('button') ? 'tag-btn-click' :
                        item.type.includes('api') ? 'tag-network-api' :
                        item.type.includes('js') ? 'tag-js-endpoint' : 'tag-html-link';
      const scopeClass = item.scope === 'in-scope' ? 'tag-in-scope' : 'tag-out-of-scope';

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
    }
    return `<span class="badge-tag ${tagClass}">${label}</span>`;
  }

  function renderSourceItem(src) {
    return `
      <div class="secret-location-item">
        <div style="display: flex; align-items: center; gap: 8px;">
          ${formatSourceTag(src.type)}
          <a href="${escapeHtml(src.url)}" target="_blank" class="url-cell text-xs" style="color: var(--neon-cyan);">${escapeHtml(src.url)}</a>
        </div>
        ${src.context ? `<div class="secret-context-snippet font-mono">${escapeHtml(src.context)}</div>` : ''}
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
        locationsHtml += renderSourceItem(src);
      });

      if (remainingSources.length > 0) {
        locationsHtml += `<div class="secret-locations-extra" style="display: none;">`;
        remainingSources.forEach(src => {
          locationsHtml += renderSourceItem(src);
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

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('autostart') === 'true') {
    setTimeout(startCrawling, 500);
  }
});
