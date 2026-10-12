/**
 * Katana Web Crawler - Dashboard UI Controller
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

  // Tabs
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const tabDiscoveredCount = document.getElementById('tab-discovered-count');

  // Tab 1: Upload & Config
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

  // Tab 2: Results & Table
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

  // Tab 3: Terminal
  const terminalBody = document.getElementById('terminal-body');
  const terminalAutoscroll = document.getElementById('terminal-autoscroll');
  const btnClearLogs = document.getElementById('btn-clear-logs');

  let currentPage = 1;
  let pageSize = 50;
  let cachedResults = [];

  // ==========================================
  // Initialization
  // ==========================================
  await storage.init();
  await refreshMetrics();
  await renderTargetsTable();
  await refreshResultsTable();

  // Auto-persist configuration whenever user toggles any switch or changes an input
  async function persistCurrentConfig() {
    try {
      const config = {
        mode: cfgMode.value,
        scopeMode: cfgScope.value,
        scopeRegex: cfgScopeRegex.value.trim(),
        tabRenderDelay: parseInt(cfgTabDelay.value, 10) || 2000,
        concurrency: cfgMode.value === 'single-tab' ? 1 : (parseInt(cfgConcurrency.value, 10) || 10),
        maxDepth: parseInt(cfgDepth.value, 10) || 2,
        timeout: (parseInt(cfgTimeout.value, 10) || 15) * 1000,
        subdomainCrawl: cfgSubdomainCrawl.checked,
        openFoundUrlsInTab: cfgOpenInTab.checked,
        autoClickButtons: cfgClickButtons.checked,
        crawlJavascript: cfgCrawlJs.checked,
        parseRobotsAndSitemaps: cfgRobotsSitemap.checked,
        userAgent: cfgUserAgent.value.trim()
      };
      await storage.saveSetting('crawler_config', config);

      if (chrome && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          katana_singletab: (cfgMode.value === 'single-tab'),
          katana_subdomains: cfgSubdomainCrawl.checked,
          katana_clicker: cfgClickButtons.checked
        });
      }
    } catch (e) {
      console.warn('Failed to auto-persist config:', e);
    }
  }

  // Load saved settings if any
  let savedConfig = await storage.getSetting('crawler_config');
  if (!savedConfig && chrome && chrome.storage && chrome.storage.local) {
    const local = await new Promise(r => chrome.storage.local.get(['katana_singletab', 'katana_subdomains', 'katana_clicker'], r));
    if (local && (local.katana_subdomains !== undefined || local.katana_singletab !== undefined)) {
      savedConfig = {
        subdomainCrawl: local.katana_subdomains !== undefined ? local.katana_subdomains : true,
        mode: local.katana_singletab === false ? 'fast-fetch' : 'single-tab',
        autoClickButtons: local.katana_clicker !== undefined ? local.katana_clicker : true
      };
    }
  }

  if (savedConfig) {
    if (savedConfig.mode) cfgMode.value = savedConfig.mode;
    if (savedConfig.scopeMode) cfgScope.value = savedConfig.scopeMode;
    if (savedConfig.scopeRegex) cfgScopeRegex.value = savedConfig.scopeRegex;
    if (savedConfig.tabRenderDelay) cfgTabDelay.value = savedConfig.tabRenderDelay;
    if (savedConfig.concurrency) cfgConcurrency.value = savedConfig.concurrency;
    if (savedConfig.maxDepth) cfgDepth.value = savedConfig.maxDepth;
    if (savedConfig.timeout) cfgTimeout.value = savedConfig.timeout / 1000;
    if (savedConfig.subdomainCrawl !== undefined) {
      cfgSubdomainCrawl.checked = Boolean(savedConfig.subdomainCrawl);
    } else {
      cfgSubdomainCrawl.checked = true;
    }
    if (savedConfig.openFoundUrlsInTab !== undefined) cfgOpenInTab.checked = Boolean(savedConfig.openFoundUrlsInTab);
    if (savedConfig.autoClickButtons !== undefined) cfgClickButtons.checked = Boolean(savedConfig.autoClickButtons);
    if (savedConfig.crawlJavascript !== undefined) cfgCrawlJs.checked = Boolean(savedConfig.crawlJavascript);
    if (savedConfig.parseRobotsAndSitemaps !== undefined) cfgRobotsSitemap.checked = Boolean(savedConfig.parseRobotsAndSitemaps);
    if (savedConfig.userAgent) cfgUserAgent.value = savedConfig.userAgent;
    toggleModeGroup();
    toggleRegexGroup();
  } else {
    // Brand new state: keep Subdomain Crawl enabled by default
    cfgSubdomainCrawl.checked = true;
    await persistCurrentConfig();
  }

  // Attach immediate auto-save listeners to all config controls
  [cfgMode, cfgScope, cfgScopeRegex, cfgTabDelay, cfgConcurrency, cfgDepth, cfgTimeout, 
   cfgSubdomainCrawl, cfgOpenInTab, cfgClickButtons, cfgCrawlJs, cfgRobotsSitemap, cfgUserAgent].forEach(el => {
    if (el) {
      el.addEventListener('change', persistCurrentConfig);
    }
  });

  function toggleModeGroup() {
    if (cfgMode.value === 'single-tab') {
      concurrencyGroup.style.display = 'none';
      btnFocusTab.style.display = engine.crawlerTabId ? 'inline-flex' : 'none';
      metricActiveWorkers.textContent = 'Single Tab Mode';
    } else {
      concurrencyGroup.style.display = 'flex';
      btnFocusTab.style.display = 'none';
      metricActiveWorkers.textContent = `${cfgConcurrency.value} Threads`;
    }
  }
  cfgMode.addEventListener('change', toggleModeGroup);

  // Focus Crawler Tab button
  btnFocusTab.addEventListener('click', async () => {
    await engine.focusCrawlerTab();
  });

  // ==========================================
  // CAPTCHA Handlers
  // ==========================================
  engine.onCaptchaDetected = (target) => {
    captchaTypeTitle.textContent = `${target.challengeType || 'Bot Challenge'} Detected!`;
    captchaTargetUrl.textContent = target.url;
    captchaBanner.style.display = 'flex';
    btnFocusTab.style.display = 'inline-flex';
  };

  engine.onCaptchaResolved = () => {
    captchaBanner.style.display = 'none';
  };

  btnCaptchaFocus.addEventListener('click', async () => {
    await engine.focusCrawlerTab();
  });

  btnCaptchaSolved.addEventListener('click', () => {
    engine.resolveCaptchaManually();
  });

  btnCaptchaSkip.addEventListener('click', () => {
    engine.resolveCaptchaManually();
  });

  // ==========================================
  // Engine Hooks
  // ==========================================
  engine.onLog = ({ timestamp, level, message, details }) => {
    const line = document.createElement('div');
    line.className = `log-line font-mono ${level === 'err' ? 'error' : level === 'wrn' ? 'warn' : 'info'}`;
    const prefix = level === 'err' ? '[ERR]' : level === 'wrn' ? '[WRN]' : '[INF]';
    line.textContent = `[${timestamp}] ${prefix} ${message} ${details ? '(' + details + ')' : ''}`;
    terminalBody.appendChild(line);

    if (terminalAutoscroll.checked) {
      terminalBody.scrollTop = terminalBody.scrollHeight;
    }
  };

  engine.onProgress = ({ crawled, queueLength, activeWorkers, totalDiscovered, duplicatesFiltered, subdomainsCount, errors, rps }) => {
    metricCrawled.textContent = crawled;
    metricQueue.textContent = queueLength;
    if (cfgMode.value === 'single-tab') {
      metricActiveWorkers.textContent = '1 Active Tab';
    } else {
      metricActiveWorkers.textContent = `${activeWorkers} Active Threads`;
    }
    metricNewSession.textContent = `+${totalDiscovered} In Current Run`;
    metricRps.textContent = rps;
    metricErrors.textContent = errors;
    if (metricSubdomains) metricSubdomains.textContent = subdomainsCount || 0;
    if (metricDupes) metricDupes.textContent = duplicatesFiltered || 0;

    const totalTargets = parseInt(metricTargets.textContent, 10) || 0;
    const progress = totalTargets > 0 ? Math.min(100, Math.round((crawled / totalTargets) * 100)) : 0;
    metricProgressPercent.textContent = `${progress}% Completed`;
    progressBarFill.style.width = `${progress}%`;
  };

  engine.onUrlFound = async () => {
    const stats = await storage.getStats();
    metricDiscovered.textContent = stats.totalDiscovered;
    tabDiscoveredCount.textContent = stats.totalDiscovered;

    const activeTab = document.querySelector('.nav-tab.active')?.dataset.tab;
    if (activeTab === 'tab-results') {
      debouncedRefreshResults();
    }
  };

  engine.onStateChange = (state) => {
    headerStatusDot.className = 'status-indicator-dot';
    if (state === 'running') {
      headerStatusDot.classList.add('running');
      headerStatusLabel.textContent = 'CRAWLING';
      btnStart.style.display = 'none';
      btnPause.style.display = 'inline-flex';
      btnResume.style.display = 'none';
      btnStop.disabled = false;
      if (cfgMode.value === 'single-tab') btnFocusTab.style.display = 'inline-flex';
    } else if (state === 'paused') {
      headerStatusDot.classList.add('paused');
      headerStatusLabel.textContent = 'PAUSED';
      btnStart.style.display = 'none';
      btnPause.style.display = 'none';
      btnResume.style.display = 'inline-flex';
      btnStop.disabled = false;
    } else {
      headerStatusLabel.textContent = 'IDLE';
      btnStart.style.display = 'inline-flex';
      btnPause.style.display = 'none';
      btnResume.style.display = 'none';
      btnStop.disabled = true;
      captchaBanner.style.display = 'none';
      refreshMetrics();
      renderTargetsTable();
      refreshResultsTable();
    }
  };

  // ==========================================
  // Tab Switching
  // ==========================================
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      navTabs.forEach(t => t.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetPane = document.getElementById(tab.dataset.tab);
      if (targetPane) targetPane.classList.add('active');

      if (tab.dataset.tab === 'tab-results') {
        refreshResultsTable();
      }
    });
  });

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
    try {
      engine.log('inf', `Processing uploaded file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
      const text = await file.text();
      const urls = parseUrlText(text);

      if (urls.length === 0) {
        alert('No valid URLs found in file.');
        return;
      }

      await storage.addTargets(urls);
      engine.log('inf', `Successfully imported ${urls.length} targets into crawler database`);
      await refreshMetrics();
      await renderTargetsTable();
    } catch (err) {
      console.error(err);
      engine.log('err', `Error reading file: ${err.message}`);
    }
  }

  btnAddPasted.addEventListener('click', async () => {
    const text = targetTextarea.value.trim();
    if (!text) return;

    const urls = parseUrlText(text);
    if (urls.length === 0) {
      alert('Please enter at least one valid URL.');
      return;
    }

    await storage.addTargets(urls);
    targetTextarea.value = '';
    engine.log('inf', `Added ${urls.length} pasted URLs to targets queue`);
    await refreshMetrics();
    await renderTargetsTable();
  });

  // Load sample targets from workspace
  btnLoadDemo.addEventListener('click', async () => {
    const sample = [
      'http://1.ram.m2m.telekom.com:8774',
      'http://1000044548-media-production.obs.eu-de.otc.t-systems.com:5080',
      'http://116.203.208.253:41241',
      'http://116.203.208.253:4430',
      'http://13.ram.m2m.telekom.com:8774',
      'http://164.30.44.18:5080',
      'http://164.30.44.19:5080',
      'http://164.30.44.20:5080',
      'http://164.30.44.21:5080',
      'http://164.30.45.18:5080'
    ];
    await storage.addTargets(sample);
    engine.log('inf', `Loaded ${sample.length} sample targets from alive.txt`);
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

  async function startCrawling() {
    const config = {
      mode: cfgMode.value,
      scopeMode: cfgScope.value,
      scopeRegex: cfgScopeRegex.value.trim(),
      tabRenderDelay: parseInt(cfgTabDelay.value, 10) || 2000,
      concurrency: cfgMode.value === 'single-tab' ? 1 : (parseInt(cfgConcurrency.value, 10) || 10),
      maxDepth: parseInt(cfgDepth.value, 10) || 1,
      timeout: (parseInt(cfgTimeout.value, 10) || 15) * 1000,
      subdomainCrawl: cfgSubdomainCrawl.checked,
      openFoundUrlsInTab: cfgOpenInTab.checked,
      autoClickButtons: cfgClickButtons.checked,
      crawlJavascript: cfgCrawlJs.checked,
      parseRobotsAndSitemaps: cfgRobotsSitemap.checked,
      userAgent: cfgUserAgent.value.trim()
    };

    engine.configure(config);
    await storage.saveSetting('crawler_config', config);

    const pending = await storage.getPendingTargets();
    if (pending.length === 0) {
      alert('No pending targets to crawl. Please upload a .txt file or paste seed URLs.');
      return;
    }

    const terminalTab = document.querySelector('[data-tab="tab-terminal"]');
    if (terminalTab) terminalTab.click();

    await engine.start(pending);
  }

  function toggleRegexGroup() {
    regexGroup.style.display = cfgScope.value === 'regex' ? 'flex' : 'none';
  }
  cfgScope.addEventListener('change', toggleRegexGroup);

  btnClearDb.addEventListener('click', async () => {
    if (confirm('Are you sure you want to completely clear all targets and discovered URLs?')) {
      await storage.clearAll();
      await refreshMetrics();
      await renderTargetsTable();
      await refreshResultsTable();
      engine.log('inf', 'All database storage cleared');
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
    downloadFile(txtContent, 'katana-urls.txt', 'text/plain');
    engine.log('inf', `Exported ${urls.length} URLs to katana-urls.txt`);
  });

  exportJson.addEventListener('click', async () => {
    const urls = await storage.getDiscoveredUrls();
    if (urls.length === 0) {
      alert('No discovered URLs to export.');
      return;
    }
    const jsonContent = JSON.stringify(urls, null, 2);
    downloadFile(jsonContent, 'katana-results.json', 'application/json');
    engine.log('inf', `Exported ${urls.length} entries to katana-results.json`);
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
    downloadFile(csv, 'katana-results.csv', 'text/csv');
    engine.log('inf', `Exported ${urls.length} entries to katana-results.csv`);
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
    metricPending.textContent = `${stats.pendingTargets} Pending`;
    metricCrawled.textContent = stats.crawledTargets;
    metricDiscovered.textContent = stats.totalDiscovered;
    tabDiscoveredCount.textContent = stats.totalDiscovered;
    loadedSeedsBadge.textContent = `${stats.totalTargets} Seeds Ready`;

    const progress = stats.totalTargets > 0 ? Math.min(100, Math.round((stats.crawledTargets / stats.totalTargets) * 100)) : 0;
    metricProgressPercent.textContent = `${progress}% Completed`;
    progressBarFill.style.width = `${progress}%`;
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
      const statusColor = t.status === 'completed' ? '#10b981' : t.status === 'crawling' ? '#00d2ff' : t.status === 'failed' ? '#ef4444' : '#94a3b8';
      const crawledTime = t.crawledAt ? new Date(t.crawledAt).toLocaleTimeString() : '-';

      rowsHtml += `
        <tr>
          <td>${idx + 1}</td>
          <td class="url-cell"><a href="${escapeHtml(t.url)}" target="_blank">${escapeHtml(t.url)}</a></td>
          <td><span style="color: ${statusColor}; font-weight: 600; text-transform: uppercase; font-size: 11px;">${t.status}</span></td>
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
                        item.type.includes('bundle') ? 'tag-script-bundle' :
                        item.type.includes('js') ? 'tag-js-endpoint' :
                        item.type.includes('script') ? 'tag-script-src' :
                        item.type.includes('form') ? 'tag-form' :
                        item.type.includes('robot') ? 'tag-robots' : 'tag-html-link';
      const scopeClass = item.scope === 'in-scope' ? 'tag-in-scope' : 'tag-out-of-scope';

      html += `
        <tr>
          <td>${rowNum}</td>
          <td class="url-cell">
            <a href="${escapeHtml(item.url)}" target="_blank" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</a>
          </td>
          <td><span class="badge-tag ${typeClass}">${escapeHtml(item.type)}</span></td>
          <td class="source-cell" title="${escapeHtml(item.sourceUrl || '')}">${escapeHtml(item.sourceUrl || '-')}</td>
          <td><span class="badge-tag ${scopeClass}">${escapeHtml(item.scope)}</span></td>
          <td>
            <button class="btn btn-xs btn-outline copy-row-btn" data-url="${escapeHtml(item.url)}" title="Copy URL">
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

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('autostart') === 'true') {
    engine.log('inf', 'Auto-start parameter detected, launching crawl...');
    setTimeout(startCrawling, 500);
  }
});
