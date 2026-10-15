/**
 * Katana Web Crawler - Modern Cyber Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  if (window.katanaStorage && window.katanaStorage.init) {
    try {
      await window.katanaStorage.init();
    } catch (e) {
      console.warn('KatanaStorage init in popup:', e);
    }
  }

  const statTargets = document.getElementById('stat-targets');
  const statCrawled = document.getElementById('stat-crawled');
  const statDiscovered = document.getElementById('stat-discovered');
  
  const miniHtml = document.getElementById('mini-html');
  const miniJs = document.getElementById('mini-js');
  const miniApis = document.getElementById('mini-apis');
  const miniSubs = document.getElementById('mini-subs');
  const miniSecrets = document.getElementById('mini-secrets');
  const miniPkgs = document.getElementById('mini-pkgs');

  const fileInput = document.getElementById('popup-file-input');
  const dropZone = document.getElementById('drop-zone');
  const uploadBox = document.getElementById('upload-box');
  const uploadMainText = document.getElementById('upload-main-text');
  const uploadSubText = document.getElementById('upload-sub-text');
  
  const btnQuickStart = document.getElementById('btn-quick-start');
  const btnStartLabel = document.getElementById('btn-start-label');
  const btnOpenDashboard = document.getElementById('btn-open-dashboard');
  const btnClearQuick = document.getElementById('btn-clear-quick');

  const statusPill = document.getElementById('status-pill');
  const statusText = document.getElementById('status-text');

  const cfgSingleTab = document.getElementById('popup-cfg-singletab');
  const cfgSubdomains = document.getElementById('popup-cfg-subdomains');
  const cfgClicker = document.getElementById('popup-cfg-clicker');

  // Load saved config toggles (stored locally on disk in .data/settings.json)
  async function loadPopupConfig() {
    try {
      const savedConfig = await window.katanaStorage.getSetting('crawler_config');
      if (savedConfig) {
        if (savedConfig.mode !== undefined) cfgSingleTab.checked = (savedConfig.mode === 'single-tab');
        if (savedConfig.subdomainCrawl !== undefined) cfgSubdomains.checked = Boolean(savedConfig.subdomainCrawl);
        else cfgSubdomains.checked = true;
        if (savedConfig.autoClickButtons !== undefined) cfgClicker.checked = Boolean(savedConfig.autoClickButtons);
      } else {
        cfgSubdomains.checked = true;
      }
    } catch (e) {
      console.warn('Could not load config in popup:', e);
    }
  }

  async function savePopupConfig() {
    try {
      const savedConfig = (await window.katanaStorage.getSetting('crawler_config')) || {};
      savedConfig.mode = cfgSingleTab.checked ? 'single-tab' : 'fast-fetch';
      savedConfig.subdomainCrawl = cfgSubdomains.checked;
      savedConfig.autoClickButtons = cfgClicker.checked;
      await window.katanaStorage.saveSetting('crawler_config', savedConfig);
    } catch (e) {
      console.warn('Could not save config in popup:', e);
    }
  }

  await loadPopupConfig();
  cfgSingleTab.addEventListener('change', savePopupConfig);
  cfgSubdomains.addEventListener('change', savePopupConfig);
  cfgClicker.addEventListener('change', savePopupConfig);

  // Refresh stats & breakdown counts
  async function updateStats() {
    try {
      const stats = await window.katanaStorage.getStats();
      statTargets.textContent = stats.totalTargets.toLocaleString();
      statCrawled.textContent = stats.crawledTargets.toLocaleString();
      statDiscovered.textContent = stats.totalDiscovered.toLocaleString();

      if (stats.pendingTargets > 0) {
        btnQuickStart.disabled = false;
        btnStartLabel.textContent = `Launch Crawl (${stats.pendingTargets} seeds)`;
      } else if (stats.totalTargets > 0) {
        btnQuickStart.disabled = false;
        btnStartLabel.textContent = `Re-run Crawl (${stats.totalTargets} seeds)`;
      } else {
        btnQuickStart.disabled = true;
        btnStartLabel.textContent = 'Launch Crawl (0 seeds)';
      }

      // Fetch sample of endpoints to calculate sub-metrics
      const allDiscovered = await window.katanaStorage.getDiscoveredUrls({ limit: 5000 });
      let countHtml = 0;
      let countJs = 0;
      let countApis = 0;
      let countSubs = 0;

      const subRegex = /^https?:\/\/[a-z0-9-_]+\.[a-z0-9-_]+\.[a-z0-9-_]+/i;

      allDiscovered.forEach(item => {
        const t = (item.type || '').toLowerCase();
        if (t.includes('js') || t.includes('script')) {
          countJs++;
        } else if (t.includes('api') || t.includes('network') || t.includes('xhr') || t.includes('fetch') || t.includes('endpoint') || t.includes('json') || t.includes('form')) {
          countApis++;
        } else {
          countHtml++;
        }

        if (subRegex.test(item.url) || t.includes('subdomain')) {
          countSubs++;
        }
      });

      miniHtml.textContent = countHtml;
      miniJs.textContent = countJs;
      miniApis.textContent = countApis;
      miniSubs.textContent = countSubs;
      if (miniSecrets) miniSecrets.textContent = (stats.totalSecrets || 0).toLocaleString();
      if (miniPkgs) miniPkgs.textContent = (stats.totalSupplyChain || 0).toLocaleString();

    } catch (e) {
      console.error('Failed to update popup stats:', e);
    }
  }

  await updateStats();

  // Process ingested text file lines
  async function handleFileContent(file) {
    uploadMainText.textContent = `Reading ${file.name}...`;
    uploadSubText.textContent = 'Parsing target URLs...';

    try {
      const text = await file.text();
      const lines = text.split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l.length > 0 && !l.startsWith('#'));

      if (lines.length === 0) {
        uploadMainText.textContent = 'No valid URLs found';
        uploadSubText.textContent = 'Please check the file content';
        return;
      }

      uploadMainText.textContent = `Saving ${lines.length} seeds...`;
      await window.katanaStorage.addTargets(lines);

      uploadMainText.textContent = `✓ ${file.name}`;
      uploadSubText.textContent = `${lines.length} seeds enqueued & ready`;
      
      btnQuickStart.disabled = false;
      statusPill.classList.add('active');
      statusText.textContent = 'SEEDS READY';

      await updateStats();
    } catch (err) {
      console.error(err);
      uploadMainText.textContent = 'Error loading file';
      uploadSubText.textContent = err.message;
    }
  }

  // File input change
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) handleFileContent(file);
  });

  // Drag and drop handlers
  ['dragenter', 'dragover'].forEach(evtName => {
    dropZone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadBox.classList.add('drag-active');
    }, false);
  });

  ['dragleave', 'drop'].forEach(evtName => {
    dropZone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadBox.classList.remove('drag-active');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length > 0) {
      handleFileContent(files[0]);
    }
  });

  const btnAuditActive = document.getElementById('btn-audit-active');
  const serverDot = document.getElementById('server-dot');
  const serverLabel = document.getElementById('server-label');

  async function checkServerStatus() {
    try {
      const res = await fetch('http://localhost:4488/api/status', { signal: AbortSignal.timeout(1000) });
      if (res.ok) {
        if (serverDot) {
          serverDot.style.background = '#39ff14';
          serverDot.style.boxShadow = '0 0 8px #39ff14';
        }
        if (serverLabel) serverLabel.textContent = 'LOCAL SERVER: 4488 (ONLINE)';
        return true;
      }
    } catch {}

    if (serverDot) {
      serverDot.style.background = '#64748b';
      serverDot.style.boxShadow = 'none';
    }
    if (serverLabel) serverLabel.textContent = 'LOCAL SERVER: OFFLINE (npm run dev)';
    return false;
  }

  checkServerStatus();

  if (btnAuditActive) {
    btnAuditActive.addEventListener('click', async () => {
      btnAuditActive.disabled = true;
      btnAuditActive.innerHTML = `<span>Scanning active tab...</span>`;
      chrome.runtime.sendMessage({ action: 'audit_active_tab' }, () => {
        btnAuditActive.innerHTML = `<span>✓ Sent to Local Server!</span>`;
        setTimeout(() => {
          btnAuditActive.disabled = false;
          btnAuditActive.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            <span>⚡ Audit Active Tab</span>
          `;
        }, 1500);
      });
    });
  }

  // Start Crawl - Opens Dashboard and auto-starts
  btnQuickStart.addEventListener('click', async () => {
    const isOnline = await checkServerStatus();
    if (isOnline) {
      chrome.tabs.create({ url: 'http://localhost:4488?autostart=true' });
    } else {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html?autostart=true') });
    }
    window.close();
  });

  // Open Dashboard
  btnOpenDashboard.addEventListener('click', async () => {
    const isOnline = await checkServerStatus();
    if (isOnline) {
      chrome.tabs.create({ url: 'http://localhost:4488' });
    } else {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    }
    window.close();
  });

  // Clear Database button
  btnClearQuick.addEventListener('click', async () => {
    if (confirm('Reset Katana database and clear all seeds & discovered endpoints?')) {
      await window.katanaStorage.clearAll();
      uploadMainText.textContent = 'Drop alive.txt or browse';
      uploadSubText.textContent = 'Supports .txt URL lists & seed files';
      btnQuickStart.disabled = true;
      btnStartLabel.textContent = 'Launch Crawl';
      statusPill.classList.remove('active');
      statusText.textContent = 'STANDBY';
      await updateStats();
    }
  });
});
