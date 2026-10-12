/**
 * Katana Web Crawler - Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const statTargets = document.getElementById('stat-targets');
  const statCrawled = document.getElementById('stat-crawled');
  const statDiscovered = document.getElementById('stat-discovered');
  const fileInput = document.getElementById('popup-file-input');
  const uploadInfo = document.getElementById('upload-info');
  const btnQuickStart = document.getElementById('btn-quick-start');
  const btnOpenDashboard = document.getElementById('btn-open-dashboard');

  let loadedUrls = [];

  // Refresh stats
  async function updateStats() {
    try {
      const stats = await window.katanaStorage.getStats();
      statTargets.textContent = stats.totalTargets;
      statCrawled.textContent = stats.crawledTargets;
      statDiscovered.textContent = stats.totalDiscovered;

      if (stats.pendingTargets > 0) {
        btnQuickStart.disabled = false;
      }
    } catch (e) {
      console.error('Failed to update stats:', e);
    }
  }

  await updateStats();

  // Handle file upload
  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    uploadInfo.textContent = `Reading ${file.name}...`;

    try {
      const text = await file.text();
      const lines = text.split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l.length > 0 && !l.startsWith('#'));

      if (lines.length === 0) {
        uploadInfo.textContent = 'No valid URLs found in file.';
        return;
      }

      uploadInfo.textContent = `Storing ${lines.length} seeds...`;
      await window.katanaStorage.addTargets(lines);
      loadedUrls = lines;

      uploadInfo.textContent = `Loaded ${lines.length} URLs from ${file.name}`;
      btnQuickStart.disabled = false;
      await updateStats();
    } catch (err) {
      console.error(err);
      uploadInfo.textContent = 'Error parsing file: ' + err.message;
    }
  });

  // Start Crawl - Opens Dashboard and auto-starts
  btnQuickStart.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html?autostart=true') });
    window.close();
  });

  // Open Dashboard
  btnOpenDashboard.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    window.close();
  });
});
