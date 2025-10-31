// Options page script
document.addEventListener('DOMContentLoaded', () => {
  // Load saved settings
  chrome.storage.sync.get({
    apiUrl: 'http://localhost:5000',
    autoDetect: true,
    showNotifications: true,
    confidenceThreshold: 0.7
  }, (items) => {
    document.getElementById('apiUrl').value = items.apiUrl;
    document.getElementById('autoDetect').checked = items.autoDetect;
    document.getElementById('showNotifications').checked = items.showNotifications;
    document.getElementById('confidenceThreshold').value = items.confidenceThreshold;
    document.getElementById('thresholdValue').textContent =
      Math.round(items.confidenceThreshold * 100) + '%';
  });

  // Update threshold value display
  document.getElementById('confidenceThreshold').addEventListener('input', (e) => {
    document.getElementById('thresholdValue').textContent =
      Math.round(e.target.value * 100) + '%';
  });

  // Save settings
  document.getElementById('saveBtn').addEventListener('click', () => {
    const settings = {
      apiUrl: document.getElementById('apiUrl').value,
      autoDetect: document.getElementById('autoDetect').checked,
      showNotifications: document.getElementById('showNotifications').checked,
      confidenceThreshold: parseFloat(document.getElementById('confidenceThreshold').value)
    };

    chrome.storage.sync.set(settings, () => {
      document.getElementById('status').textContent = 'Settings saved!';
      document.getElementById('status').style.color = 'green';
      setTimeout(() => {
        document.getElementById('status').textContent = '';
      }, 2000);
    });
  });

  // Test connection
  document.getElementById('testBtn').addEventListener('click', async () => {
    const apiUrl = document.getElementById('apiUrl').value;

    try {
      const response = await fetch(`${apiUrl}/health`);
      if (response.ok) {
        document.getElementById('status').textContent = '✅ Connection successful!';
        document.getElementById('status').style.color = 'green';
      } else {
        throw new Error(`Server returned ${response.status}`);
      }
    } catch (error) {
      document.getElementById('status').textContent = '❌ Connection failed: ' + error.message;
      document.getElementById('status').style.color = 'red';
    }
  });
});