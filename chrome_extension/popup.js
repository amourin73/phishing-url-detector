// Popup script - Fixed version
class PhishingDetectorPopup {
  constructor() {
    this.currentTab = null;
    this.apiBaseUrl = 'http://localhost:5000';
    this.init();
  }

  async init() {
    try {
      await this.getCurrentTab();
      this.bindEvents();
      this.analyzeCurrentUrl();
    } catch (error) {
      console.error('Init error:', error);
      this.showError('Failed to initialize: ' + error.message);
    }
  }

  async getCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    this.currentTab = tab;
    document.getElementById('currentUrl').textContent = this.formatUrl(tab.url);
  }

  formatUrl(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname + urlObj.pathname;
    } catch {
      return url;
    }
  }

  bindEvents() {
    document.getElementById('refreshBtn').addEventListener('click', () => {
      this.analyzeCurrentUrl();
    });

    document.getElementById('settingsBtn').addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });

    document.getElementById('scanPageBtn').addEventListener('click', () => {
      this.scanCurrentPage();
    });
  }

  async analyzeCurrentUrl() {
    this.showLoading();

    try {
      const result = await this.checkUrl(this.currentTab.url);
      this.displayResult(result);
    } catch (error) {
      this.showError('Failed to analyze URL: ' + error.message);
    }
  }

  async scanCurrentPage() {
    const scanBtn = document.getElementById('scanPageBtn');
    const originalText = scanBtn.textContent;

    try {
      scanBtn.disabled = true;
      scanBtn.textContent = '🔄 Scanning...';

      console.log('🔄 Starting page scan from popup...');

      // Send message to content script
      const response = await chrome.tabs.sendMessage(this.currentTab.id, {
        action: 'scanPage'
      });

      console.log('📨 Received response:', response);

      if (response && response.success) {
        this.showMessage('✅ Page scan completed! Check the page for highlighted URLs.', 'success');

        // Close popup after delay
        setTimeout(() => window.close(), 2000);
      } else {
        throw new Error(response?.error || 'Scan failed without specific error');
      }

    } catch (error) {
      console.error('❌ Scan error:', error);

      let errorMessage = 'Scan failed: ';
      if (error.message.includes('Could not establish connection')) {
        errorMessage = 'Content script not loaded. Please refresh the page and try again.';
      } else if (error.message.includes('PageURLScanner class not found')) {
        errorMessage = 'Scanner injection failed. Trying alternative method...';
        // Try alternative injection method
        await this.tryAlternativeScan();
        return;
      } else {
        errorMessage += error.message;
      }

      this.showMessage(errorMessage, 'error');
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = originalText;
    }
  }

  async tryAlternativeScan() {
    try {
      // Use scripting API directly as fallback
      await chrome.scripting.executeScript({
        target: { tabId: this.currentTab.id },
        files: ['page_scanner.js']
      });

      this.showMessage('✅ Scanner injected! Please click Scan again.', 'success');
    } catch (error) {
      this.showMessage('❌ Alternative scan also failed: ' + error.message, 'error');
    }
  }

  async checkUrl(url) {
    const response = await fetch(`${this.apiBaseUrl}/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    return await response.json();
  }

  showLoading() {
    document.getElementById('status').className = 'status loading';
    document.getElementById('status').textContent = '🔍 Analyzing URL...';
    document.getElementById('confidence').textContent = '';
    document.getElementById('explanation').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
  }

  displayResult(result) {
    if (!result.success) {
      this.showError(result.error || 'Analysis failed');
      return;
    }

    const isPhishing = result.is_phishing;
    const confidence = result.confidence || result.probability || 0.5;

    const statusElement = document.getElementById('status');
    if (isPhishing) {
      statusElement.className = 'status phishing';
      statusElement.textContent = '🚨 PHISHING DETECTED';
    } else {
      statusElement.className = 'status safe';
      statusElement.textContent = '✅ SAFE';
    }

    document.getElementById('confidence').textContent =
      `Confidence: ${(confidence * 100).toFixed(1)}%`;

    this.generateExplanation(result, this.currentTab.url);
    document.getElementById('explanation').classList.remove('hidden');
  }

  generateExplanation(result, url) {
    const featureList = document.getElementById('featureList');
    featureList.innerHTML = '';

    const features = this.analyzeFeatures(url, result);

    features.forEach(feature => {
      const li = document.createElement('li');
      li.innerHTML = `<span class="${feature.type}">${feature.icon} ${feature.text}</span>`;
      featureList.appendChild(li);
    });
  }

  analyzeFeatures(url, result) {
    const features = [];
    // Your existing feature analysis logic
    return features;
  }

  showError(message) {
    document.getElementById('error').textContent = message;
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('status').className = 'status error';
    document.getElementById('status').textContent = '❌ Error';
  }

  showMessage(message, type) {
    const existing = document.querySelectorAll('.phishing-popup-message');
    existing.forEach(el => el.remove());

    const messageDiv = document.createElement('div');
    messageDiv.className = 'phishing-popup-message';
    messageDiv.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      background: ${type === 'success' ? '#4CAF50' : '#f44336'};
      color: white;
      padding: 12px 20px;
      border-radius: 5px;
      z-index: 10000;
      font-family: Arial, sans-serif;
      font-size: 12px;
      font-weight: bold;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      max-width: 350px;
      text-align: center;
    `;
    messageDiv.textContent = message;

    document.body.appendChild(messageDiv);

    setTimeout(() => {
      if (document.body.contains(messageDiv)) {
        document.body.removeChild(messageDiv);
      }
    }, 4000);
  }
}

// Initialize when popup loads
document.addEventListener('DOMContentLoaded', () => {
  new PhishingDetectorPopup();
});