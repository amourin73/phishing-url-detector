// Popup script for phishing detection extension
class PhishingDetectorPopup {
  constructor() {
    this.currentTab = null;
    this.apiBaseUrl = 'http://localhost:5000';
    this.init();
  }

  async init() {
    await this.getCurrentTab();
    this.bindEvents();
    this.analyzeCurrentUrl();
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

    // Update status
    const statusElement = document.getElementById('status');
    if (isPhishing) {
      statusElement.className = 'status phishing';
      statusElement.textContent = '🚨 PHISHING DETECTED';
    } else {
      statusElement.className = 'status safe';
      statusElement.textContent = '✅ SAFE';
    }

    // Update confidence
    document.getElementById('confidence').textContent =
      `Confidence: ${(confidence * 100).toFixed(1)}%`;

    // Generate explanation
    this.generateExplanation(result, this.currentTab.url);

    // Show explanation
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
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    // Analyze based on your feature extractor logic
    if (hostname.includes('bit.ly') || hostname.includes('tinyurl') || hostname.includes('goo.gl')) {
      features.push({
        icon: '🔗',
        text: 'Uses URL shortener service',
        type: 'negative'
      });
    }

    if (/\d+\.\d+\.\d+\.\d+/.test(hostname)) {
      features.push({
        icon: '🌐',
        text: 'Uses IP address instead of domain name',
        type: 'negative'
      });
    }

    if (hostname.endsWith('.tk') || hostname.endsWith('.ml') || hostname.endsWith('.ga') ||
        hostname.endsWith('.cf') || hostname.endsWith('.xyz')) {
      features.push({
        icon: '🏷️',
        text: 'Uses suspicious top-level domain',
        type: 'negative'
      });
    }

    if (hostname.includes('login') || hostname.includes('verify') || hostname.includes('secure') ||
        hostname.includes('account') || hostname.includes('bank')) {
      features.push({
        icon: '🔒',
        text: 'Contains security-related keywords in domain',
        type: 'negative'
      });
    }

    if (hostname.includes('google') || hostname.includes('facebook') || hostname.includes('microsoft') ||
        hostname.includes('apple') || hostname.includes('amazon') || hostname.includes('paypal')) {
      if (!this.isOfficialDomain(hostname)) {
        features.push({
          icon: '🏢',
          text: 'Imitates well-known brand',
          type: 'negative'
        });
      } else {
        features.push({
          icon: '✅',
          text: 'Official domain of trusted company',
          type: 'positive'
        });
      }
    }

    if (url.startsWith('https://')) {
      features.push({
        icon: '🔐',
        text: 'Uses HTTPS encryption',
        type: 'positive'
      });
    }

    if (hostname.length > 30) {
      features.push({
        icon: '📏',
        text: 'Unusually long domain name',
        type: 'negative'
      });
    }

    if (this.calculateEntropy(hostname) > 3.5) {
      features.push({
        icon: '🎲',
        text: 'Domain appears randomly generated',
        type: 'negative'
      });
    }

    // Add confidence-based message
    if (result.confidence > 0.8) {
      features.push({
        icon: '🎯',
        text: 'High confidence in classification',
        type: 'positive'
      });
    } else if (result.confidence < 0.6) {
      features.push({
        icon: '⚠️',
        text: 'Low confidence - exercise caution',
        type: 'neutral'
      });
    }

    return features;
  }

  isOfficialDomain(hostname) {
    const officialDomains = [
      'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'github.com',
      'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com', 'instagram.com'
    ];
    return officialDomains.some(domain => hostname.endsWith(domain));
  }

  calculateEntropy(text) {
    const freq = {};
    for (let char of text) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    for (let char in freq) {
      const p = freq[char] / text.length;
      entropy += -p * Math.log2(p);
    }

    return entropy;
  }

  showError(message) {
    document.getElementById('error').textContent = message;
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('status').className = 'status error';
    document.getElementById('status').textContent = '❌ Error';
  }
}

// Initialize when popup loads
document.addEventListener('DOMContentLoaded', () => {
  new PhishingDetectorPopup();
});

// Popup script for phishing detection extension
class EnhancedPhishingDetectorPopup {
  constructor() {
    this.currentTab = null;
    this.apiBaseUrl = 'http://localhost:5000';
    this.init();
  }

  async init() {
    await this.getCurrentTab();
    this.bindEvents();
    this.analyzeCurrentUrl();
    this.updatePageScanButton();
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

  updatePageScanButton() {
    const scanBtn = document.getElementById('scanPageBtn');
    // Only enable scan button for http/https pages
    if (this.currentTab.url.startsWith('http')) {
      scanBtn.disabled = false;
      scanBtn.title = 'Scan this page for hidden URLs';
    } else {
      scanBtn.disabled = true;
      scanBtn.title = 'Page scanning only available for web pages';
    }
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

// Updated popup.js - Replace the scanCurrentPage method with this:

async scanCurrentPage() {
    const scanBtn = document.getElementById('scanPageBtn');
    const originalText = scanBtn.textContent;

    try {
        scanBtn.disabled = true;
        scanBtn.textContent = '🔄 Scanning...';
        scanBtn.style.opacity = '0.7';

        console.log('🔄 Starting page scan...');

        // First, check if we can access the current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab) {
            throw new Error('Could not access current tab');
        }

        // Send ping message to check if content script is ready
        let contentScriptReady = false;
        try {
            const pingResponse = await chrome.tabs.sendMessage(tab.id, { action: 'ping' });
            contentScriptReady = !!pingResponse;
        } catch (error) {
            console.log('Content script not ready, will try to scan anyway...');
        }

        // Send scan message
        console.log('📨 Sending scan message to content script...');
        const response = await chrome.tabs.sendMessage(tab.id, {
            action: 'scanPage',
            timestamp: Date.now()
        });

        if (response && response.success) {
            this.showMessage('✅ Page scan started! Check the page for highlighted URLs.', 'success');

            // Close popup after successful scan start
            setTimeout(() => {
                window.close();
            }, 1500);

        } else {
            throw new Error(response?.error || 'Scan failed to start');
        }

    } catch (error) {
        console.error('❌ Page scan error:', error);

        let errorMessage = 'Error starting page scan: ';

        if (error.message.includes('Could not establish connection')) {
            errorMessage += 'Content script not loaded. Try refreshing the page.';
        } else if (error.message.includes('Receiving end does not exist')) {
            errorMessage += 'Extension not active on this page. Try refreshing.';
        } else {
            errorMessage += error.message;
        }

        this.showMessage(errorMessage, 'error');
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = originalText;
        scanBtn.style.opacity = '1';
    }
}

// Also update the showMessage method:
showMessage(message, type) {
    // Remove existing messages
    const existingMessages = document.querySelectorAll('.phishing-popup-message');
    existingMessages.forEach(msg => msg.remove());

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
        word-wrap: break-word;
    `;
    messageDiv.textContent = message;

    document.body.appendChild(messageDiv);

    setTimeout(() => {
        if (document.body.contains(messageDiv)) {
            document.body.removeChild(messageDiv);
        }
    }, 5000);
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

    // Update status
    const statusElement = document.getElementById('status');
    if (isPhishing) {
      statusElement.className = 'status phishing';
      statusElement.textContent = '🚨 PHISHING DETECTED';
    } else {
      statusElement.className = 'status safe';
      statusElement.textContent = '✅ SAFE';
    }

    // Update confidence
    document.getElementById('confidence').textContent =
      `Confidence: ${(confidence * 100).toFixed(1)}%`;

    // Generate explanation
    this.generateExplanation(result, this.currentTab.url);

    // Show explanation
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
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    // Analyze based on your feature extractor logic
    if (hostname.includes('bit.ly') || hostname.includes('tinyurl') || hostname.includes('goo.gl')) {
      features.push({
        icon: '🔗',
        text: 'Uses URL shortener service',
        type: 'negative'
      });
    }

    if (/\d+\.\d+\.\d+\.\d+/.test(hostname)) {
      features.push({
        icon: '🌐',
        text: 'Uses IP address instead of domain name',
        type: 'negative'
      });
    }

    if (hostname.endsWith('.tk') || hostname.endsWith('.ml') || hostname.endsWith('.ga') ||
        hostname.endsWith('.cf') || hostname.endsWith('.xyz')) {
      features.push({
        icon: '🏷️',
        text: 'Uses suspicious top-level domain',
        type: 'negative'
      });
    }

    if (hostname.includes('login') || hostname.includes('verify') || hostname.includes('secure') ||
        hostname.includes('account') || hostname.includes('bank')) {
      features.push({
        icon: '🔒',
        text: 'Contains security-related keywords in domain',
        type: 'negative'
      });
    }

    if (hostname.includes('google') || hostname.includes('facebook') || hostname.includes('microsoft') ||
        hostname.includes('apple') || hostname.includes('amazon') || hostname.includes('paypal')) {
      if (!this.isOfficialDomain(hostname)) {
        features.push({
          icon: '🏢',
          text: 'Imitates well-known brand',
          type: 'negative'
        });
      } else {
        features.push({
          icon: '✅',
          text: 'Official domain of trusted company',
          type: 'positive'
        });
      }
    }

    if (url.startsWith('https://')) {
      features.push({
        icon: '🔐',
        text: 'Uses HTTPS encryption',
        type: 'positive'
      });
    }

    if (hostname.length > 30) {
      features.push({
        icon: '📏',
        text: 'Unusually long domain name',
        type: 'negative'
      });
    }

    if (this.calculateEntropy(hostname) > 3.5) {
      features.push({
        icon: '🎲',
        text: 'Domain appears randomly generated',
        type: 'negative'
      });
    }

    // Add confidence-based message
    if (result.confidence > 0.8) {
      features.push({
        icon: '🎯',
        text: 'High confidence in classification',
        type: 'positive'
      });
    } else if (result.confidence < 0.6) {
      features.push({
        icon: '⚠️',
        text: 'Low confidence - exercise caution',
        type: 'neutral'
      });
    }

    return features;
  }

  isOfficialDomain(hostname) {
    const officialDomains = [
      'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'github.com',
      'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com', 'instagram.com'
    ];
    return officialDomains.some(domain => hostname.endsWith(domain));
  }

  calculateEntropy(text) {
    const freq = {};
    for (let char of text) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    for (let char in freq) {
      const p = freq[char] / text.length;
      entropy += -p * Math.log2(p);
    }

    return entropy;
  }

  showError(message) {
    document.getElementById('error').textContent = message;
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('status').className = 'status error';
    document.getElementById('status').textContent = '❌ Error';
  }

  showMessage(message, type) {
    const messageDiv = document.createElement('div');
    messageDiv.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      background: ${type === 'success' ? '#4CAF50' : '#f44336'};
      color: white;
      padding: 10px 20px;
      border-radius: 5px;
      z-index: 10000;
      font-family: Arial, sans-serif;
    `;
    messageDiv.textContent = message;

    document.body.appendChild(messageDiv);

    setTimeout(() => {
      if (document.body.contains(messageDiv)) {
        document.body.removeChild(messageDiv);
      }
    }, 3000);
  }
}

// Initialize when popup loads
document.addEventListener('DOMContentLoaded', () => {
  new EnhancedPhishingDetectorPopup();
});