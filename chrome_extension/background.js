// Background script for phishing detection
class PhishingBackground {
  constructor() {
    this.apiBaseUrl = 'http://localhost:5000';
    this.init();
  }

  init() {
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.checkAndNotify(tab);
      }
    });

    // Listen for navigation
    chrome.webNavigation.onCompleted.addListener((details) => {
      chrome.tabs.get(details.tabId, (tab) => {
        if (tab.url) {
          this.checkAndNotify(tab);
        }
      });
    });

    console.log('Phishing detector background script loaded');
  }

  async checkAndNotify(tab) {
    try {
      const result = await this.checkUrl(tab.url);

      if (result.success && result.is_phishing) {
        this.showWarning(tab.id, result);
      }
    } catch (error) {
      console.error('Error checking URL:', error);
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

  showWarning(tabId, result) {
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: showWarningBanner,
      args: [result]
    });
  }
}

// Function to inject warning banner
function showWarningBanner(result) {
  // Remove existing banner if present
  const existingBanner = document.getElementById('phishing-warning-banner');
  if (existingBanner) {
    existingBanner.remove();
  }

  const banner = document.createElement('div');
  banner.id = 'phishing-warning-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background: linear-gradient(135deg, #ff6b6b, #ee5a52);
    color: white;
    padding: 15px;
    text-align: center;
    font-family: Arial, sans-serif;
    font-size: 14px;
    font-weight: bold;
    z-index: 10000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
  `;

  banner.innerHTML = `
    <span>🚨 WARNING: This site has been detected as potentially phishing</span>
    <button id="close-warning" style="
      background: rgba(255,255,255,0.2);
      border: 1px solid white;
      color: white;
      padding: 5px 10px;
      border-radius: 4px;
      cursor: pointer;
    ">Dismiss</button>
    <button id="learn-more" style="
      background: rgba(255,255,255,0.2);
      border: 1px solid white;
      color: white;
      padding: 5px 10px;
      border-radius: 4px;
      cursor: pointer;
    ">Learn More</button>
  `;

  document.body.prepend(banner);

  // Add event listeners
  document.getElementById('close-warning').addEventListener('click', () => {
    banner.remove();
  });

  document.getElementById('learn-more').addEventListener('click', () => {
    alert(`Phishing Detection Details:\n\n` +
          `Confidence: ${(result.confidence * 100).toFixed(1)}%\n` +
          `Probability: ${(result.probability * 100).toFixed(1)}%\n\n` +
          `This site exhibits characteristics commonly found in phishing websites. ` +
          `Be careful about entering any personal or financial information.`);
  });
}

// Initialize background script
new PhishingBackground();