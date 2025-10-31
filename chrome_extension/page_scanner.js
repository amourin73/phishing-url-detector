// Page URL Scanner - Self-contained class
class PageURLScanner {
  constructor() {
    this.apiBaseUrl = 'http://localhost:5000';
    this.foundUrls = [];
    this.suspiciousUrls = [];
    this.scanning = false;
    console.log('✅ PageURLScanner Initialized');
  }

  async scanPage() {
    if (this.scanning) {
      console.log('⚠️ Scan already in progress');
      return;
    }

    this.scanning = true;
    this.foundUrls = [];
    this.suspiciousUrls = [];

    try {
      this.showNotification('🔍 Scanning page for URLs...', 'blue');

      // Extract URLs from page
      const urls = this.extractAllURLs();
      console.log(`📊 Found ${urls.length} URLs to check:`, urls);

      if (urls.length === 0) {
        this.showNotification('✅ No URLs found on this page', 'green');
        return;
      }

      // Check each URL
      for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        try {
          console.log(`🔍 Checking URL ${i + 1}/${urls.length}:`, url);
          const result = await this.checkURL(url);

          const urlInfo = {
            url: url,
            is_phishing: result.is_phishing,
            confidence: result.confidence || result.probability || 0.5,
            context: this.getURLContext(url)
          };

          this.foundUrls.push(urlInfo);

          if (result.is_phishing) {
            this.suspiciousUrls.push(urlInfo);
            console.log('🚨 Found phishing URL:', url);
          }

          // Update progress
          if ((i + 1) % 3 === 0 || i === urls.length - 1) {
            this.showNotification(`🔍 Checked ${i + 1}/${urls.length} URLs...`, 'blue');
          }

          // Small delay to avoid overwhelming the server
          await new Promise(resolve => setTimeout(resolve, 200));

        } catch (error) {
          console.error(`Error checking URL ${url}:`, error);
        }
      }

      console.log('✅ Scan completed:', {
        total: this.foundUrls.length,
        suspicious: this.suspiciousUrls.length
      });

      this.displayResults();

    } catch (error) {
      console.error('❌ Page scan error:', error);
      this.showNotification('❌ Error scanning page: ' + error.message, 'red');
    } finally {
      this.scanning = false;
    }
  }

  extractAllURLs() {
    const urls = new Set();
    const currentUrl = window.location.href;

    console.log('🔍 Extracting URLs from page...');

    // 1. Extract from text content
    const pageText = this.getAllPageText();
    const textUrls = this.extractURLsFromText(pageText);
    textUrls.forEach(url => {
      if (url !== currentUrl) urls.add(url);
    });

    // 2. Extract from links
    const links = document.querySelectorAll('a[href]');
    links.forEach(link => {
      try {
        const href = link.href;
        if (href && href.startsWith('http') && href !== currentUrl) {
          urls.add(href);
        }
      } catch (error) {
        // Skip invalid URLs
      }
    });

    // 3. Extract from meta tags
    const metaTags = document.querySelectorAll('meta[content]');
    metaTags.forEach(meta => {
      const content = meta.getAttribute('content');
      const metaUrls = this.extractURLsFromText(content);
      metaUrls.forEach(url => {
        if (url !== currentUrl) urls.add(url);
      });
    });

    console.log('📊 Extracted URLs:', Array.from(urls));
    return Array.from(urls);
  }

  extractURLsFromText(text) {
    if (!text) return [];

    const urlRegex = /(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/gi;
    const matches = text.match(urlRegex) || [];

    return matches.map(url => {
      // Ensure URL has protocol
      if (url.startsWith('www.')) {
        url = 'http://' + url;
      }
      // Clean URL
      return url.replace(/[.,;:!?'")}\]]+$/, '').trim();
    }).filter(url => url.length > 8); // Filter out very short strings
  }

  getAllPageText() {
    // Clone body to avoid modifying original
    const bodyClone = document.body.cloneNode(true);

    // Remove elements that don't contain meaningful text
    const elementsToRemove = bodyClone.querySelectorAll('script, style, noscript, iframe');
    elementsToRemove.forEach(el => el.remove());

    return bodyClone.textContent || bodyClone.innerText || '';
  }

  getURLContext(url, text = null) {
    if (!text) {
      text = this.getAllPageText();
    }

    const index = text.indexOf(url);
    if (index === -1) return 'Found in page content';

    const start = Math.max(0, index - 30);
    const end = Math.min(text.length, index + url.length + 30);
    return text.substring(start, end).replace(/\s+/g, ' ').trim();
  }

  async checkURL(url) {
    console.log('🌐 Checking URL with API:', url);

    try {
      const response = await fetch('http://localhost:5000/check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const result = await response.json();
      console.log('✅ URL check result:', result);
      return result;

    } catch (error) {
      console.error('❌ URL check failed:', error);
      throw error;
    }
  }

  displayResults() {
    this.removeExistingHighlights();

    if (this.suspiciousUrls.length === 0) {
      this.showNotification(`✅ Scan complete: No suspicious URLs found (checked ${this.foundUrls.length} URLs)`, 'green');
      return;
    }

    this.highlightSuspiciousURLs();
    this.showWarningNotification();
    this.createResultsPanel();
  }

  highlightSuspiciousURLs() {
    console.log('🎨 Highlighting suspicious URLs...');

    // Walk through all text nodes
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    let node;
    const nodesToProcess = [];

    while (node = walker.nextNode()) {
      if (node.textContent.trim().length > 10) {
        nodesToProcess.push(node);
      }
    }

    nodesToProcess.forEach(textNode => {
      const text = textNode.textContent;
      let hasMatch = false;
      let newHTML = text;

      this.suspiciousUrls.forEach(item => {
        const url = item.url;
        if (text.includes(url)) {
          hasMatch = true;
          const escapedUrl = this.escapeRegex(url);
          const regex = new RegExp(escapedUrl, 'g');
          newHTML = newHTML.replace(regex,
            `<span class="phishing-highlight" data-phishing-url="${url}" 
                    style="background-color: #ffebee; border: 2px solid #f44336; 
                           padding: 2px 4px; border-radius: 4px; cursor: pointer;
                           position: relative; font-weight: bold; display: inline-block;">
             ${url}
             <span style="position: absolute; top: -8px; right: -8px; 
                         background: #f44336; color: white; border-radius: 50%; 
                         width: 16px; height: 16px; font-size: 10px; 
                         text-align: center; line-height: 16px;">!</span>
             </span>`
          );
        }
      });

      if (hasMatch) {
        const wrapper = document.createElement('span');
        wrapper.innerHTML = newHTML;
        textNode.parentNode.replaceChild(wrapper, textNode);
      }
    });

    // Add click handlers to highlighted URLs
    document.addEventListener('click', (e) => {
      const highlight = e.target.closest('.phishing-highlight');
      if (highlight) {
        e.preventDefault();
        e.stopPropagation();
        const url = highlight.getAttribute('data-phishing-url');
        this.showURLDetails(url);
      }
    });

    console.log('✅ Highlighting completed');
  }

  showURLDetails(url) {
    const urlData = this.suspiciousUrls.find(item => item.url === url);
    if (!urlData) return;

    // Remove existing modal
    const existingModal = document.getElementById('phishing-details-modal');
    if (existingModal) {
      existingModal.remove();
    }

    const modal = document.createElement('div');
    modal.id = 'phishing-details-modal';
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.7);
      z-index: 10000;
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: Arial, sans-serif;
    `;

    modal.innerHTML = `
      <div style="
        background: white;
        border-radius: 10px;
        padding: 20px;
        max-width: 500px;
        width: 90%;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
      ">
        <h3 style="color: #f44336; margin-top: 0;">🚨 Suspicious URL Detected</h3>
        <p><strong>URL:</strong></p>
        <code style="
          background: #f5f5f5;
          padding: 10px;
          border-radius: 5px;
          display: block;
          overflow-wrap: break-word;
          margin: 10px 0;
          font-size: 12px;
        ">${url}</code>
        
        <p><strong>Confidence:</strong> ${(urlData.confidence * 100).toFixed(1)}%</p>
        <p><strong>Context:</strong> "${urlData.context}"</p>
        
        <div style="margin-top: 20px; text-align: right;">
          <button id="phishing-modal-close" style="
            background: #666;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
          ">Close</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    document.getElementById('phishing-modal-close').addEventListener('click', () => {
      modal.remove();
    });

    // Close on background click
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
  }

  showNotification(message, color = 'blue') {
    // Remove existing notifications
    const existing = document.querySelectorAll('.phishing-notification');
    existing.forEach(el => el.remove());

    const notification = document.createElement('div');
    notification.className = 'phishing-notification';
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${this.getColor(color)};
      color: white;
      padding: 15px 20px;
      border-radius: 5px;
      z-index: 9999;
      font-family: Arial, sans-serif;
      font-weight: bold;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      cursor: pointer;
      max-width: 300px;
    `;
    notification.textContent = message;

    notification.addEventListener('click', () => {
      notification.remove();
    });

    document.body.appendChild(notification);

    setTimeout(() => {
      if (document.body.contains(notification)) {
        notification.remove();
      }
    }, 4000);
  }

  getColor(type) {
    const colors = {
      red: '#f44336',
      green: '#4CAF50',
      blue: '#2196F3',
      orange: '#FF9800'
    };
    return colors[type] || colors.blue;
  }

  showWarningNotification() {
    this.showNotification(
      `🚨 Found ${this.suspiciousUrls.length} suspicious URLs`,
      'red'
    );
  }

  createResultsPanel() {
    this.removeResultsPanel();

    const panel = document.createElement('div');
    panel.id = 'phishing-scan-results';
    panel.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: white;
      border: 2px solid #f44336;
      border-radius: 10px;
      padding: 15px;
      z-index: 9998;
      font-family: Arial, sans-serif;
      max-width: 400px;
      max-height: 300px;
      overflow-y: auto;
      box-shadow: 0 4px 20px rgba(0,0,0,0.2);
      color: #333;
    `;

    panel.innerHTML = `
      <h4 style="margin: 0 0 10px 0; color: #f44336;">
        🚨 Suspicious URLs: ${this.suspiciousUrls.length}
      </h4>
      <div style="font-size: 12px; max-height: 200px; overflow-y: auto;">
        ${this.suspiciousUrls.map(item => `
          <div style="margin-bottom: 8px; padding: 8px; background: #ffebee; border-radius: 4px; border-left: 3px solid #f44336;">
            <div style="font-weight: bold; margin-bottom: 4px;">${this.shortenURL(item.url)}</div>
            <div>Confidence: ${(item.confidence * 100).toFixed(1)}%</div>
          </div>
        `).join('')}
      </div>
      <div style="margin-top: 10px; display: flex; gap: 5px;">
        <button id="close-panel" style="
          background: #f44336; color: white; border: none; 
          padding: 8px 12px; border-radius: 4px; cursor: pointer;
          font-size: 12px; flex: 1;
        ">Close</button>
      </div>
    `;

    document.body.appendChild(panel);

    document.getElementById('close-panel').addEventListener('click', () => {
      this.removeResultsPanel();
    });
  }

  removeResultsPanel() {
    const panel = document.getElementById('phishing-scan-results');
    if (panel) panel.remove();
  }

  removeExistingHighlights() {
    const highlights = document.querySelectorAll('.phishing-highlight');
    highlights.forEach(highlight => {
      const parent = highlight.parentNode;
      if (parent) {
        parent.replaceChild(document.createTextNode(highlight.textContent), highlight);
        parent.normalize();
      }
    });
  }

  shortenURL(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname + (urlObj.pathname !== '/' ? urlObj.pathname.substring(0, 20) + '...' : '');
    } catch {
      return url.length > 40 ? url.substring(0, 37) + '...' : url;
    }
  }

  escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}

// Make the class available globally
window.PageURLScanner = PageURLScanner;
console.log('✅ PageURLScanner class defined and ready to use');

// Auto-test: Check if class can be instantiated
try {
  const testScanner = new PageURLScanner();
  console.log('✅ PageURLScanner instantiation test passed');
} catch (error) {
  console.error('❌ PageURLScanner instantiation failed:', error);
}