// Page URL Scanner - Self-contained version
class PageURLScanner {
    constructor() {
        this.apiBaseUrl = 'http://localhost:5000';
        this.foundUrls = [];
        this.suspiciousUrls = [];
        this.scanning = false;
        this.isConnected = false;

        this.testConnection();
        console.log('🔍 PageURLScanner Initialized');
    }

    async testConnection() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/health`, {
                method: 'GET',
                timeout: 5000
            });
            this.isConnected = response.ok;
            console.log('✅ API Connection:', this.isConnected ? 'Connected' : 'Failed');
        } catch (error) {
            this.isConnected = false;
            console.warn('⚠️ API Connection Failed:', error.message);
        }
    }

    async scanPage() {
        if (this.scanning) {
            console.log('⚠️ Scan already in progress');
            return;
        }

        if (!this.isConnected) {
            this.showNotification('❌ Cannot connect to detection service. Please ensure the server is running on localhost:5000', 'red');
            return;
        }

        this.scanning = true;
        this.foundUrls = [];
        this.suspiciousUrls = [];

        try {
            this.showNotification('🔍 Scanning page for URLs...', 'blue');

            // Extract URLs from page content
            const pageUrls = await this.extractAllURLs();
            console.log(`📊 Found ${pageUrls.length} URLs to check`);

            if (pageUrls.length === 0) {
                this.showNotification('✅ No URLs found on this page', 'green');
                return;
            }

            // Check each URL
            let checkedCount = 0;
            for (const url of pageUrls) {
                try {
                    const result = await this.checkURL(url);
                    checkedCount++;

                    const urlInfo = {
                        url: url,
                        is_phishing: result.is_phishing,
                        confidence: result.confidence || result.probability || 0.5,
                        context: this.getURLContext(url)
                    };

                    this.foundUrls.push(urlInfo);

                    if (result.is_phishing) {
                        this.suspiciousUrls.push(urlInfo);
                    }

                    // Update progress every 5 URLs
                    if (checkedCount % 5 === 0) {
                        this.showNotification(`🔍 Checking URLs... (${checkedCount}/${pageUrls.length})`, 'blue');
                    }

                    // Small delay to avoid overwhelming the server
                    await this.delay(100);

                } catch (error) {
                    console.error(`Error checking URL ${url}:`, error);
                }
            }

            this.displayResults();

        } catch (error) {
            console.error('❌ Page scan error:', error);
            this.showNotification('❌ Error scanning page: ' + error.message, 'red');
        } finally {
            this.scanning = false;
        }
    }

    async extractAllURLs() {
        const urls = new Set();

        // 1. Extract from text content
        const textUrls = this.extractURLsFromText(this.getAllPageText());
        textUrls.forEach(url => urls.add(url));

        // 2. Extract from links
        const linkUrls = this.extractURLsFromLinks();
        linkUrls.forEach(url => urls.add(url));

        // 3. Extract from meta tags
        const metaUrls = this.extractURLsFromMeta();
        metaUrls.forEach(url => urls.add(url));

        // Filter out invalid URLs and current page URL
        const currentUrl = window.location.href;
        return Array.from(urls).filter(url =>
            url &&
            url.startsWith('http') &&
            url !== currentUrl &&
            url.length > 10
        );
    }

    extractURLsFromText(text) {
        const urlRegex = /(https?:\/\/[^\s<>"'{}\|\\^`[\]]+|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s<>"']*)?)/gi;
        const matches = text.match(urlRegex) || [];

        return matches.map(url => {
            // Clean and normalize URL
            if (!url.startsWith('http')) {
                url = 'http://' + url;
            }
            // Remove common trailing characters
            url = url.replace(/[.,;:!?'")\]}]+$/, '');
            return url.trim();
        }).filter(url => url.length > 8); // Filter out very short strings
    }

    extractURLsFromLinks() {
        const links = document.querySelectorAll('a[href]');
        const urls = [];

        links.forEach(link => {
            try {
                const href = link.href;
                if (href && href.startsWith('http') && !href.startsWith('javascript:')) {
                    urls.push(href);
                }
            } catch (error) {
                // Skip invalid URLs
            }
        });

        return urls;
    }

    extractURLsFromMeta() {
        const metaUrls = [];
        const metaTags = document.querySelectorAll('meta[content], meta[property]');

        metaTags.forEach(meta => {
            const content = meta.getAttribute('content') || meta.getAttribute('property') || '';
            const urls = this.extractURLsFromText(content);
            urls.forEach(url => metaUrls.push(url));
        });

        return metaUrls;
    }

    getAllPageText() {
        // Clone body to avoid modifying original
        const bodyClone = document.body.cloneNode(true);

        // Remove elements that don't contain meaningful text
        const elementsToRemove = bodyClone.querySelectorAll('script, style, noscript, iframe, svg, nav, header, footer');
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
        let context = text.substring(start, end).replace(/\s+/g, ' ').trim();

        if (context.length > 100) {
            context = '...' + context.substring(0, 97) + '...';
        }

        return context;
    }

    async checkURL(url) {
        if (!this.isConnected) {
            throw new Error('API not connected');
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        try {
            const response = await fetch(`${this.apiBaseUrl}/check`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
                signal: controller.signal
            });

            clearTimeout(timeout);

            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            clearTimeout(timeout);
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
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );

        let node;
        const nodesToProcess = [];

        while (node = walker.nextNode()) {
            if (node.textContent.trim().length > 10) { // Only process nodes with meaningful text
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
                    const regex = new RegExp(escapedUrl, 'gi');
                    newHTML = newHTML.replace(regex,
                        `<span class="phishing-highlight" data-phishing-url="${url}" 
                                style="background-color: #ffebee; border: 2px solid #f44336; 
                                       padding: 2px 4px; border-radius: 4px; cursor: pointer;
                                       position: relative; font-weight: bold;">
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

        // Add click handlers
        document.addEventListener('click', (e) => {
            if (e.target.closest('.phishing-highlight')) {
                e.preventDefault();
                const highlight = e.target.closest('.phishing-highlight');
                const url = highlight.getAttribute('data-phishing-url');
                this.showURLDetails(url);
            }
        });
    }

    removeExistingHighlights() {
        const existingHighlights = document.querySelectorAll('.phishing-highlight');
        existingHighlights.forEach(el => {
            const parent = el.parentNode;
            if (parent) {
                parent.replaceChild(document.createTextNode(el.textContent), el);
                parent.normalize();
            }
        });
    }

    showURLDetails(url) {
        const urlData = this.suspiciousUrls.find(item => item.url === url);
        if (!urlData) return;

        this.removeExistingModals();

        const modal = document.createElement('div');
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
                    <button id="phishing-modal-copy" style="
                        background: #2196F3;
                        color: white;
                        border: none;
                        padding: 8px 16px;
                        border-radius: 4px;
                        cursor: pointer;
                    ">Copy URL</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        document.getElementById('phishing-modal-close').addEventListener('click', () => {
            document.body.removeChild(modal);
        });

        document.getElementById('phishing-modal-copy').addEventListener('click', () => {
            navigator.clipboard.writeText(url).then(() => {
                alert('URL copied to clipboard');
            });
        });

        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                document.body.removeChild(modal);
            }
        });
    }

    removeExistingModals() {
        const existingModals = document.querySelectorAll('[style*="position: fixed"][style*="z-index: 10000"]');
        existingModals.forEach(modal => modal.remove());
    }

    showWarningNotification() {
        this.showNotification(
            `🚨 Found ${this.suspiciousUrls.length} suspicious URLs on this page`,
            'red',
            5000
        );
    }

    showNotification(message, color = 'blue', duration = 3000) {
        this.removeExistingNotifications();

        const notification = document.createElement('div');
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
            max-width: 400px;
            word-wrap: break-word;
        `;
        notification.textContent = message;
        notification.className = 'phishing-notification';

        notification.addEventListener('click', () => {
            document.body.removeChild(notification);
        });

        document.body.appendChild(notification);

        setTimeout(() => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
            }
        }, duration);
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
                <button id="rescan-page" style="
                    background: #2196F3; color: white; border: none; 
                    padding: 8px 12px; border-radius: 4px; cursor: pointer;
                    font-size: 12px; flex: 1;
                ">Rescan</button>
            </div>
        `;

        document.body.appendChild(panel);

        document.getElementById('close-panel').addEventListener('click', () => {
            this.removeResultsPanel();
        });

        document.getElementById('rescan-page').addEventListener('click', () => {
            this.removeResultsPanel();
            this.scanPage();
        });
    }

    removeResultsPanel() {
        const existingPanel = document.getElementById('phishing-scan-results');
        if (existingPanel) {
            document.body.removeChild(existingPanel);
        }
    }

    removeExistingNotifications() {
        const existingNotifications = document.querySelectorAll('.phishing-notification');
        existingNotifications.forEach(notification => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
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

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Make it globally available
window.PageURLScanner = PageURLScanner;
console.log('✅ PageURLScanner class loaded');

// Auto-initialize when injected
if (typeof autoInitialize !== 'undefined' && autoInitialize) {
    setTimeout(() => {
        window.pageScanner = new PageURLScanner();
        console.log('✅ PageURLScanner Auto-Initialized');
    }, 1000);
}