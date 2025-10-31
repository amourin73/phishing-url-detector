// Content script for page analysis and URL scanning
class ContentScriptManager {
    constructor() {
        this.isInitialized = false;
        this.init();
    }

    async init() {
        try {
            console.log('🔄 Phishing Detector Content Script Loading...');

            // Wait for page to be ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.initializeScanner());
            } else {
                await this.initializeScanner();
            }

            this.setupMessageListener();
            this.isInitialized = true;

            console.log('✅ Phishing Detector Content Script Ready');
        } catch (error) {
            console.error('❌ Content Script Error:', error);
        }
    }

    async initializeScanner() {
        try {
            // Inject the page scanner
            await this.injectPageScanner();

            // Wait a bit for the page to fully load
            setTimeout(() => {
                if (window.PageURLScanner) {
                    this.pageScanner = new window.PageURLScanner();
                    console.log('✅ Page Scanner Initialized');

                    // Auto-scan after delay
                    setTimeout(() => {
                        this.autoScanPage();
                    }, 2000);
                }
            }, 1000);

        } catch (error) {
            console.error('Error initializing scanner:', error);
        }
    }

    injectPageScanner() {
        return new Promise((resolve, reject) => {
            try {
                // Remove existing scanner if any
                const existingScript = document.getElementById('phishing-scanner-script');
                if (existingScript) {
                    existingScript.remove();
                }

                const script = document.createElement('script');
                script.id = 'phishing-scanner-script';
                script.src = chrome.runtime.getURL('page_scanner.js');
                script.onload = () => {
                    console.log('✅ Page Scanner Script Injected');
                    resolve();
                };
                script.onerror = (error) => {
                    console.error('❌ Script Injection Failed:', error);
                    reject(error);
                };

                (document.head || document.documentElement).appendChild(script);
            } catch (error) {
                reject(error);
            }
        });
    }

    setupMessageListener() {
        // Listen for messages from popup/background
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            console.log('📨 Content Script Received Message:', request);

            switch (request.action) {
                case 'scanPage':
                    this.handleScanPage(request, sendResponse);
                    return true; // Keep channel open for async response

                case 'getStatus':
                    sendResponse({
                        status: 'ready',
                        initialized: this.isInitialized,
                        scannerReady: !!this.pageScanner
                    });
                    break;

                case 'ping':
                    sendResponse({ pong: true, tabId: sender.tab?.id });
                    break;

                default:
                    sendResponse({ error: 'Unknown action' });
            }
        });
    }

    async handleScanPage(request, sendResponse) {
        try {
            console.log('🔄 Starting page scan from content script...');

            if (!this.pageScanner) {
                // Try to re-initialize scanner
                await this.initializeScanner();

                if (!this.pageScanner) {
                    throw new Error('Page scanner not available');
                }
            }

            await this.pageScanner.scanPage();
            sendResponse({
                success: true,
                message: 'Page scan completed successfully'
            });

        } catch (error) {
            console.error('Page scan error:', error);
            sendResponse({
                success: false,
                error: error.message
            });
        }
    }

    async autoScanPage() {
        try {
            if (this.pageScanner && !this.pageScanner.scanning) {
                console.log('🔍 Auto-scanning page for URLs...');
                await this.pageScanner.scanPage();
            }
        } catch (error) {
            console.log('Auto-scan skipped or failed:', error.message);
        }
    }
}

// Initialize content script
new ContentScriptManager();