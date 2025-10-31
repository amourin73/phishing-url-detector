// Content script - Main world execution
console.log('🔄 Phishing Detector Content Script Loaded');

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Content script received:', request.action);

  if (request.action === 'scanPage') {
    handlePageScan().then(result => {
      sendResponse(result);
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true; // Keep message channel open
  }

  if (request.action === 'ping') {
    sendResponse({ status: 'ready' });
    return false;
  }
});

async function handlePageScan() {
  console.log('🔄 Starting page scan...');

  try {
    // Use chrome.scripting API to inject and execute in page context
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // First, inject the page_scanner.js script
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['page_scanner.js']
    });

    console.log('✅ Page scanner script injected');

    // Then execute the scanner
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: startPageScan,
      args: []
    });

    console.log('✅ Page scan executed:', results);

    return {
      success: true,
      message: 'Page scan completed successfully',
      results: results[0]?.result
    };

  } catch (error) {
    console.error('❌ Page scan error:', error);
    throw new Error(`Failed to scan page: ${error.message}`);
  }
}

// This function will be executed in the page context
function startPageScan() {
  return new Promise((resolve) => {
    console.log('🔍 Starting page scan in page context...');

    // Check if scanner class exists
    if (typeof PageURLScanner === 'undefined') {
      throw new Error('PageURLScanner class not found in page context');
    }

    // Create scanner instance and start scanning
    const scanner = new PageURLScanner();
    scanner.scanPage().then(() => {
      resolve({
        foundUrls: scanner.foundUrls.length,
        suspiciousUrls: scanner.suspiciousUrls.length,
        status: 'completed'
      });
    }).catch(error => {
      resolve({
        error: error.message,
        status: 'failed'
      });
    });
  });
}