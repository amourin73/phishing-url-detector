// Content script for additional page analysis
class PageAnalyzer {
  constructor() {
    this.analyzePage();
  }

  analyzePage() {
    // Analyze page content for phishing indicators
    const indicators = this.detectPhishingIndicators();

    if (indicators.length > 0) {
      this.sendAnalysisToBackground(indicators);
    }
  }

  detectPhishingIndicators() {
    const indicators = [];

    // Check for suspicious form fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const emailFields = document.querySelectorAll('input[type="email"]');
    const creditCardFields = document.querySelectorAll('input[autocomplete*="cc"]');

    if (passwordFields.length > 0) {
      indicators.push('Contains password fields');
    }

    if (emailFields.length > 0) {
      indicators.push('Contains email input fields');
    }

    if (creditCardFields.length > 0) {
      indicators.push('Contains credit card input fields');
    }

    // Check for suspicious text content
    const pageText = document.body.innerText.toLowerCase();
    const suspiciousKeywords = [
      'verify your account', 'security alert', 'suspicious activity',
      'update your information', 'password reset', 'account verification',
      'confirm your identity', 'login to continue'
    ];

    suspiciousKeywords.forEach(keyword => {
      if (pageText.includes(keyword)) {
        indicators.push(`Contains suspicious text: "${keyword}"`);
      }
    });

    // Check for brand impersonation in images
    const images = document.querySelectorAll('img[src*="logo"], img[alt*="logo"]');
    images.forEach(img => {
      const src = img.src.toLowerCase();
      const alt = img.alt.toLowerCase();

      if (src.includes('google') || alt.includes('google') ||
          src.includes('facebook') || alt.includes('facebook') ||
          src.includes('microsoft') || alt.includes('microsoft') ||
          src.includes('apple') || alt.includes('apple') ||
          src.includes('paypal') || alt.includes('paypal')) {
        indicators.push('Uses brand logos from well-known companies');
      }
    });

    return indicators;
  }

  sendAnalysisToBackground(indicators) {
    chrome.runtime.sendMessage({
      type: 'PAGE_ANALYSIS',
      url: window.location.href,
      indicators: indicators
    });
  }
}

// Initialize page analyzer
new PageAnalyzer();