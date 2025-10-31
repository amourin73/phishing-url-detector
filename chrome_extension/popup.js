document.addEventListener('DOMContentLoaded', function() {
    const urlText = document.getElementById('url-text');
    const resultDiv = document.getElementById('result');
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const confidenceText = document.getElementById('confidence');
    const checkBtn = document.getElementById('check-btn');
    const errorDiv = document.getElementById('error');

    // Get current tab URL
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentTab = tabs[0];
        if (currentTab && currentTab.url) {
            urlText.textContent = currentTab.url;
            // Auto-check the URL
            checkURL(currentTab.url);
        } else {
            urlText.textContent = 'Cannot access URL';
        }
    });

    // Check URL function
    async function checkURL(url) {
        try {
            showLoading();
            errorDiv.classList.add('hidden');

            const response = await fetch(`http://localhost:5000/predict?url=${encodeURIComponent(url)}`);
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            displayResult(data.result);
        } catch (error) {
            console.error('Error:', error);
            errorDiv.textContent = 'Error: ' + error.message;
            errorDiv.classList.remove('hidden');
            resultDiv.classList.add('hidden');
        }
    }

    function displayResult(result) {
        resultDiv.className = 'result';

        if (result.safe) {
            resultDiv.classList.add('safe');
            statusIcon.innerHTML = '✅';
            statusText.textContent = 'SAFE URL';
            statusText.style.color = '#155724';
        } else {
            resultDiv.classList.add('phishing');
            statusIcon.innerHTML = '🚨';
            statusText.textContent = 'PHISHING DETECTED';
            statusText.style.color = '#721c24';
        }

        confidenceText.textContent = `Confidence: ${(result.confidence * 100).toFixed(1)}%`;
        resultDiv.classList.remove('hidden');
    }

    function showLoading() {
        resultDiv.className = 'result';
        resultDiv.classList.remove('hidden');
        statusIcon.innerHTML = '⏳';
        statusText.textContent = 'Analyzing...';
        statusText.style.color = '#856404';
        confidenceText.textContent = 'Please wait';
    }

    // Manual check button
    checkBtn.addEventListener('click', function() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs[0] && tabs[0].url) {
                checkURL(tabs[0].url);
            }
        });
    });
});