const API_URL = "https://phishing-detector-npfz.onrender.com/check-url";

// DOM elements
const currentUrlEl = document.getElementById("current-url");
const scanningState = document.getElementById("scanning-state");
const verdictState = document.getElementById("verdict-state");
const errorState = document.getElementById("error-state");
const verdictIcon = document.getElementById("verdict-icon");
const verdictText = document.getElementById("verdict-text");
const confidenceText = document.getElementById("confidence-text");
const legitBar = document.getElementById("legit-bar");
const phishBar = document.getElementById("phish-bar");
const legitPct = document.getElementById("legit-pct");
const phishPct = document.getElementById("phish-pct");
const rescanBtn = document.getElementById("rescan-btn");
const errorMessage = document.getElementById("error-message");

// Show scanning state
function showScanning() {
  scanningState.style.display = "block";
  verdictState.style.display = "none";
  errorState.style.display = "none";
}

// Show verdict state
function showVerdict(data) {
  scanningState.style.display = "none";
  errorState.style.display = "none";
  verdictState.style.display = "block";

  if (data.verdict === "LEGITIMATE") {
    verdictIcon.textContent = "✅";
    verdictText.textContent = "Legitimate";
    verdictText.className = "verdict-text legitimate";
  } else {
    verdictIcon.textContent = "🚨";
    verdictText.textContent = "Phishing / Malicious";
    verdictText.className = "verdict-text phishing";
  }

  confidenceText.textContent = `Confidence: ${data.confidence}%`;

  // Animate bars
  setTimeout(() => {
    legitBar.style.width = `${data.legitimate_probability}%`;
    phishBar.style.width = `${data.phishing_probability}%`;
    legitPct.textContent = `${data.legitimate_probability}%`;
    phishPct.textContent = `${data.phishing_probability}%`;
  }, 100);
}

// Show error state
function showError(message) {
  scanningState.style.display = "none";
  verdictState.style.display = "none";
  errorState.style.display = "block";
  errorMessage.textContent = message;
}

// Main scan function
async function scanURL(url) {
  showScanning();
  currentUrlEl.textContent = url;

  try {
    // Hard timeout of 30 seconds
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }

    const data = await response.json();

    if (data.verdict === "ERROR") {
      showError("Analysis failed. Check backend.");
    } else {
      showVerdict(data);
    }
  } catch (err) {
    showError("Cannot reach backend. Is the server running?");
    document.getElementById("backend-status").style.color = "#f44336";
  }
}

// Get current tab URL and scan it
function init() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (tab && tab.url) {
      const url = tab.url;

      // Block internal browser pages
      if (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("about:") ||
        url.startsWith("edge://") ||
        url.startsWith("file://")
      ) {
        currentUrlEl.textContent = url;
        showError("This page cannot be scanned.");
        return;
      }

      scanURL(url);
    } else {
      showError("Could not get current tab URL.");
    }
  });
}
// Rescan button
rescanBtn.addEventListener("click", init);

// Run on popup open
init();
