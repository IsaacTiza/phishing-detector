// Background service worker
// Listens for tab updates and stores the current URL

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    // Store the latest URL for this tab
    chrome.storage.local.set({
      [`tab_${tabId}`]: tab.url,
    });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  // Clean up storage when tab is closed
  chrome.storage.local.remove(`tab_${tabId}`);
});
