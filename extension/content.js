// Content script — runs inside every webpage
// Currently minimal — reserved for future DOM analysis

(function () {
  // Send current page URL to background worker
  chrome.runtime.sendMessage({
    type: "PAGE_LOADED",
    url: window.location.href,
  });
})();
