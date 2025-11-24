document.addEventListener("DOMContentLoaded", () => {
  const blockedCountEl = document.getElementById("blockedCount");
  const toggleBtn = document.getElementById("toggle");
  const domainInput = document.getElementById("domainInput");
  const addWhitelist = document.getElementById("addWhitelist");
  const addBlacklist = document.getElementById("addBlacklist");
  const whitelistEl = document.getElementById("whitelist");
  const blacklistEl = document.getElementById("blacklist");

  // Load current tab's blocked count
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    chrome.storage.local.get("blockedPerTab", (data) => {
      const blocked = data.blockedPerTab || {};
      blockedCountEl.textContent = blocked[tab.id] || 0;
    });
  });

  // Whitelist / Blacklist logic
  chrome.storage.local.get(["whitelist", "blacklist"], (data) => {
    const wl = data.whitelist || [];
    const bl = data.blacklist || [];
    wl.forEach(d => {
      let li = document.createElement("li"); li.textContent = d; whitelistEl.append(li);
    });
    bl.forEach(d => {
      let li = document.createElement("li"); li.textContent = d; blacklistEl.append(li);
    });
  });

  addWhitelist.onclick = () => {
    const domain = domainInput.value.trim();
    if (!domain) return;
    chrome.storage.local.get("whitelist", (data) => {
      const wl = data.whitelist || [];
      wl.push(domain);
      chrome.storage.local.set({ whitelist: wl }, () => {
        whitelistEl.appendChild(Object.assign(document.createElement("li"), { textContent: domain }));
      });
    });
  };

  addBlacklist.onclick = () => {
    const domain = domainInput.value.trim();
    if (!domain) return;
    chrome.storage.local.get("blacklist", (data) => {
      const bl = data.blacklist || [];
      bl.push(domain);
      chrome.storage.local.set({ blacklist: bl }, () => {
        blacklistEl.appendChild(Object.assign(document.createElement("li"), { textContent: domain }));
      });
    });
  };

  toggleBtn.onclick = () => {
    // You can implement toggle logic: store a value in storage to enable / disable blocking
    chrome.storage.local.get("enabled", (data) => {
      const enabled = data.enabled === false ? true : false;
      chrome.storage.local.set({ enabled });
      toggleBtn.textContent = enabled ? "Disable Blocking" : "Enable Blocking";
    });
  };
});

