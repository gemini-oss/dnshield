// Background service worker for DNShield

let ws = null;
let blockedDomains = new Set();
let blockHistory = [];
const MAX_HISTORY = 100;
let isConnected = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_DELAY = 5000; // 5 seconds
let pingInterval = null;
let keepAliveInterval = null;
let syncInterval = null;
const SYNC_INTERVAL = 30000; // Sync every 30 seconds
const BROWSER_PROCESS_KEYWORDS = ["chrome", "google chrome", "browser"];

function isBrowserProcess(processName) {
  if (!processName || typeof processName !== "string") {
    return false;
  }
  const lower = processName.toLowerCase();
  return BROWSER_PROCESS_KEYWORDS.some((keyword) => lower.includes(keyword));
}

function sanitizeHistoryEntries(history) {
  if (!Array.isArray(history)) {
    return [];
  }

  const sanitized = [];

  for (const item of history) {
    if (!item || typeof item !== "object") {
      continue;
    }

    const domain =
      typeof item.domain === "string" && item.domain.trim().length > 0
        ? item.domain.trim()
        : "";
    if (!domain) {
      continue;
    }

    const processName =
      typeof item.process === "string" && item.process.trim().length > 0
        ? item.process
        : "Unknown";

    let timestamp = null;
    const rawTimestamp = item.timestamp;
    if (typeof rawTimestamp === "string") {
      const parsed = new Date(rawTimestamp);
      if (!Number.isNaN(parsed.getTime())) {
        timestamp = parsed.toISOString();
      }
    } else if (rawTimestamp instanceof Date) {
      timestamp = rawTimestamp.toISOString();
    } else if (typeof rawTimestamp === "number") {
      const parsed = new Date(rawTimestamp);
      if (!Number.isNaN(parsed.getTime())) {
        timestamp = parsed.toISOString();
      }
    }

    if (!timestamp) {
      continue;
    }

    const hasBrowserFlag = item.fromBrowser === true;
    const browserProcess = isBrowserProcess(processName);

    if (!hasBrowserFlag && !browserProcess) {
      continue;
    }

    sanitized.push({
      ...item,
      domain,
      process: processName,
      timestamp,
      fromBrowser: true,
    });
  }

  if (sanitized.length > MAX_HISTORY) {
    return sanitized.slice(0, MAX_HISTORY);
  }

  return sanitized;
}

function persistState() {
  blockHistory = sanitizeHistoryEntries(blockHistory);
  const sanitizedDomains = Array.from(blockedDomains)
    .map((domain) => extractDomain(domain))
    .filter(Boolean);
  blockedDomains = new Set(sanitizedDomains);
  chrome.storage.local.set({
    blockedDomains: sanitizedDomains,
    blockHistory,
  });
}

function clearBlockHistory() {
  blockHistory = [];
  persistState();
}

function getUniqueBlockedSiteCount() {
  if (!Array.isArray(blockHistory)) {
    return 0;
  }

  const uniqueDomains = new Set();
  for (const entry of blockHistory) {
    if (
      entry &&
      typeof entry.domain === "string" &&
      entry.domain.trim().length > 0
    ) {
      uniqueDomains.add(entry.domain);
    }
  }
  return uniqueDomains.size;
}

// Secure token storage using session storage (memory-only, cleared on browser close)
async function getAuthToken() {
  try {
    // First try managed storage (enterprise policy - highest priority)
    const managedResult = await chrome.storage.managed.get(["authToken"]);
    if (managedResult.authToken) {
      console.log("Using auth token from enterprise policy");
      return managedResult.authToken;
    }

    // Use session storage for non-enterprise deployments (memory-only)
    const sessionResult = await chrome.storage.session.get([
      "auth_token",
      "expires_at",
    ]);

    if (sessionResult.auth_token) {
      // Check if token is expired
      const now = Date.now();
      const expiresAt = sessionResult.expires_at || 0;

      if (now < expiresAt) {
        return sessionResult.auth_token;
      }
      console.log("Session token expired, clearing...");
      await chrome.storage.session.remove(["auth_token", "expires_at"]);
    }

    // One-time migration from local storage to session storage
    const localResult = await chrome.storage.local.get(["dnshield_auth_token"]);
    if (localResult.dnshield_auth_token) {
      console.log(
        "Migrating token from local storage to secure session storage"
      );

      // Store in session storage with 1-hour expiry
      await chrome.storage.session.set({
        auth_token: localResult.dnshield_auth_token,
        expires_at: Date.now() + 3600 * 1000,
      });

      // Clear from local storage to prevent further use
      await chrome.storage.local.remove(["dnshield_auth_token"]);

      return localResult.dnshield_auth_token;
    }

    console.warn("No auth token found. Extension must be configured via:");
    console.warn("1. Enterprise policy (Google Admin Console)");
    console.warn("2. Native messaging to request token from DNShield app");
    return null;
  } catch (error) {
    console.error("Error accessing auth token:", error);
    return null;
  }
}

// Get WebSocket URL from managed storage or use default
async function getWebSocketUrl() {
  return new Promise((resolve) => {
    chrome.storage.managed.get(["websocketUrl"], (result) => {
      resolve(result.websocketUrl || "ws://localhost:8876/ws");
    });
  });
}

// Connect to WebSocket server
async function connectWebSocket() {
  // Prevent duplicate connection attempts
  if (
    ws &&
    (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)
  ) {
    console.log("WebSocket connection already in progress or established");
    return;
  }

  console.log("Connecting to DNShield WebSocket server...");

  // Clean up any existing connection
  if (ws) {
    ws.close();
    ws = null;
  }

  try {
    // Get auth token
    const authToken = await getAuthToken();
    if (!authToken) {
      console.error("No authentication token available");
      // Schedule retry
      setTimeout(() => connectWebSocket(), RECONNECT_DELAY);
      return;
    }

    // Get WebSocket URL from managed storage or default
    const wsUrl = await getWebSocketUrl();
    console.log("Attempting WebSocket connection to:", wsUrl);

    // Since standard WebSocket API doesn't support custom headers,
    // we'll use a custom subprotocol to pass the auth token
    // URL-encode the token to handle special characters like = in base64
    const encodedToken = encodeURIComponent(authToken);
    const authProtocol = `auth.${encodedToken}`;
    ws = new WebSocket(wsUrl, [authProtocol]);

    // Add event listener for raw WebSocket frames (for debugging)
    // Try 'blob' instead of 'arraybuffer' to see if it makes a difference
    ws.binaryType = "blob";

    ws.onopen = () => {
      console.log("Connected to DNShield server");
      console.log("WebSocket readyState:", ws.readyState);
      console.log("WebSocket url:", ws.url);
      console.log("WebSocket protocol:", ws.protocol);
      console.log("WebSocket extensions:", ws.extensions);
      console.log("WebSocket bufferedAmount:", ws.bufferedAmount);
      isConnected = true;
      reconnectAttempts = 0; // Reset reconnection attempts on successful connection

      // Start keep-alive mechanism for service worker (Chrome 116+)
      startKeepAlive();

      // Request current blocked domains list from DNShield
      requestBlockedDomainsList();

      // Start periodic sync to keep blocked domains list up to date
      startDomainSync();

      // Send a ping message every 20 seconds to keep service worker alive
      if (pingInterval) {
        clearInterval(pingInterval);
      }

      pingInterval = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          // Send actual ping message to keep connection active
          try {
            ws.send(JSON.stringify({ type: "ping", timestamp: Date.now() }));
            console.log("Sent ping to keep connection alive");
          } catch (error) {
            console.error("Failed to send ping:", error);
          }
        } else {
          clearInterval(pingInterval);
          pingInterval = null;
        }
      }, 20000); // 20 seconds as recommended for Chrome 116+
    };

    ws.onmessage = (event) => {
      console.log("=== WebSocket Message Received ===");
      // console.log('Event object:', event); // enable for debugging full event
      console.log(
        "Event.data type:",
        Object.prototype.toString.call(event.data)
      );
      console.log(
        "Event.data instanceof ArrayBuffer:",
        event.data instanceof ArrayBuffer
      );
      console.log("Event.data instanceof Blob:", event.data instanceof Blob);
      console.log("Event.origin:", event.origin);
      console.log("Event.lastEventId:", event.lastEventId);

      // Handle different data types
      if (event.data instanceof ArrayBuffer) {
        console.log("Received ArrayBuffer, length:", event.data.byteLength);
        const uint8Array = new Uint8Array(event.data);
        console.log("First 20 bytes:", Array.from(uint8Array.slice(0, 20)));

        // Try to decode as text
        const decoder = new TextDecoder();
        try {
          const text = decoder.decode(event.data);
          console.log("Decoded text:", text);
          // console.log('Event.data:', event.data); // enable for debugging full event
          // Try to parse as JSON
          const message = JSON.parse(text);
          // console.log('Parsed JSON:', message); // enable for debugging full event

          if (message.type === "blocked_site" && message.data) {
            console.log("Processing blocked site from binary message");
            handleBlockedSite(message.data);
          } else if (message.type === "blocked_domains_list" && message.data) {
            // console.log('Received blocked domains list from binary:', message.data); // enable for debugging full event
            syncBlockedDomains(message.data);
          } else if (message.type === "domain_unblocked" && message.data) {
            console.log("Domain unblocked from binary:", message.data);
            removeDomainFromCache(message.data.domain);
          }
        } catch (error) {
          console.error("Error processing ArrayBuffer:", error);
        }
      } else if (event.data instanceof Blob) {
        console.log("Received Blob, size:", event.data.size);
        // Convert Blob to text
        event.data
          .text()
          .then((text) => {
            // console.log('Blob text:', text); // enable for debugging full event
            try {
              const message = JSON.parse(text);
              console.log("Parsed JSON from Blob:", message);

              if (message.type === "blocked_site" && message.data) {
                console.log("Processing blocked site from Blob message");
                handleBlockedSite(message.data);
              } else if (
                message.type === "blocked_domains_list" &&
                message.data
              ) {
                // console.log('Received blocked domains list from Blob:', message.data);
                syncBlockedDomains(message.data);
              } else if (message.type === "domain_unblocked" && message.data) {
                console.log("Domain unblocked from Blob:", message.data);
                removeDomainFromCache(message.data.domain);
              }
            } catch (error) {
              console.error("Error parsing Blob text:", error);
            }
          })
          .catch((error) => {
            console.error("Error reading Blob:", error);
          });
      } else if (typeof event.data === "string") {
        // console.log('Received string message:', event.data);
        try {
          const message = JSON.parse(event.data);
          // console.log('Parsed JSON from string:', message);

          if (message.type === "blocked_site" && message.data) {
            console.log("Processing blocked site from string message");
            handleBlockedSite(message.data);
          } else if (message.type === "blocked_domains_list" && message.data) {
            // console.log('Received blocked domains list:', message.data);
            syncBlockedDomains(message.data);
          } else if (message.type === "domain_unblocked" && message.data) {
            // console.log('Domain unblocked:', message.data);
            removeDomainFromCache(message.data.domain);
          }
        } catch (error) {
          console.error("Error parsing string message:", error);
        }
      } else {
        console.log("Unknown data type:", typeof event.data);
      }
      console.log("=== End of Message ===");
    };

    ws.onerror = (error) => {
      // WebSocket errors are often followed by close events with more details
      // We'll handle reconnection in the onclose handler
      // Only log if we're not already expecting a connection failure
      if (isConnected) {
        console.error("WebSocket error while connected:", error);
      }
    };

    ws.onclose = (event) => {
      console.log("WebSocket disconnected:", event.code, event.reason);
      isConnected = false;
      ws = null;

      // Clear intervals
      stopKeepAlive();
      stopDomainSync();
      if (pingInterval) {
        clearInterval(pingInterval);
        pingInterval = null;
      }

      // Attempt reconnection with exponential backoff
      if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
        reconnectAttempts++;
        const delay = Math.min(RECONNECT_DELAY * reconnectAttempts, 30000); // Max 30 seconds
        console.log(
          `Reconnecting in ${
            delay / 1000
          } seconds... (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})`
        );
        setTimeout(connectWebSocket, delay);
      } else {
        console.error(
          "Max reconnection attempts reached. Please ensure DNShield is running."
        );
      }
    };
  } catch (error) {
    console.error("Failed to connect to WebSocket:", error);
    if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      reconnectAttempts++;
      const delay = Math.min(RECONNECT_DELAY * reconnectAttempts, 30000);
      setTimeout(connectWebSocket, delay);
    }
  }
}

// Handle a blocked site - only track if it's from the browser
function handleBlockedSite(blockedSite) {
  // Only track blocks that originate from Chrome/browser processes
  const processName =
    typeof blockedSite.process === "string" ? blockedSite.process : "Unknown";
  const isBrowserBlock =
    blockedSite.fromBrowser === true || isBrowserProcess(processName);

  if (!isBrowserBlock) {
    console.log(
      `Ignoring non-browser block from process: ${blockedSite.process}`
    );
    return;
  }

  // Add to blocked domains set
  const domain = extractDomain(blockedSite.domain);
  if (domain) {
    blockedDomains.add(domain);

    // Add to history with browser flag
    blockHistory.unshift({
      ...blockedSite,
      domain,
      process: processName,
      timestamp: blockedSite.timestamp || new Date().toISOString(),
      fromBrowser: true,
    });

    // Limit history size
    if (blockHistory.length > MAX_HISTORY) {
      blockHistory = blockHistory.slice(0, MAX_HISTORY);
    }

    // Save to storage
    persistState();

    // Update badge
    updateBadge();

    // Show notification
    showBlockNotification(blockHistory[0]);

    // Don't automatically open a new tab here - wait for navigation attempt
    // The navigation listener will handle the redirect
  }
}

// Extract domain from various formats
function extractDomain(input) {
  if (!input) {
    return "";
  }

  let candidate = "";

  if (typeof input === "string") {
    candidate = input;
  } else if (input && typeof input.domain === "string") {
    candidate = input.domain;
  }

  if (typeof candidate !== "string") {
    return "";
  }

  return extractDomainFromString(candidate);
}

function extractDomainFromString(raw) {
  const value = raw.trim();
  if (!value) {
    return "";
  }

  // Handle IP:port format
  if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(value)) {
    return value.split(":")[0];
  }

  // Handle domain:port format
  if (value.includes(":")) {
    return value.split(":")[0];
  }

  // Handle full URLs
  try {
    const url = new URL(value.startsWith("http") ? value : `http://${value}`);
    return url.hostname;
  } catch {
    return value;
  }
}

// Show notification for blocked site
function showBlockNotification(blockedSite) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("images/icon-128.png"),
    title: "Site Blocked",
    message: `${blockedSite.domain} was blocked by DNShield`,
    contextMessage: `Process: ${blockedSite.process}`,
    priority: 2,
  });
}

// Update extension badge
function updateBadge() {
  const count = getUniqueBlockedSiteCount();
  chrome.action.setBadgeText({ text: count > 0 ? count.toString() : "" });
  chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
}

// Listen for tab navigation to redirect blocked sites
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // Only check main frame

  try {
    const url = new URL(details.url);
    const domain = url.hostname;

    // Check if domain is blocked
    if (blockedDomains.has(domain) || blockedDomains.has(url.host)) {
      console.log("Browser navigation to blocked domain:", domain);

      // Track this as a browser-initiated block
      const browserBlock = {
        domain: domain,
        process: "Chrome",
        timestamp: new Date().toISOString(),
        fromBrowser: true,
        url: details.url,
      };

      // Add to history if not already recent
      const recentBlock = blockHistory.find(
        (item) =>
          extractDomain(item.domain) === domain &&
          new Date() - new Date(item.timestamp) < 5000 // Within 5 seconds
      );

      if (!recentBlock) {
        blockHistory.unshift(browserBlock);

        // Limit history size
        if (blockHistory.length > MAX_HISTORY) {
          blockHistory = blockHistory.slice(0, MAX_HISTORY);
        }

        // Save to storage
        persistState();

        // Update badge
        updateBadge();
      }

      // Redirect to block page
      const blockPageUrl =
        chrome.runtime.getURL("blocked.html") +
        "?domain=" +
        encodeURIComponent(domain) +
        "&url=" +
        encodeURIComponent(details.url) +
        "&process=" +
        encodeURIComponent("Browser") +
        "&timestamp=" +
        encodeURIComponent(browserBlock.timestamp);

      chrome.tabs.update(details.tabId, { url: blockPageUrl });
    }
  } catch (error) {
    console.error("Error checking navigation:", error);
  }
});

// Also listen for navigation errors (DNS failures)
chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId !== 0) return; // Only check main frame

  // Check if error might be due to DNS blocking
  if (
    details.error === "net::ERR_NAME_NOT_RESOLVED" ||
    details.error === "net::ERR_CONNECTION_REFUSED" ||
    details.error === "net::ERR_ADDRESS_UNREACHABLE"
  ) {
    try {
      const url = new URL(details.url);
      const domain = url.hostname;

      // Check if this domain is in our blocked list
      if (blockedDomains.has(domain)) {
        // Redirect to blocked page
        const blockPageUrl =
          chrome.runtime.getURL("blocked.html") +
          "?domain=" +
          encodeURIComponent(domain) +
          "&url=" +
          encodeURIComponent(details.url) +
          "&process=" +
          encodeURIComponent("Browser") +
          "&timestamp=" +
          encodeURIComponent(new Date().toISOString());

        chrome.tabs.update(details.tabId, { url: blockPageUrl });
      }
    } catch (error) {
      console.error("Error handling navigation error:", error);
    }
  }
});

// Handle messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case "getBlockedDomains":
      sendResponse({
        domains: Array.from(blockedDomains),
        history: blockHistory,
      });
      break;

    case "clearHistory":
      clearBlockHistory();
      updateBadge();
      sendResponse({ success: true });
      break;

    case "unblockDomain":
      if (request.domain) {
        const domainToRemove = extractDomain(request.domain);
        if (domainToRemove) {
          blockedDomains.delete(domainToRemove);
        }
        persistState();
        updateBadge();
        // Send whitelist request to DNShield
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(
            JSON.stringify({
              type: "whitelist_domain",
              domain: request.domain,
            })
          );
        }
        sendResponse({ success: true });
      }
      break;

    case "requestBypass":
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(
          JSON.stringify({
            type: "request_bypass",
            domain: request.domain || "all",
          })
        );
        sendResponse({ success: true });
      } else {
        sendResponse({ error: "Not connected to DNShield" });
      }
      break;

    case "checkConnection":
      sendResponse({ connected: isConnected });
      break;

    case "reconnect":
      reconnectWebSocket();
      sendResponse({ success: true });
      break;

    default:
      sendResponse({ error: "Unknown message type" });
  }
  return false; // Synchronous response
});

// Initialize on startup
chrome.runtime.onStartup.addListener(() => {
  initialize();
});

// Initialize on install
chrome.runtime.onInstalled.addListener(() => {
  initialize();
});

// Handle alarms to keep service worker alive
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "keepAlive") {
    console.log("Keep-alive alarm triggered");
    // Check WebSocket connection
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      console.log("WebSocket not connected, attempting to reconnect...");
      connectWebSocket();
    }
  }
});

// Initialize extension
async function initialize() {
  // Load saved data
  const data = await chrome.storage.local.get([
    "blockedDomains",
    "blockHistory",
  ]);
  if (Array.isArray(data.blockedDomains)) {
    const sanitizedDomains = data.blockedDomains
      .map((domain) => extractDomain(domain))
      .filter(Boolean);
    blockedDomains = new Set(sanitizedDomains);
  }

  blockHistory = sanitizeHistoryEntries(data.blockHistory || []);

  // Ensure persisted data is cleaned up if we dropped invalid entries
  persistState();

  updateBadge();
  connectWebSocket();
}

// Manual reconnect function
function reconnectWebSocket() {
  console.log("Manual reconnect requested");
  reconnectAttempts = 0; // Reset attempts for manual reconnect
  if (ws) {
    ws.close();
  }
  connectWebSocket();
}

// Test function to simulate a blocked site (for debugging)
function testBlockedSite() {
  const testData = {
    domain: "test.doubleclick.net",
    process: "Chrome",
    timestamp: new Date().toISOString(),
  };
  console.log("Simulating blocked site:", testData);
  handleBlockedSite(testData);
}

// Start initialization
initialize();

// Test function to send a message to DNShield
function testWebSocketSend() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    const testMsg = JSON.stringify({ type: "test", data: "Hello from Chrome" });
    console.log("Sending test message:", testMsg);
    ws.send(testMsg);
  } else {
    console.error("WebSocket not connected");
  }
}

// Test function to change binary type
function testBinaryType(type) {
  if (ws) {
    console.log("Changing binaryType from", ws.binaryType, "to", type);
    ws.binaryType = type;
    console.log("New binaryType:", ws.binaryType);
  } else {
    console.error("WebSocket not initialized");
  }
}

// Debug function to inspect WebSocket
function debugWebSocket() {
  if (ws) {
    console.log("WebSocket State:");
    console.log("- URL:", ws.url);
    console.log("- ReadyState:", ws.readyState);
    console.log("- BinaryType:", ws.binaryType);
    console.log("- Protocol:", ws.protocol);
    console.log("- Extensions:", ws.extensions);
    console.log("- BufferedAmount:", ws.bufferedAmount);
    console.log("- Connected:", isConnected);
  } else {
    console.log("WebSocket not initialized");
  }
}

// Keep service worker alive while WebSocket is connected
function startKeepAlive() {
  console.log("Starting keep-alive mechanism");

  // Clear any existing interval
  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
  }

  // Create alarm to wake service worker periodically
  chrome.alarms.create("keepAlive", {
    periodInMinutes: 0.5, // Every 30 seconds
  });

  // Chrome 116+ extends service worker lifetime while WebSocket is active
  // But we still need to show activity to prevent termination
  keepAliveInterval = setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      // Access chrome API to show activity
      chrome.storage.local.get(["keepAlive"], (result) => {
        const count = (result.keepAlive || 0) + 1;
        chrome.storage.local.set({ keepAlive: count });
      });
    }
  }, 25000); // Every 25 seconds
}

function stopKeepAlive() {
  console.log("Stopping keep-alive mechanism");

  // Clear alarm
  chrome.alarms.clear("keepAlive");

  // Clear interval
  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
    keepAliveInterval = null;
  }
}

// Request the current list of blocked domains from DNShield
function requestBlockedDomainsList() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    console.log("Requesting current blocked domains list from DNShield");
    ws.send(JSON.stringify({ type: "get_blocked_domains" }));
  }
}

// Start periodic domain sync
function startDomainSync() {
  console.log("Starting domain sync");

  // Clear any existing sync interval
  if (syncInterval) {
    clearInterval(syncInterval);
  }

  // Sync every 30 seconds
  syncInterval = setInterval(() => {
    requestBlockedDomainsList();
  }, SYNC_INTERVAL);
}

// Stop domain sync
function stopDomainSync() {
  console.log("Stopping domain sync");
  if (syncInterval) {
    clearInterval(syncInterval);
    syncInterval = null;
  }
}

// Sync blocked domains with the current list from DNShield
function syncBlockedDomains(domainsList) {
  console.log(
    "Syncing blocked domains, received:",
    domainsList.length,
    "domains"
  );

  // Create new set from server's list
  const serverDomains = new Set(domainsList.map((d) => extractDomain(d)));

  // Find domains that are no longer blocked
  const removedDomains = [];
  for (const domain of blockedDomains) {
    if (!serverDomains.has(domain)) {
      removedDomains.push(domain);
    }
  }

  // Remove unblocked domains from our cache
  removedDomains.forEach((domain) => {
    console.log("Removing unblocked domain from cache:", domain);
    blockedDomains.delete(domain);
  });

  // Also clean up history - remove entries for unblocked domains
  if (removedDomains.length > 0) {
    blockHistory = blockHistory.filter((item) => {
      const itemDomain = extractDomain(item.domain);
      return serverDomains.has(itemDomain);
    });
  }

  // Update the blocked domains set with server's list
  // Only add new domains that we haven't seen yet
  for (const domain of serverDomains) {
    if (!blockedDomains.has(domain)) {
      blockedDomains.add(domain);
    }
  }

  // Save updated data
  persistState();

  // Update badge
  updateBadge();

  console.log(
    "Domain sync complete. Total blocked domains:",
    blockedDomains.size
  );
}

// Remove a specific domain from cache when it's unblocked
function removeDomainFromCache(domain) {
  const cleanDomain = extractDomain(domain);

  if (blockedDomains.has(cleanDomain)) {
    console.log("Removing domain from cache:", cleanDomain);
    blockedDomains.delete(cleanDomain);

    // Also remove from history
    blockHistory = blockHistory.filter((item) => {
      const itemDomain = extractDomain(item.domain);
      return itemDomain !== cleanDomain;
    });

    // Save updated data
    persistState();

    // Update badge
    updateBadge();
  }
}

// Export for debugging in console
// globalThis.testBlockedSite = testBlockedSite;
// globalThis.reconnectWebSocket = reconnectWebSocket;
// globalThis.testWebSocketSend = testWebSocketSend;
// globalThis.testBinaryType = testBinaryType;
// globalThis.debugWebSocket = debugWebSocket;
// globalThis.ws = () => ws; // Export WebSocket instance for debugging
// globalThis.requestBlockedDomainsList = requestBlockedDomainsList; // Export for debugging
