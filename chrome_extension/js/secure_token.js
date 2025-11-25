// Secure token management for DNShield Chrome Extension
// Uses session storage (memory-only) to prevent token persistence to disk

const TOKEN_EXPIRY_TIME = 3600 * 1000; // 1 hour
const TOKEN_REFRESH_BUFFER = 5 * 60 * 1000; // Refresh 5 minutes before expiry

class SecureTokenManager {
  constructor() {
    this.tokenRefreshTimer = null;
  }

  // Get auth token from secure storage
  async getAuthToken() {
    try {
      // First check enterprise managed storage (read-only)
      const managedResult = await chrome.storage.managed.get(['authToken']);
      if (managedResult.authToken) {
        console.log('Using auth token from enterprise policy');
        return managedResult.authToken;
      }

      // Use session storage for non-enterprise deployments
      const sessionResult = await chrome.storage.session.get(['auth_token', 'expires_at']);
      
      if (sessionResult.auth_token) {
        // Check if token is expired or about to expire
        const now = Date.now();
        const expiresAt = sessionResult.expires_at || 0;
        
        if (expiresAt - now < TOKEN_REFRESH_BUFFER) {
          console.log('Token expired or expiring soon, refreshing...');
          return await this.refreshToken();
        }
        
        return sessionResult.auth_token;
      }

      // No token found, need to obtain one
      console.log('No auth token found, requesting new token...');
      return await this.requestNewToken();
      
    } catch (error) {
      console.error('Error getting auth token:', error);
      return null;
    }
  }

  // Request new token from native app via native messaging
  async requestNewToken() {
    try {
      // Send message to native app to get token
      const response = await chrome.runtime.sendNativeMessage('com.dnshield.app', {
        type: 'REQUEST_AUTH_TOKEN',
        timestamp: Date.now()
      });

      if (response && response.token) {
        await this.storeToken(response.token);
        return response.token;
      }

      // Fallback: Try to get from DNShield app preferences (one-time migration)
      // This is for backward compatibility during transition
      const localResult = await chrome.storage.local.get(['dnshield_auth_token']);
      if (localResult.dnshield_auth_token) {
        console.log('Migrating token from local storage to session storage');
        await this.storeToken(localResult.dnshield_auth_token);
        
        // Clear the old token from local storage
        await chrome.storage.local.remove(['dnshield_auth_token']);
        
        return localResult.dnshield_auth_token;
      }

      return null;
    } catch (error) {
      console.error('Error requesting new token:', error);
      return null;
    }
  }

  // Refresh existing token
  async refreshToken() {
    try {
      const currentToken = (await chrome.storage.session.get(['auth_token'])).auth_token;
      
      // Send refresh request to native app
      const response = await chrome.runtime.sendNativeMessage('com.dnshield.app', {
        type: 'REFRESH_AUTH_TOKEN',
        current_token: currentToken,
        timestamp: Date.now()
      });

      if (response && response.token) {
        await this.storeToken(response.token);
        return response.token;
      }

      // If refresh fails, request new token
      return await this.requestNewToken();
      
    } catch (error) {
      console.error('Error refreshing token:', error);
      return await this.requestNewToken();
    }
  }

  // Store token in session storage with expiry
  async storeToken(token) {
    const expiresAt = Date.now() + TOKEN_EXPIRY_TIME;
    
    await chrome.storage.session.set({
      auth_token: token,
      expires_at: expiresAt
    });

    // Schedule token refresh
    this.scheduleTokenRefresh(expiresAt);
  }

  // Schedule automatic token refresh before expiry
  scheduleTokenRefresh(expiresAt) {
    // Clear any existing timer
    if (this.tokenRefreshTimer) {
      clearTimeout(this.tokenRefreshTimer);
    }

    const refreshTime = expiresAt - Date.now() - TOKEN_REFRESH_BUFFER;
    if (refreshTime > 0) {
      this.tokenRefreshTimer = setTimeout(async () => {
        console.log('Auto-refreshing token...');
        await this.refreshToken();
      }, refreshTime);
    }
  }

  // Clear token (for logout/disconnect)
  async clearToken() {
    if (this.tokenRefreshTimer) {
      clearTimeout(this.tokenRefreshTimer);
      this.tokenRefreshTimer = null;
    }
    
    await chrome.storage.session.remove(['auth_token', 'expires_at']);
  }

  // Generate CSRF token for additional security
  generateCSRFToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}

// Export for use in background.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecureTokenManager;
}