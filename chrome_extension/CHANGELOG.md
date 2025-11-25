# Chrome Extension Changelog

## Version 2.3.41

### Fixed Issues

1. **Accurate Block Counters**: Badge and popup now show only browser-originated blocked sites rather than the total rule catalog, removing the constant alert dot.
2. **History Sanitization**: Stored history is filtered to discard stale or malformed entries so counts stay consistent after upgrading.

### Technical Changes

- Centralized state persistence to sanitize blocked domains/history before saving.
- Ensured history clear operations leave the synchronized rule set intact.

## Version 2.2.0

### Fixed Issues

1. **Browser-Only Blocking**: Extension now only displays domains that are blocked in the browser, ignoring system-level blocks from other processes
2. **Domain Cache Sync**: Fixed bug where extension would continue blocking sites that are no longer in the block rules

### New Features

- Added periodic sync with DNShield server (every 30 seconds) to keep blocked domains list up-to-date
- Extension now requests current blocked domains list on connection
- Automatic removal of unblocked domains from cache
- Better tracking of browser-initiated blocks vs system blocks

### Technical Changes

- Added `fromBrowser` flag to track browser-originated blocks
- Implemented `syncBlockedDomains()` function for syncing with server
- Added `removeDomainFromCache()` for real-time domain removal
- Enhanced WebSocket message handling for new message types:
  - `get_blocked_domains`: Request current list
  - `blocked_domains_list`: Receive domain list
  - `domain_unblocked`: Remove specific domain
- Process filtering to only track Chrome/Browser processes
