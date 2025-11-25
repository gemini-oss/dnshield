# Network State Detection and Icon Coloring

[Watch demo video](../../resources/video/state-detection.mp4)

## Overview

DNShield uses a sophisticated network state detection system to automatically change the menu bar icon color based on the current network conditions. This provides immediate visual feedback about DNS filtering status and network connectivity.

## Network States

The system detects and responds to three primary network states:

### 1. **Offline** (DNSNetworkStateOffline)

- **Detection**: No active network interfaces or all interfaces are down
- **Default Color**: Red (#FF453A)
- **Meaning**: Device has no network connectivity
- **Icon Behavior**: Both shield and globe are colored red to indicate no protection is possible

### 2. **Online** (DNSNetworkStateOnline)

- **Detection**: Active network connection detected without VPN
- **Default Color**: Blue (#0A84FF)
- **Meaning**: Normal operating state with DNS filtering active
- **Icon Behavior**: Shield and globe use the configured color (default blue)

### 3. **VPN Connected** (DNSNetworkStateVPNConnected)

- **Detection**: VPN interface is active with intelligent detection (see below)
- **Default Color**: Green (#32D74B)
- **Meaning**: Additional VPN protection layer is active
- **Icon Behavior**: Green indicates enhanced security through VPN

### Note on Deprecated States

The following states are defined but not actively used in current implementation:

- **VPN Disconnected**: Conceptually flawed as it requires tracking a specific VPN that exists but isn't connected
- **Restricted Network**: Reserved for future implementation of expensive/constrained network detection
- **Manual Override**: Used internally for manual color mode

## Detection Mechanism

### Intelligent VPN Detection

DNShield uses a multi-layered approach for accurate VPN detection:

1. **VPNResolvers Configuration**
   - Checks `/Library/Managed Preferences/*/com.dnshield.app.plist` for enterprise configs
   - Falls back to user defaults for VPNResolvers array
   - Supports CIDR notation (e.g., "100.64.0.0/10" for CGNAT ranges)
   - Caches preferences for 60 seconds to reduce disk I/O

2. **Interface-Based Detection**
   - **IPSec/PPP interfaces**: Always considered VPN
   - **utun interfaces**:
     - Ignores utun0-3 (system services like Content Caching)
     - Checks utun4+ for valid IPv4 addresses
     - Validates against VPNResolvers ranges if configured
   - **tun/tap interfaces**: Used by OpenVPN and similar

3. **IP Range Matching**
   - When VPNResolvers is configured, checks if interface IPs fall within specified ranges
   - Common VPN ranges include:
     - `100.64.0.0/10` - Carrier-Grade NAT (CGNAT)
     - `10.0.0.0/8` - Private network range
     - `172.16.0.0/12` - Private network range

### Performance Optimizations

The detection system is optimized to prevent UI freezing:

1. **Background Execution**
   - Network state checks run on background queue
   - UI updates dispatched to main thread
   - Prevents blocking during network operations

2. **Caching Strategy**
   - VPNResolvers cached for 60 seconds
   - Reduces repeated disk reads
   - Improves responsiveness

3. **Timer-Based Polling**
   - Regular checks every 5 seconds
   - Non-blocking asynchronous execution
   - Immediate response to network changes

### State Determination Logic

```objc
// Optimized state determination flow
1. Background thread:
   ├─ Check network interfaces (getifaddrs)
   ├─ Get cached VPNResolvers (or read if expired)
   └─ Determine network status
   
2. VPN Detection:
   ├─ Check for ipsec/ppp interfaces → VPN Connected
   ├─ Check utun4+ with IP matching VPNResolvers → VPN Connected
   └─ Otherwise → Check network availability
   
3. Main thread update:
   ├─ Network unavailable → Offline
   ├─ VPN detected → VPN Connected
   └─ Network available → Online
```

## Color Configuration

### Manual vs State-Based Modes

1. **Manual Mode**
   - User selects a single color for the icon
   - Color remains constant regardless of network state
   - Separate colors can be set for shield and globe parts

2. **State-Based Mode**
   - Colors change automatically based on network state
   - Each state can have custom colors configured
   - Visual feedback for network conditions

### Icon Component Coloring

The DNShield icon (SF Symbol: `network.badge.shield.half.filled`) has two colorable components:

1. **Shield Component** (Primary)
   - Represents DNS filtering protection
   - First color in the palette array
   - Can be colored independently

2. **Globe Component** (Secondary)
   - Represents network connectivity
   - Second color in the palette array
   - Can be colored independently

### Color Target Selection

Users can choose which parts of the icon to color:

- **Both**: Shield and globe use the same color
- **Shield Only**: Only the shield changes color
- **Globe Only**: Only the globe changes color

## Implementation Details

### Key Classes

1. **DNSStateColorManager**
   - Singleton managing color state
   - Stores color preferences per state
   - Handles state transitions
   - Persists configuration to UserDefaults

2. **AppDelegate**
   - Monitors network changes
   - Updates menu bar icon
   - Handles user color selection
   - Manages state detection timer

### State Persistence

Colors and preferences are stored in UserDefaults:

- `DNSIconColorTarget`: Which icon parts to color (0=Both, 1=Shield, 2=Globe)
- `DNSStateColors`: Dictionary of colors per state
- `DNSColorMode`: Manual or State-based mode

### Configuration UI

Users can configure colors through:

1. **Icon Color menu** - Quick color selection with preset colors
2. **Configure State Colors** - Per-state configuration with individual Apply buttons
   - Each state has separate Shield and Globe color wells
   - Apply button per state for immediate application
   - Simplified UI without confusing global Apply/Cancel
3. **Custom Color picker** - Direct color selection via macOS color panel
