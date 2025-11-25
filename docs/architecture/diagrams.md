# DNShield Architecture Flow Charts and Diagrams

## 1. System Architecture Overview

```mermaid
graph TB
    subgraph "User Space"
        App[DNShield.app<br/>Menu Bar Application]
        Chrome[Chrome Extension<br/>Real-time Notifications]
    end
    
    subgraph "System Extension"
        NE[Network Extension<br/>DNSProxyProvider]
        Cache[DNS Cache<br/>Response Caching]
        RuleDB[Rule Database<br/>SQLite + Indexes]
        RuleCache[Rule Cache<br/>LRU Memory Cache]
    end
    
    subgraph "Enterprise"
        Daemon[System Daemon<br/>Headless Management]
        ManifestServer[Manifest Server<br/>CloudFront CDN]
    end
    
    subgraph "External"
        DNS[Upstream DNS<br/>8.8.8.8, 1.1.1.1]
        Network[Network Traffic<br/>All DNS Queries]
    end
    
    Network --> NE
    NE --> DNS
    NE <--> Cache
    NE <--> RuleCache
    NE <--> RuleDB
    App <--> NE
    Chrome <--> NE
    Daemon <--> NE
    ManifestServer --> NE
    
    classDef system fill:#e1f5fe
    classDef extension fill:#f3e5f5
    classDef external fill:#fff3e0
    
    class App,Chrome system
    class NE,Cache,RuleDB,RuleCache extension
    class DNS,Network,ManifestServer,Daemon external
```

## 2. DNS Query Processing Flow

```mermaid
flowchart TD
    Start([DNS Query Arrives]) --> Parse{Parse DNS Packet}
    Parse -->|Valid| ConnCheck{Network Connected?}
    Parse -->|Invalid| FormatErr[Return FORMERR]
    
    ConnCheck -->|No| CacheOnly{Check Cache}
    ConnCheck -->|Yes| BypassCheck{Bypass Active?}
    
    CacheOnly -->|Hit| ReturnCached[Return Cached Response]
    CacheOnly -->|Miss| ServFail[Return SERVFAIL]
    
    BypassCheck -->|Yes| Forward[Forward to Upstream]
    BypassCheck -->|No| CacheCheck{DNS Cache Hit?}
    
    CacheCheck -->|Hit| UpdateTTL[Update TTL] --> ReturnCached
    CacheCheck -->|Miss| RuleLookup{Rule Cache Hit?}
    
    RuleLookup -->|Hit| ApplyAction{Apply Cached Rule}
    RuleLookup -->|Miss| DBLookup[Database Query]
    
    DBLookup --> Precedence[Rule Precedence Resolution]
    Precedence --> CacheResult[Cache Rule Result]
    CacheResult --> ApplyAction
    
    ApplyAction -->|Block| GenBlock[Generate Blocked Response]
    ApplyAction -->|Allow| Forward
    ApplyAction -->|Whitelist| Forward
    
    GenBlock -->|A Record| Return127[Return 127.0.0.1]
    GenBlock -->|AAAA Record| Return1[Return ::1]
    GenBlock -->|Other| ReturnNXDOMAIN[Return NXDOMAIN]
    
    Forward --> UpstreamQuery[Query Upstream DNS]
    UpstreamQuery -->|Success| CacheResponse[Cache Response]
    UpstreamQuery -->|Timeout| ServFail
    
    CacheResponse --> ReturnResponse[Return DNS Response]
    
    Return127 --> LogBlock[Log Blocked Query]
    Return1 --> LogBlock
    ReturnNXDOMAIN --> LogBlock
    ReturnResponse --> LogAllow[Log Allowed Query]
    ReturnCached --> LogCached[Log Cache Hit]
    
    LogBlock --> NotifyWS[Notify WebSocket Clients]
    LogAllow --> UpdateStats[Update Statistics]
    LogCached --> UpdateStats
    
    NotifyWS --> UpdateStats
    UpdateStats --> End([End])
    
    FormatErr --> End
    ServFail --> End
    
    classDef decision fill:#fff3e0
    classDef process fill:#e8f5e8
    classDef terminal fill:#ffebee
    
    class Parse,ConnCheck,BypassCheck,CacheCheck,CacheOnly,RuleLookup,ApplyAction decision
    class Forward,DBLookup,Precedence,CacheResult,UpstreamQuery,CacheResponse process
    class Start,End,FormatErr,ServFail,Return127,Return1,ReturnNXDOMAIN,ReturnResponse,ReturnCached terminal
```

## 3. Rule Management Lifecycle

```mermaid
flowchart TD
    subgraph "Rule Sources"
        ManifestURL[Manifest URL<br/>Device-specific]
        LocalFile[Local Files<br/>.json/.yml/.yaml/.plist]
        HTTPSource[HTTP Sources<br/>Remote lists]
    end
    
    subgraph "Manifest Resolution"
        SerialCheck{Device Serial<br/>Available?}
        SerialCheck -->|Yes| SerialManifest[manifest_<serial>.json]
        SerialCheck -->|No| DefaultManifest[manifest_default.json]
        SerialManifest -->|404| TryPlist[Try .plist extension]
        TryPlist -->|404| TryYML[Try .yml extension]
        TryYML -->|404| TryYAML[Try .yaml extension]
        DefaultManifest -->|404| TryPlistDefault[Try default.plist]
        TryPlistDefault -->|404| TryYMLDefault[Try default.yml]
        TryYMLDefault -->|404| TryYAMLDefault[Try default.yaml]
    end
    
    subgraph "Rule Processing"
        Fetch[Fetch Rule Source]
        Fetch --> DetectFormat{Detect Format}
        DetectFormat -->|JSON| JSONParser[JSON Rule Parser]
        DetectFormat -->|YAML/YML| YAMLParser[YAML Rule Parser]
        DetectFormat -->|Plist| PlistParser[Property List Parser]
        DetectFormat -->|Hosts| HostsParser[Hosts File Parser]
        
        JSONParser --> Validate[Validate Domains]
        YAMLParser --> Validate
        PlistParser --> Validate
        HostsParser --> Validate
        
        Validate -->|Valid| CreateRuleSet[Create RuleSet Object]
        Validate -->|Invalid| LogError[Log Parse Error]
        
        CreateRuleSet --> Precedence[Apply Precedence Rules]
        Precedence --> BulkInsert[Bulk Database Insert]
        BulkInsert --> UpdateCache[Update Rule Cache]
        UpdateCache --> NotifyApp[Notify App of Updates]
    end
    
    subgraph "Update Scheduling"
        Timer[Update Timer] --> CheckStrategy{Update Strategy}
        CheckStrategy -->|Interval| IntervalCheck[Check Interval]
        CheckStrategy -->|Scheduled| CronCheck[Check Cron Schedule]
        CheckStrategy -->|Manual| ManualTrigger[Manual Update]
        
        IntervalCheck --> TriggerUpdate[Trigger Update]
        CronCheck --> TriggerUpdate
        ManualTrigger --> TriggerUpdate
        
        TriggerUpdate --> NetworkCheck{Network Available?}
        NetworkCheck -->|Yes| Fetch
        NetworkCheck -->|No| RetryLater[Schedule Retry]
    end
    
    subgraph "Error Handling"
        LogError --> FallbackCache[Use Cached Rules]
        NetworkError[Network Error] --> ExponentialBackoff[Exponential Backoff]
        ExponentialBackoff --> RetryLater
        FallbackCache --> End([Rule Update Complete])
    end
    
    ManifestURL --> SerialCheck
    LocalFile --> Fetch
    HTTPSource --> Fetch
    
    RetryLater --> Timer
    NotifyApp --> End
    
    classDef source fill:#e3f2fd
    classDef process fill:#e8f5e8
    classDef decision fill:#fff3e0
    classDef error fill:#ffebee
    
    class ManifestURL,LocalFile,HTTPSource source
    class Fetch,JSONParser,YAMLParser,PlistParser,HostsParser,CreateRuleSet,BulkInsert,UpdateCache process
    class SerialCheck,DetectFormat,CheckStrategy,NetworkCheck decision
    class LogError,NetworkError,ExponentialBackoff,FallbackCache error
```

## 4. XPC Communication Architecture

```mermaid
sequenceDiagram
    participant App as DNShield.app
    participant XPCClient as XPC Client
    participant NE as Network Extension
    participant DB as Rule Database
    participant WS as WebSocket Server
    participant Chrome as Chrome Extension
    
    Note over App,Chrome: Application Startup
    App->>XPCClient: Initialize connection
    XPCClient->>NE: Connect with code signing validation
    NE-->>XPCClient: Connection established
    
    Note over App,Chrome: Rule Updates
    App->>XPCClient: updateBlockedDomains:
    XPCClient->>NE: XPC call with domain list
    NE->>DB: Insert/update rules
    DB-->>NE: Success
    NE-->>XPCClient: Completion handler
    XPCClient-->>App: Success callback
    
    Note over App,Chrome: Statistics Request
    App->>XPCClient: getStatistics
    XPCClient->>NE: XPC statistics request
    NE->>NE: Calculate current stats
    NE-->>XPCClient: Statistics dictionary
    XPCClient-->>App: Statistics data
    
    Note over App,Chrome: DNS Query Blocking
    NE->>NE: Process DNS query
    NE->>DB: Rule lookup
    DB-->>NE: Block action
    NE->>NE: Generate blocked response
    NE->>WS: Send blocking notification
    WS->>Chrome: WebSocket message
    Chrome->>Chrome: Display notification
    
    Note over App,Chrome: Connection Error Handling
    XPCClient->>NE: XPC call
    NE-->>XPCClient: Connection interrupted
    XPCClient->>XPCClient: Exponential backoff
    XPCClient->>NE: Retry connection
    NE-->>XPCClient: Connection restored
```

## 5. Cache Architecture and Data Flow

```mermaid
graph TB
    subgraph "DNS Query Processing"
        Query[DNS Query] --> L1Check{Memory Cache<br/>DNSCache}
        L1Check -->|Hit| L1Return[Return Cached Response]
        L1Check -->|Miss| RuleCheck{Rule Cache<br/>DNSRuleCache}
    end
    
    subgraph "Rule Resolution"
        RuleCheck -->|Hit| L2Return[Apply Cached Rule]
        RuleCheck -->|Miss| L3Check{Disk Cache<br/>RuleSet Files}
        L3Check -->|Hit| L3Load[Load from Disk]
        L3Check -->|Miss| DBQuery[Database Query]
        
        L3Load --> CacheRule[Cache in Memory]
        DBQuery --> PrecedenceResolve[Precedence Resolution]
        PrecedenceResolve --> CacheRule
        CacheRule --> L2Return
    end
    
    subgraph "Cache Management"
        MemoryPressure[Memory Pressure] --> Eviction{Eviction Strategy}
        Eviction -->|LRU| RemoveLRU[Remove Least Recently Used]
        Eviction -->|Size| ReduceSize[Reduce Cache Size by 25%]
        Eviction -->|TTL| ExpiredCleanup[Remove Expired Entries]
        
        Timer[Cleanup Timer<br/>Every 5 minutes] --> ExpiredCleanup
        
        RemoveLRU --> UpdateStats[Update Cache Statistics]
        ReduceSize --> UpdateStats
        ExpiredCleanup --> UpdateStats
    end
    
    subgraph "Performance Monitoring"
        UpdateStats --> HitRate[Calculate Hit Rate]
        HitRate --> QPS[Queries Per Second]
        QPS --> ResponseTime[Average Response Time]
        ResponseTime --> SlowQueries[Slow Query Detection]
    end
    
    L1Return --> UpdateStats
    L2Return --> UpdateStats
    
    classDef cache fill:#e1f5fe
    classDef decision fill:#fff3e0
    classDef process fill:#e8f5e8
    classDef monitoring fill:#f3e5f5
    
    class L1Check,RuleCheck,L3Check,Eviction cache
    class Query,L1Return,L2Return,L3Load,DBQuery,PrecedenceResolve,CacheRule decision
    class RemoveLRU,ReduceSize,ExpiredCleanup,UpdateStats process
    class HitRate,QPS,ResponseTime,SlowQueries monitoring
```

## 6. Enterprise Deployment Architecture

```mermaid
graph TB
    subgraph "Management Infrastructure"
        MDM[MDM System<br/>Jamf Pro/Similar]
        ManifestCDN[Manifest CDN<br/>CloudFront]
        ConfigRepo[Configuration Repository]
    end
    
    subgraph "Device Management"
        Profile[Configuration Profile] --> InstallDaemon[Install Daemon]
        Profile --> SetPreferences[Set Managed Preferences]
        InstallDaemon --> SystemService[System LaunchDaemon]
    end
    
    subgraph "Client Device"
        SystemService --> Daemon[DNShield Daemon]
        Daemon <--> Extension[Network Extension]
        Extension <--> Database[Local Rule Database]
        
        SetPreferences --> PreferenceFile[/Library/Managed Preferences/]
        PreferenceFile --> Extension
        
        Extension --> ManifestFetch[Manifest Fetcher]
        ManifestFetch --> ManifestCDN
        ManifestCDN --> DeviceSpecific{Device-Specific<br/>Manifest}
        DeviceSpecific -->|Serial Match| CustomRules[Custom Rule Set]
        DeviceSpecific -->|Default| StandardRules[Standard Rule Set]
    end
    
    subgraph "Monitoring and Logging"
        Extension --> TelemetryLogger[Telemetry Logger]
        TelemetryLogger --> Syslog[System Log]
        Syslog --> LogAggregator[Central Log Aggregator]
        
        Extension --> HealthMonitor[Health Monitor]
        HealthMonitor --> StatusReporting[Status Reporting]
    end
    
    MDM --> Profile
    ConfigRepo --> ManifestCDN
    CustomRules --> Database
    StandardRules --> Database
    
    classDef management fill:#e8eaf6
    classDef device fill:#e8f5e8
    classDef monitoring fill:#fff3e0
    
    class MDM,ManifestCDN,ConfigRepo management
    class Daemon,Extension,Database,ManifestFetch device
    class TelemetryLogger,Syslog,LogAggregator,HealthMonitor,StatusReporting monitoring
```

## 7. Security Architecture

```mermaid
graph TB
    subgraph "Code Signing Validation"
        AppBundle[DNShield.app] --> CertValidation[Certificate Validation]
        CertValidation --> TeamIDCheck[Team ID Verification]
        TeamIDCheck --> BundleIDCheck[Bundle ID Verification]
        BundleIDCheck --> TrustedConnection[Trusted XPC Connection]
    end
    
    subgraph "Network Extension Security"
        TrustedConnection --> NEEntitlements[System Extension Entitlements]
        NEEntitlements --> Sandbox[Sandboxed Environment]
        Sandbox --> FileAccess[Restricted File Access]
        FileAccess --> SharedContainer[App Group Container]
    end
    
    subgraph "WebSocket Security"
        Chrome[Chrome Extension] --> OriginValidation[Origin Validation]
        OriginValidation --> ExtensionIDCheck[Extension ID Verification]
        ExtensionIDCheck --> AuthToken[Bearer Token Authentication]
        AuthToken --> KeychainStorage[Keychain Token Storage]
        KeychainStorage --> SecureConnection[Authenticated WebSocket]
    end
    
    subgraph "Enterprise Security"
        MDMProfile[MDM Configuration Profile] --> SignedProfile[Cryptographically Signed]
        SignedProfile --> ManagedPrefs[Managed Preferences]
        ManagedPrefs --> DaemonValidation[Daemon Code Validation]
        DaemonValidation --> PrivilegedXPC[Privileged XPC Service]
    end
    
    subgraph "Data Protection"
        SharedContainer --> EncryptedDB[Encrypted Database]
        KeychainStorage --> KeyRotation[Automatic Key Rotation]
        EncryptedDB --> AuditLogging[Audit Logging]
        PrivilegedXPC --> AuditLogging
        SecureConnection --> AuditLogging
    end
    
    classDef security fill:#ffebee
    classDef validation fill:#fff3e0
    classDef storage fill:#e8f5e8
    
    class CertValidation,TeamIDCheck,BundleIDCheck,OriginValidation,ExtensionIDCheck,DaemonValidation validation
    class NEEntitlements,Sandbox,AuthToken,SignedProfile,ManagedPrefs security
    class SharedContainer,EncryptedDB,KeychainStorage,PrivilegedXPC,AuditLogging storage
```

## 8. Performance Optimization Flow

```mermaid
flowchart TD
    QueryArrival[DNS Query Arrives] --> FastPath{Fast Path Check}
    
    FastPath -->|Cache Hit| CacheReturn[Return from L1 Cache<br/>< 1ms]
    FastPath -->|Cache Miss| RulePath{Rule Cache Check}
    
    RulePath -->|Rule Hit| RuleReturn[Apply Cached Rule<br/>< 0.1ms]
    RulePath -->|Rule Miss| SlowPath[Slow Path: Database]
    
    SlowPath --> IndexedQuery[Indexed Database Query]
    IndexedQuery --> OptimizedLookup{Query Type}
    
    OptimizedLookup -->|Exact Match| ExactIndex[Use Primary Index<br/>O(1) lookup]
    OptimizedLookup -->|Wildcard| WildcardIndex[Use Wildcard Index<br/>Prefix match]
    OptimizedLookup -->|Parent Domain| ParentTraversal[Parent Domain Walk<br/>Avoid LIKE queries]
    
    ExactIndex --> CacheUpdate[Update Rule Cache]
    WildcardIndex --> CacheUpdate
    ParentTraversal --> CacheUpdate
    
    CacheUpdate --> ApplyRule[Apply Rule Action]
    ApplyRule -->|Block| FastBlock[Generate Block Response<br/>No network]
    ApplyRule -->|Allow| UpstreamQuery[Upstream DNS Query<br/>Connection pool]
    
    UpstreamQuery --> ResponseCache[Cache DNS Response<br/>TTL-aware]
    ResponseCache --> Return[Return Response]
    
    FastBlock --> Return
    CacheReturn --> UpdateMetrics[Update Performance Metrics]
    RuleReturn --> UpdateMetrics
    Return --> UpdateMetrics
    
    UpdateMetrics --> MemoryCheck{Memory Pressure?}
    MemoryCheck -->|High| CacheEviction[Evict LRU Entries<br/>25% reduction]
    MemoryCheck -->|Normal| End([Query Complete])
    
    CacheEviction --> End
    
    classDef fast fill:#c8e6c9
    classDef medium fill:#fff3e0
    classDef slow fill:#ffcdd2
    classDef optimization fill:#e1f5fe
    
    class CacheReturn,RuleReturn,FastBlock fast
    class IndexedQuery,ExactIndex,WildcardIndex medium
    class SlowPath,ParentTraversal,UpstreamQuery slow
    class CacheUpdate,ResponseCache,UpdateMetrics,CacheEviction optimization
```
