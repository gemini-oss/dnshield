#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Common/LoggingUtils.h>
#import <Rule/Manager+Manifest.h>

#import "DNSManifestResolver.h"
#import "PreferenceManager.h"
#import "Provider.h"
#import "ProxyProvider+Delegates.h"
#import "ProxyProvider+Helpers.h"
#import "ProxyProvider+Private.h"
#import "WebSocketServer.h"

#pragma mark - Initialization

@implementation ProxyProvider (Initialization)

- (instancetype)init {
  self = [super init];
  if (self) {
    self.dnsQueue = dispatch_queue_create("com.dnshield.dns", DISPATCH_QUEUE_SERIAL);

    self.dnsCache = [[DNSCache alloc] initWithMaxSize:10000];
    self.blockedCount = 0;
    self.allowedCount = 0;

    self.queryToClientInfo = [NSMapTable strongToStrongObjectsMapTable];
    self.upstreamConnections = [NSMutableDictionary new];
    self.queryTimestamps = [NSMutableDictionary new];
    self.activeFlows = [NSMutableSet new];
    self.tcpFlows = [NSMapTable strongToStrongObjectsMapTable];
    self.closedFlows = [NSMutableSet new];
    self.flowEmptyReadCounts = [NSMutableDictionary new];

    self.queuedQueries = [NSMutableArray new];
    self.isInTransitionMode = NO;
    self.transitionQueue = dispatch_queue_create("com.dnshield.transition", DISPATCH_QUEUE_SERIAL);

    self.activeXPCConnections = [NSMutableArray new];

    self.preferenceManager = [PreferenceManager sharedManager];

    if (!self.preferenceManager.sharedDefaults) {
      DNSLogError(LogCategoryConfiguration, "Failed to initialize shared defaults");
    }

    self.telemetry = [DNSShieldTelemetry sharedInstance];

    DNSConfiguration* defaultConfiguration = [DNSConfiguration defaultConfiguration];
    self.ruleManager = [[RuleManager alloc] initWithConfiguration:defaultConfiguration];
    self.ruleManager.delegate = self;

    self.configManager = [ConfigurationManager sharedManager];

    self.ruleCache = [DNSRuleCache sharedCache];
    self.ruleCache.maxEntries = 5000;
    self.ruleDatabase = [RuleDatabase sharedDatabase];

    self.commandProcessor = [DNSCommandProcessor sharedProcessor];
    self.commandProcessor.delegate = self;
    self.interfaceManager =
        [[DNSInterfaceManager alloc] initWithPreferenceManager:self.preferenceManager];
    self.interfaceManager.delegate = self;

    self.retryManager = [[DNSRetryManager alloc] initWithPreferenceManager:self.preferenceManager];
    self.retryManager.delegate = self;

    self.flowTelemetry =
        [[DNSFlowTelemetry alloc] initWithPreferenceManager:self.preferenceManager];

    self.networkReachability = [NetworkReachability sharedInstance];
    self.networkReachability.delegate = self;
    self.isWaitingForConnectivity = NO;

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(sharedDefaultsChanged:)
                                                 name:NSUserDefaultsDidChangeNotification
                                               object:self.preferenceManager.sharedDefaults];

    // Initialize WebSocket server for Chrome extension communication
    // Check configuration to determine if WebSocket should be enabled
    NSNumber* wsEnabled =
        [self.preferenceManager preferenceValueForKey:kDNShieldEnableWebSocketServer
                                             inDomain:kDNShieldPreferenceDomain];
    [self resetWebSocketRetryState];

    if (!wsEnabled || [wsEnabled boolValue]) {
      [self ensureWebSocketServerRunning];
    }
  }
  return self;
}

- (void)sharedDefaultsChanged:(NSNotification*)notification {
  DNSLogInfo(LogCategoryConfiguration, "Shared defaults changed notification received");

  [self.preferenceManager.sharedDefaults synchronize];
  BOOL syncResult = DNPreferenceDomainSynchronize(kDNShieldAppGroup);
  DNSLogInfo(LogCategoryConfiguration, "CFPreferences sync result: %d", syncResult);

  dispatch_async(self.dnsQueue, ^{
    [self reloadConfigurationIfNeeded];

    if (self.interfaceManager) {
      [self.interfaceManager reloadConfiguration];
      DNSLogInfo(LogCategoryConfiguration,
                 "Reloaded DNS interface manager configuration due to preference changes");
    }

    if (self.retryManager) {
      [self.retryManager reloadConfiguration];
      DNSLogInfo(LogCategoryConfiguration,
                 "Reloaded DNS retry manager configuration due to preference changes");
    }

    if (self.flowTelemetry) {
      [self.flowTelemetry reloadConfiguration];
      DNSLogInfo(LogCategoryConfiguration,
                 "Reloaded DNS flow telemetry configuration due to preference changes");
    }

    [self ensureWebSocketServerRunning];
  });
}

- (void)loadConfiguration {
  DNSLogInfo(LogCategoryConfiguration, "Loading configuration from shared defaults");

  [self.preferenceManager.sharedDefaults synchronize];

  NSArray* servers = [self.preferenceManager.sharedDefaults arrayForKey:@"DNSServers"];
  BOOL usingSharedDefaults = (servers && servers.count > 0);

  if (!usingSharedDefaults) {
    NSArray* systemServers = [self getSystemDNSServers];
    if (systemServers.count > 0) {
      servers = systemServers;
      DNSLogInfo(LogCategoryConfiguration, "Detected system DNS servers via scutil: %@",
                 [servers componentsJoinedByString:@", "]);
    }
  }

  if (!servers || servers.count == 0) {
    servers = @[ @"1.1.1.1", @"8.8.8.8" ];
    DNSLogInfo(LogCategoryConfiguration, "Falling back to default DNS servers: %@",
               [servers componentsJoinedByString:@", "]);
  } else if (usingSharedDefaults) {
    DNSLogInfo(LogCategoryConfiguration, "Using DNS servers from shared defaults: %@",
               [servers componentsJoinedByString:@", "]);
  }

  self.dnsServers = servers;

  [self setupConfigurationReloadTimer];
}

- (void)setupConfigurationReloadTimer {
  static NSTimer* configReloadTimer = nil;
  if (configReloadTimer) {
    [configReloadTimer invalidate];
    DNSLogInfo(LogCategoryConfiguration, "Stopped existing configuration reload timer");
  }

  NSTimeInterval updateInterval = 300.0;
  NSNumber* intervalValue =
      [[PreferenceManager sharedManager] preferenceValueForKey:kDNShieldManifestUpdateInterval
                                                      inDomain:kDNShieldPreferenceDomain];
  if (intervalValue && [intervalValue doubleValue] > 0) {
    updateInterval = [intervalValue doubleValue];
  }

  DNSLogInfo(LogCategoryScheduler,
             " TIMER: Setting up unified configuration/manifest reload timer with interval: %.1f "
             "seconds (%.1f minutes)",
             updateInterval, updateInterval / 60.0);

  configReloadTimer = [NSTimer scheduledTimerWithTimeInterval:updateInterval
                                                       target:self
                                                     selector:@selector(reloadConfigurationIfNeeded)
                                                     userInfo:nil
                                                      repeats:YES];
}

- (void)reloadConfigurationIfNeeded {
  static NSUInteger timerFireCount = 0;
  timerFireCount++;

  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.dateFormat = @"HH:mm:ss";
  NSString* timestamp = [formatter stringFromDate:[NSDate date]];

  DNSLogInfo(LogCategoryScheduler,
             "Timer fired #%lu at %{public}@: Checking for configuration/manifest updates",
             (unsigned long)timerFireCount, timestamp);

  [self.preferenceManager.sharedDefaults synchronize];
  DNPreferenceAppSynchronize(kDNShieldPreferenceDomain);

  BOOL shouldUseManifest = [[ConfigurationManager sharedManager] shouldUseManifest];

  if (shouldUseManifest) {
    NSString* currentIdentifier = self.ruleManager.currentManifestIdentifier;
    NSString* newIdentifier =
        [DNSManifestResolver determineClientIdentifierWithPreferenceManager:self.preferenceManager];

    BOOL manifestChanged = NO;
    if (!currentIdentifier || ![currentIdentifier isEqualToString:newIdentifier]) {
      manifestChanged = YES;
      DNSLogInfo(LogCategoryRuleFetching,
                 "Manifest identifier changed from %{public}@ to %{public}@",
                 currentIdentifier ?: @"none", newIdentifier);
    }

    NSString* manifestURL =
        [self.preferenceManager preferenceValueForKey:kDNShieldManifestURL
                                             inDomain:kDNShieldPreferenceDomain];
    if (manifestURL.length > 0) {
      DNSLogInfo(LogCategoryRuleFetching, "Manifest base URL: %{public}@", manifestURL);
    } else {
      DNSLogInfo(LogCategoryRuleFetching, "Manifest base URL not set; will use defaults");
    }
    NSArray* httpHeaders =
        [self.preferenceManager preferenceValueForKey:kDNShieldAdditionalHttpHeaders
                                             inDomain:kDNShieldPreferenceDomain];

    DNSLogInfo(LogCategoryRuleFetching,
               "Current manifest configuration - URL: %{public}@, Headers: %{public}@",
               manifestURL ?: @"none", httpHeaders ?: @"(nil)");

    if (self.ruleManager &&
        [self.ruleManager respondsToSelector:@selector(reloadManifestIfNeeded)]) {
      DNSLogInfo(LogCategoryRuleFetching, "Timer: Triggering manifest/rule update check (async)");
      // CRITICAL: Don't block the main thread with manifest resolution
      // The semaphore wait in HTTP fetcher can block for 10+ seconds
      dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [(id)self.ruleManager reloadManifestIfNeeded];
      });
    }
  }
}

@end
