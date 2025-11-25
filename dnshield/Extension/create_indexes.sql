-- Create indexes for better performance as documented in FILESYSTEM_IPC_MIGRATION.md

-- Index for fast domain lookups with action
CREATE INDEX IF NOT EXISTS idx_domain_action ON dns_rules(domain, action);

-- Index for domain type queries
CREATE INDEX IF NOT EXISTS idx_domain_type ON dns_rules(domain, type);

-- Index for tracking rule updates
CREATE INDEX IF NOT EXISTS idx_updated_at ON dns_rules(updated_at);

-- Index for expiration cleanup
CREATE INDEX IF NOT EXISTS idx_expires_at ON dns_rules(expires_at);

-- Additional indexes for wildcard matching
CREATE INDEX IF NOT EXISTS idx_wildcard_domains ON dns_rules(domain) WHERE type = 1;

-- Index for source-based queries
CREATE INDEX IF NOT EXISTS idx_source_priority ON dns_rules(source, priority DESC);