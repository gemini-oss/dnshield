#!/bin/bash
# DNShield Cache Testing Script

DOMAIN="${1:-github.com}"
QUERY_TYPE="${2:-A}"

echo "Testing DNS cache for domain: $DOMAIN (Type: $QUERY_TYPE)"
echo "==========================================="

# Function to query DNS and measure time
query_dns() {
    local start=$(date +%s%N)
    dig +short @127.0.0.1 -p 53 $DOMAIN $QUERY_TYPE
    local end=$(date +%s%N)
    local duration=$(( ($end - $start) / 1000000 ))
    echo "Query time: ${duration}ms"
}

# Check current cache rules
echo -e "\n1. Current cache rules for $DOMAIN:"
defaults read com.dnshield.app DomainCacheRules 2>/dev/null | grep -A2 "$DOMAIN" || echo "No specific rule found"

# Check if caching is enabled
CACHE_MANAGED=$(defaults read com.dnshield.app EnableDNSCache 2>/dev/null || echo "")
if [ -n "$CACHE_MANAGED" ]; then
    CACHE_ENABLED="$CACHE_MANAGED (managed)"
else
    CACHE_ENABLED=$(defaults read com.dnshield.app UserCanAdjustCache 2>/dev/null || echo "0")
fi
echo -e "\n2. DNS Cache Enabled: $CACHE_ENABLED"

# First query (potentially uncached)
echo -e "\n3. First query (potentially uncached):"
RESULT1=$(query_dns)
echo "$RESULT1"

# Immediate second query (should be cached if caching is enabled)
echo -e "\n4. Immediate second query (should be cached):"
sleep 0.1
RESULT2=$(query_dns)
echo "$RESULT2"

# Multiple rapid queries to test cache hit
echo -e "\n5. Testing 5 rapid queries:"
for i in {1..5}; do
    echo -n "Query $i: "
    query_dns | grep "Query time"
    sleep 0.05
done

# Check cache statistics via command file
echo -e "\n6. Requesting cache statistics..."
cat > /tmp/dnshield_command.json << EOF
{
    "command": "getCacheStats",
    "timestamp": $(date +%s)
}
EOF

sleep 1

# Parse any response
if [ -f /tmp/dnshield_response.json ]; then
    echo "Cache stats:"
    cat /tmp/dnshield_response.json | python3 -m json.tool
    rm -f /tmp/dnshield_response.json
fi

# Test specific TTL behavior
echo -e "\n7. Testing TTL behavior (waiting for cache expiry)..."
CACHE_RULE=$(defaults read com.dnshield.app DomainCacheRules 2>/dev/null | grep -A3 "\"$DOMAIN\"" | grep -o 'ttl = [0-9]*' | awk '{print $3}')
if [ -n "$CACHE_RULE" ]; then
    echo "Custom TTL for $DOMAIN: $CACHE_RULE seconds"
else
    echo "Using default TTL: 300 seconds"
fi
