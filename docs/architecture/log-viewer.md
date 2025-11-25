# DNShield Log Viewer

## Log Command Parameter Format

- > = 1 day: Format as `Xd` (e.g., `1d`, `7d`)
- > = 1 hour: Format as `Xh` (e.g., `1h`, `12h`)
- < 1 hour: Format as `Xm` (e.g., `30m`, `60m`)

## DNShield-Specific Subsystem Filtering

```txt
process == "DNShield" OR
subsystem == "com.dnshield" OR
subsystem == "com.dnshield.app" OR
process == "com.dnshield.extension"
```

## Predicate Selection Dropdown

- **All DNShield**: Shows all DNShield-related logs (default)
- **DNShield App Only**: Shows only main app logs (`process == "DNShield"`)
- **Extension Only**: Shows only network extension logs (`process == "com.dnshield.extension"`)
- **Subsystem Only**: Shows only subsystem logs (`subsystem == "com.dnshield*"`)
- **Custom Predicate**: Allows manual predicate entry

## Time Range Simplification

- Simplified to use period-based time ranges (matching `--last` parameter behavior)
- Default period changed to 3600 seconds (1 hour) for more reasonable log volume
- Start date picker and seconds field still available for reference but primary control is the period field
