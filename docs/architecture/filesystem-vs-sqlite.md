# DNShield Architecture: Filesystem Commands vs SQLite Database

## Overview

DNShield uses both a filesystem-based command system and SQLite database for different purposes. This document explains the architectural decisions behind this dual approach.

## The Two Systems

### 1. Filesystem Command System (`/Library/Application Support/DNShield/Commands/`)

- **Purpose**: Communication between app and network extension
- **Format**: Files monitored via FSEvents
- **Use Cases**:
  - Triggering rule updates
  - Getting extension status
  - Clearing DNS cache
  - Reloading configuration

### 2. SQLite Database (`/var/db/dnshield/rules.db`)

- **Purpose**: Persistent storage and efficient querying of DNS filtering rules
- **Format**: Structured database with indexed columns
- **Use Cases**:
  - Storing all DNS rules (blocked/allowed domains)
  - Tracking rule sources and metadata
  - Efficient domain lookup during DNS queries
  - Rule management and updatesok

## Architecture Flow

1. **Command Flow**: App → Filesystem → Extension
2. **Data Flow**: Extension → SQLite → Memory Cache
3. **Query Flow**: App → XPC → Extension → SQLite
