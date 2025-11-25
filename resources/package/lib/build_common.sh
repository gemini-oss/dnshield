#!/bin/bash

# Shared build helpers for DNShield macOS packaging
# Assumes caller sets: PROJECT_DIR, BUILD_DIR, DAEMON_BUILD_DIR, APP_BUILD_DIR, DIST_DIR

set -e

# Basic logging if not provided by caller
if ! declare -F log_info >/dev/null; then
  log_info() { echo "[INFO] $1"; }
fi
if ! declare -F log_warning >/dev/null; then
  log_warning() { echo "[WARNING] $1"; }
fi
if ! declare -F log_error >/dev/null; then
  log_error() { echo "[ERROR] $1" >&2; }
fi

# Build daemon universal binary (arm64 + x86_64)
dns_build_daemon() {
  mkdir -p "${DAEMON_BUILD_DIR}/obj"

  local -a daemon_sources=(
    "${PROJECT_DIR}/Daemon/main.m"
    "${PROJECT_DIR}/Common/LoggingManager.m"
    "${PROJECT_DIR}/Common/Defaults.m"
  )

  local -a compiler_flags=(
    -framework Foundation
    -framework SystemExtensions
    -framework NetworkExtension
    -framework Security
    -I"${PROJECT_DIR}"
    -I"${PROJECT_DIR}/Common"
    -fobjc-arc
    -O2
    -Wno-deprecated-declarations
  )

  log_info "Building daemon for arm64..."
  clang -target arm64-apple-macos11.0 \
        -o "${DAEMON_BUILD_DIR}/dnshield-daemon-arm64" \
        "${compiler_flags[@]}" \
        "${daemon_sources[@]}" \
        2>&1 | tee "${DAEMON_BUILD_DIR}/build-arm64.log"

  log_info "Building daemon for x86_64..."
  clang -target x86_64-apple-macos11.0 \
        -o "${DAEMON_BUILD_DIR}/dnshield-daemon-x86_64" \
        "${compiler_flags[@]}" \
        "${daemon_sources[@]}" \
        2>&1 | tee "${DAEMON_BUILD_DIR}/build-x86_64.log"

  log_info "Creating universal binary..."
  lipo -create \
       "${DAEMON_BUILD_DIR}/dnshield-daemon-arm64" \
       "${DAEMON_BUILD_DIR}/dnshield-daemon-x86_64" \
       -output "${DAEMON_BUILD_DIR}/dnshield-daemon"

  strip -S "${DAEMON_BUILD_DIR}/dnshield-daemon" || true

  if [ -n "${DEVELOPER_ID:-}" ]; then
    log_info "Signing daemon with: $DEVELOPER_ID"
    # Sign with entitlements for system extension installation
    local entitlements_path="${PROJECT_DIR}/Daemon/entitlements.plist"
    if [ -f "$entitlements_path" ]; then
      log_info "Applying daemon entitlements from: $entitlements_path"
      codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
               --entitlements "$entitlements_path" \
               "${DAEMON_BUILD_DIR}/dnshield-daemon" || log_warning "Daemon signing failed"
    else
      log_warning "Daemon entitlements file not found at: $entitlements_path"
      codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
               "${DAEMON_BUILD_DIR}/dnshield-daemon" || log_warning "Daemon signing failed"
    fi
  fi
}

# Build the optional Go-based watchdog (arm64 + x86_64 universal binary)
dns_build_watchdog() {
  WATCHDOG_OUTPUT=""

  if [ -z "${WATCHDOG_BUILD_DIR:-}" ]; then
    log_warning "WATCHDOG_BUILD_DIR not set; skipping watchdog build"
    return 0
  fi

  # Look for watchdog source in tools/cmd/watchdog
  local tools_dir="${PROJECT_DIR}/../tools/cmd/watchdog"
  local source_dir="${PROJECT_DIR}/Watchdog"

  # Check both locations for watchdog source
  if [ -d "${tools_dir}" ]; then
    source_dir="${tools_dir}"
    log_info "Using watchdog source from tools/cmd/watchdog"
  elif [ ! -d "${source_dir}" ]; then
    log_warning "Watchdog source directory not found at ${source_dir} or ${tools_dir}; skipping build"
    return 0
  fi

  if ! command -v go >/dev/null; then
    log_warning "Go toolchain not available; skipping watchdog build"
    return 0
  fi

  mkdir -p "${WATCHDOG_BUILD_DIR}"

  local arm_output="${WATCHDOG_BUILD_DIR}/watchdog-arm64"
  local x86_output="${WATCHDOG_BUILD_DIR}/watchdog-x86_64"
  local uni_output="${WATCHDOG_BUILD_DIR}/watchdog"

  log_info "Building watchdog for arm64..."
  if ! (cd "${source_dir}" && env CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o "${arm_output}" .); then
    log_warning "Failed to build watchdog for arm64; skipping watchdog binary"
    rm -f "${arm_output}" 2>/dev/null || true
    return 0
  fi

  log_info "Building watchdog for x86_64..."
  if ! (cd "${source_dir}" && env CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "${x86_output}" .); then
    log_warning "Failed to build watchdog for x86_64; skipping watchdog binary"
    rm -f "${arm_output}" "${x86_output}" 2>/dev/null || true
    return 0
  fi

  log_info "Creating universal watchdog binary..."
  if ! lipo -create "${arm_output}" "${x86_output}" -output "${uni_output}"; then
    log_warning "Failed to create universal watchdog binary"
    rm -f "${arm_output}" "${x86_output}" "${uni_output}" 2>/dev/null || true
    return 0
  fi

  rm -f "${arm_output}" "${x86_output}" 2>/dev/null || true
  strip -S "${uni_output}" 2>/dev/null || true

  WATCHDOG_OUTPUT="${uni_output}"
  export WATCHDOG_OUTPUT

  if [ -n "${DEVELOPER_ID:-}" ] && [ -f "${WATCHDOG_OUTPUT}" ]; then
    log_info "Signing watchdog binary with: $DEVELOPER_ID"
    codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp "${WATCHDOG_OUTPUT}" \
      || log_warning "Failed to sign watchdog binary"
  fi

  log_info "Watchdog build complete"
  return 0
}

# Build the main app via xcodebuild to DerivedData
dns_build_app() {
  rm -rf "${APP_BUILD_DIR}/DerivedData"

  xcodebuild \
    -project "${PROJECT_DIR}/DNShield.xcodeproj" \
    -scheme DNShield \
    -configuration Release \
    -derivedDataPath "${APP_BUILD_DIR}/DerivedData" \
    ARCHS="arm64 x86_64" \
    ONLY_ACTIVE_ARCH=NO \
    CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
    OTHER_CODE_SIGN_FLAGS="--timestamp --options=runtime" \
    HEADER_SEARCH_PATHS="${PROJECT_DIR} ${PROJECT_DIR}/App ${PROJECT_DIR}/Extension" \
    build \
    2>&1 | tee "${APP_BUILD_DIR}/build.log"

  local build_status=${PIPESTATUS[0]}
  if [ "$build_status" -ne 0 ]; then
    log_error "xcodebuild failed with status ${build_status} (see ${APP_BUILD_DIR}/build.log)"
    return "$build_status"
  fi
}

# Build universal XPC helper into BUILD_DIR/dnshield-xpc
dns_build_xpc_universal() {
  local xpc_out="${BUILD_DIR}/dnshield-xpc"

  clang -framework Foundation \
        -target arm64-apple-macos11.0 \
        -o "${BUILD_DIR}/dnshield-xpc-arm64" \
        "${PROJECT_DIR}/XPC/dnshield-xpc.m"

  clang -framework Foundation \
        -target x86_64-apple-macos11.0 \
        -o "${BUILD_DIR}/dnshield-xpc-x86_64" \
        "${PROJECT_DIR}/XPC/dnshield-xpc.m"

  lipo -create \
       "${BUILD_DIR}/dnshield-xpc-arm64" \
       "${BUILD_DIR}/dnshield-xpc-x86_64" \
       -output "$xpc_out"

  if [ -n "${DEVELOPER_ID:-}" ]; then
    >&2 echo "[INFO] Signing XPC helper with: $DEVELOPER_ID"
    codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp "$xpc_out" 1>&2 \
      || { >&2 echo "[WARNING] XPC helper signing failed"; true; }
  fi

  echo "$xpc_out"
}

# Sign helper binaries in an app bundle's MacOS directory
dns_sign_helpers_in_app() {
  local app_macos_dir="$1"
  shift || true
  local helpers=("$@")
  if [ ${#helpers[@]} -eq 0 ]; then
    helpers=(dnshield-daemon dnshield-ctl dnshield-xpc)
  fi
  if [ -n "${DEVELOPER_ID:-}" ]; then
    for helper in "${helpers[@]}"; do
      if [ -f "${app_macos_dir}/${helper}" ]; then
        log_info "Signing ${helper} with: $DEVELOPER_ID"
        # For daemon, preserve entitlements
        if [ "$helper" = "dnshield-daemon" ]; then
          if [ -f "${PROJECT_DIR}/Daemon/entitlements.plist" ]; then
            log_info "Applying daemon entitlements from: ${PROJECT_DIR}/Daemon/entitlements.plist"
            codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
                     --entitlements "${PROJECT_DIR}/Daemon/entitlements.plist" \
                     "${app_macos_dir}/${helper}" \
            || log_warning "Failed to sign ${helper} with entitlements"
          else
            log_warning "Daemon entitlements file not found at: ${PROJECT_DIR}/Daemon/entitlements.plist"
            codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
                     "${app_macos_dir}/${helper}" \
            || log_warning "Failed to sign ${helper}"
          fi
        else
          codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
                   "${app_macos_dir}/${helper}" \
          || log_warning "Failed to sign ${helper}"
        fi
      fi
    done
  fi
}

# Sign the app bundle (no --deep) using entitlements if present
dns_sign_app_bundle() {
  local app_bundle="$1"
  local entitlements="$2"
  if [ -n "${DEVELOPER_ID:-}" ]; then
    if [ -n "$entitlements" ] && [ -f "$entitlements" ]; then
      codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
               --entitlements "$entitlements" "$app_bundle"
    else
      codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
               "$app_bundle"
    fi
  fi
}

# Staple a notarization ticket with retries to mitigate CloudKit transient errors
dns_staple_with_retry() {
  local path="$1"
  local attempts="${2:-6}"
  local sleep_secs="${3:-15}"

  if [ -z "$path" ] || [ ! -e "$path" ]; then
    log_error "dns_staple_with_retry: Path not found: $path"
    return 1
  fi

  local i=1
  while :; do
    log_info "Stapling notarization ticket (attempt $i/$attempts): $(basename "$path")"
    if xcrun stapler staple -v "$path"; then
      log_info "Staple succeeded: $(basename "$path")"
      return 0
    fi
    if [ "$i" -ge "$attempts" ]; then
      log_error "Staple failed after $attempts attempts: $path"
      return 1
    fi
    log_warning "Staple failed; retrying in ${sleep_secs}s..."
    sleep "$sleep_secs"
    i=$((i+1))
  done
}
