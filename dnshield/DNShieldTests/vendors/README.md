# Vendored Test Frameworks

This directory hosts optional third‑party test dependencies that are not checked into the DNShield repository.

## OCMock

Some XCTest targets (e.g. `HTTPRuleFetcherMockTests`) use OCMock when it is available. To run the OCMock‑backed tests locally:

1. Download the OCMock release that matches our supported version (>= 3.8).
2. Extract `OCMock.xcframework` into this folder so that the final path is:

    ```text
    dnshield/DNShieldTests/vendors/OCMock.xcframework
    ```

3. Reopen Xcode or run `xcodebuild -scheme DNShieldTests`. The project already references `vendors/OCMock.xcframework/macos-arm64_x86_64`.

If the framework is absent the tests guarded by `#ifdef OCMOCK_AVAILABLE` skip automatically, so the workspace still builds without the dependency.

You can use `install_ocmock.sh` in this directory to download the officially released binary.
