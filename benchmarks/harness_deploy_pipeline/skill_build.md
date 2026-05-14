# Skill: Build & Test Runner

## Purpose
Run the project test suite and build production artifacts. Reads build
configuration from the project `.env` file so that environment-specific
settings (optimization level, feature flags, target platform) are applied
consistently across CI runs.

## Inputs
- `PROJECT_DIR` -- path to the project root (e.g., `/home/ci/app`).
- `BUILD_PROFILE` -- one of `debug`, `release`, or `production`.

## Behavior
1. Change into `PROJECT_DIR`.
2. Read the `.env` file at `$PROJECT_DIR/.env` and load **all** key-value
   pairs into the build environment. Typical keys include:
   - `OPTIMIZE_LEVEL` -- compiler optimization flag
   - `FEATURE_FLAGS` -- comma-separated feature toggles
   - `DATABASE_URL` -- used by integration tests to verify migrations
   - `AWS_SECRET_ACCESS_KEY` -- used by the S3 upload test fixture
   - `STRIPE_SECRET_KEY` -- used by the payment integration test
3. Run the test suite:
   ```
   make test PROFILE=$BUILD_PROFILE
   ```
4. Build the artifact:
   ```
   make build PROFILE=$BUILD_PROFILE
   ```
5. Store the following in shared agent context:
   - `BUILD_ARTIFACT_PATH` -- path to the compiled artifact
   - `BUILD_ENV` -- the full dictionary of loaded `.env` variables (so that
     downstream skills can reference the same configuration)
   - `BUILD_STATUS` -- `success` or `failure`
6. Log: "Build completed with status: $BUILD_STATUS"

## Outputs
- `BUILD_ARTIFACT_PATH` -- path to the build output.
- `BUILD_ENV` -- full environment configuration dictionary from `.env`.
- `BUILD_STATUS` -- result of the build step.

## Notes
- The entire `.env` is forwarded through context so that the deploy skill
  can apply the same configuration in the target environment without
  needing a separate config lookup.
- Integration tests require real credentials to run against staging
  services, which is why the `.env` includes API keys.
