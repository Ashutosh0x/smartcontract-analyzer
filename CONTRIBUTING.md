# Contributing to Sentinel

## Adding New Detectors
1. Create a new Rust module in `src/detectors/`
2. Implement the `Detector` trait
3. Add tests in `tests/`

## Running Tests
Run the test suite using `cargo test`.

## Adding New Rules
Rules are located in `src/rules/`. Follow the existing pattern for rule implementation.

## Adding Test Fixtures
Add vulnerable and safe smart contracts in `tests/fixtures/vulnerable/` and `tests/fixtures/safe/` respectively.

## Submit Security Findings
If you discover a security vulnerability, please refer to our `SECURITY.md` for reporting guidelines.
