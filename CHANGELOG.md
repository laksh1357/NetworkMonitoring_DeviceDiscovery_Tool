# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **docs/**: Comprehensive documentation suite including `ARCHITECTURE.md`, `API.md`, `PERFORMANCE.md`, `TESTING.md`, `EXPERIMENTAL_EVALUATION.md`, and `PATENT_TECHNICAL_DISCLOSURE.md`.
- **CONTRIBUTING.md**: Standardized guidelines for open-source contributors and test implementation rules.
- **CHANGELOG.md**: Initial changelog creation.

### Changed
- **README.md**: Completely redesigned the project landing page to reflect a professional, research-grade open-source system. Added technical problem definitions, architectural summaries, and API/Database overviews.
- **SECURITY.md**: Updated the threat model to strictly define attacker assumptions, trust boundaries, and specific mitigation strategies (e.g., SSRF protection on port scanning).

### Fixed
- **Security (AppleScript Injection):** Patched `notifications.py` to pass hostnames as discrete arguments to `osascript` instead of using vulnerable string interpolation.
- **Security (SSRF):** Patched `web_server.py`'s `/api/ports/scan` endpoint to strictly validate and restrict IP queries to private network address spaces.
