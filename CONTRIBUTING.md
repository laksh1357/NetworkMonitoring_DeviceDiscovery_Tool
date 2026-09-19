# Contributing to LAN Watchtower

Thank you for your interest in contributing to LAN Watchtower! We welcome pull requests, bug reports, and research proposals.

## 1. Code of Conduct
All contributors are expected to adhere to professional engineering standards. Be respectful in discussions, provide clear justifications for architectural changes, and prioritize constructive feedback.

## 2. Getting Started
1. Fork the repository.
2. Clone your fork locally.
3. Install the required dependencies: `pip install -r requirements.txt`.
4. Ensure you can run the test suite: `python -m pytest tests/`.

## 3. Pull Request Guidelines
- **Tests are Mandatory:** Any new logic (specifically within the analytical engines) must include corresponding unit tests demonstrating edge-case handling.
- **No Unverifiable Claims:** Documentation and UI text must use technically verifiable language. Avoid terms like "unhackable" or "AI-driven" unless specifically utilizing a documented machine learning model.
- **Mocking:** Integration tests must use the `MockNetworkSimulator`. Do not write tests that send unauthorized or live packets into the network environment.
- **Formatting:** Code must adhere to standard PEP-8 formatting. Run `black` and `isort` prior to submitting your PR.

## 4. Reporting Issues
When filing bug reports, include:
- Operating System and Python version.
- Detailed reproduction steps.
- Relevant anonymized logs (ensure no sensitive PII or network topologies are leaked in public issue trackers).
