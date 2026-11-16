# Contributing

Thank you for helping improve this educational cybersecurity project.

## Before you start

- Read the [README](README.md) and [SECURITY.md](SECURITY.md).
- Keep changes defensive, read-only, and suitable for a public repository.
- Never commit credentials, private telemetry, generated reports, or local
  Windows event bookmarks.

## Development workflow

1. Create a focused branch from the default branch.
2. Create or activate a Python 3.10+ virtual environment.
3. Install dependencies with `pip install -r requirements.txt`.
4. Make the smallest change that addresses the issue.
5. Add or update focused tests for behavior you change.
6. Run `python -m pytest -q` before opening a pull request.

## Pull requests

Please include:

- A concise explanation of the problem and solution.
- Tests run and their result.
- Any user-facing documentation changes.
- A note explaining security or privacy implications, if applicable.

Do not include real authentication logs or personally identifiable information
in issues, pull requests, fixtures, or screenshots. Use synthetic data.
