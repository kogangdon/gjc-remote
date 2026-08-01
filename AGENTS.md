# Repository Contribution Guidance

## Branches and pull requests

- Every new feature, behavior change, bug fix, or operational change MUST be developed on a dedicated branch; do not implement directly on `main`.
- Every such change MUST be submitted through a pull request before it is considered complete. Keep the PR focused and describe the acceptance criteria and verification evidence.
- Do not commit unrelated work from the working tree to the feature branch. Preserve pre-existing user changes and call out overlap before modifying them.
- Do not merge, push, or close a PR unless the task explicitly authorizes that action.

## Agent review requirement

- Every pull request MUST receive agent review before merge.
- The review must cover architecture, product/contract behavior, tests, security, and operational regressions as applicable.
- Implementation agents must not self-approve their own changes. Use a separate read-only review agent or review lane and record its findings in the PR.
- Resolve blocking findings and rerun the relevant verification after each fix. A passing test suite alone does not replace agent review.
- PRs must include the review result, changed-file scope, commands run, and any platform evidence that remains unavailable.

## Verification

- Match verification commands to the changed surface. For daemon lifecycle changes, run focused Node tests plus the repository regression suite and smoke test where the environment supports it.
- Do not claim native Windows, macOS, Linux, Docker, NSSM, or systemd evidence unless it was actually run on that platform or in that runtime.
- Runtime configuration values that control retries, timeouts, or restart policy MUST be validated, bounded, and covered by tests for invalid, minimum, and maximum values.
