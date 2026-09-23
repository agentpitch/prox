# pitchProx v0.44.1

This patch includes all v0.44 resource, CLI and tray improvements and repairs
update discovery when GitHub returns incomplete release metadata.

## Update discovery

- GitHub's general release list can omit attached files while the release's
  dedicated assets endpoint already lists the complete upload. The updater now
  consults that endpoint when required filenames are absent.
- This happens only during an explicit update check, for at most the five
  visible releases. It adds no background polling. All existing digest, size,
  manifest and duplicate-file checks still apply.
- Publication now independently verifies all four uploaded files before making
  the release public and checks the anonymous list/tag responses afterwards.
  Already-published releases cannot be overwritten by a workflow rerun.

The v0.44 incident was reproduced in the installed v0.43 updater: it detected
the version but disabled installation because GitHub's list returned an empty
`assets` array. The EXE, ZIP, checksums and manifest were present and verified
through the dedicated asset endpoint. No v0.44 binary or tag was replaced.

## Compatibility and checks

Configuration and history formats are unchanged. An update requires the usual
application restart. See `docs/RELEASE_NOTES_v0.44.md` for the full feature list,
installation guidance and runtime verification limits.

Regression coverage includes incomplete API responses, bounded fallback
requests, cancellation, and rejection of duplicate or invalid asset metadata.
Release packaging runs the full Go and JavaScript checks with Go 1.26.8 and
Node.js 22.17.0 and verifies the official WinDivert 2.2.2 runtime by SHA-256.
