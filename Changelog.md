# Changelog

## Unreleased

### SID resolution

- Added fallback account-name candidates for profile folders such as `dave.SCCMLAB`.
- LSA lookups now try the literal profile folder, `DOMAIN\user`, and the short username when appropriate.
- SID construction now uses the domain SID returned by the lookup response instead of assuming the local policy domain SID.

Why: Chrome protected-preference MACs depend on the correct Windows SID. If the SID is wrong or `Unknown`, Chrome treats the injected preference entry as tampered and may ignore or remove it.

### Extension ID and preference generation

- Extension IDs are now calculated from the deployed manifest `key` when available.
- Preference entries now derive API permissions, host permissions, and content-script matches from the manifest instead of using a hard-coded permission set.
- The manifest is included in the generated extension preference entry.
- Stale extension entries pointing at the same deployment path are removed before the new entry is added.

Why: The preference entry must match the actual unpacked extension Chrome is going to load. Stale entries or mismatched permissions can prevent Chrome from accepting or starting the extension.

### Exploit workflow guards

- `exploit` now refuses to run when the selected target has an unknown SID.
- Regular `Preferences` updates now receive the selected browser ID instead of always defaulting to Chrome.

Why: Running with an unknown SID produces invalid MACs, and using the wrong browser configuration can generate invalid protected-preference data.

