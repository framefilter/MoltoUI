//! Per-fingerprint white/blacklist for the non-standard PIV commands keyroost
//! exposes.
//!
//! A handful of management operations in this crate are vendor extensions, not
//! SP 800-73-4: Yubico's MOVE KEY and DELETE KEY, which landed in YubiKey
//! firmware 5.7. "Speaks PIV" says nothing about whether a given applet
//! implements them, and the answer can differ between firmware versions of the
//! same product. This module encodes what keyroost has actually observed,
//! keyed by [`AppletFingerprint`], as a **combined white/blacklist**: for each
//! fingerprint it knows about, a list of per-version verdicts each either
//! [`Verdict::Whitelisted`] ("extension known to be supported at this version")
//! or [`Verdict::Blacklisted`] ("extension known to be unsupported at this
//! version").
//!
//! [`resolve`] queries that table with the live applet's fingerprint and
//! version and returns a three-way [`FeatureGate`] a UI consumes directly:
//! enable the control ([`FeatureGate::Supported`]), enable it but flag it
//! ([`FeatureGate::Unverified`]), or disable it ([`FeatureGate::Unsupported`]).
//! It is deliberately conservative about *disabling*: a control is only ever
//! [`FeatureGate::Unsupported`] when the table has a blacklist verdict that
//! actually covers the applet's version. Anything less certain — no verdicts
//! for the fingerprint at all, none at or below the reported version, no
//! reported version, or only a blacklist verdict old enough that a later
//! firmware might have added the extension — resolves to
//! [`FeatureGate::Unverified`], which keeps the control usable.

use crate::fingerprint::AppletFingerprint;

/// One of the non-standard, vendor-extension PIV commands keyroost exposes —
/// nothing in SP 800-73-4 defines it, so support varies by applet and is
/// gated by device fingerprint through [`resolve`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivExtension {
    /// Yubico MOVE KEY — relocate a slot's private key into another slot.
    MoveKey,
    /// Yubico DELETE KEY — erase a slot's private key in place.
    DeleteKey,
}

impl PivExtension {
    /// This extension's white/blacklist: one [`FingerprintVerdicts`] row per
    /// fingerprint keyroost has data for. A fingerprint absent from the slice
    /// means "no data" and [`resolve`] returns [`FeatureGate::Unverified`].
    #[must_use]
    fn verdicts(self) -> &'static [FingerprintVerdicts] {
        match self {
            // MOVE KEY and DELETE KEY shipped together in YubiKey firmware
            // 5.7: unsupported at every earlier version, supported from 5.7 on.
            PivExtension::MoveKey | PivExtension::DeleteKey => YUBICO_5_7_KEY_OPS,
        }
    }

    /// A one-sentence statement of what running this extension needs, phrased
    /// for the user. A UI or the CLI follows it with a state-specific suffix —
    /// [`FeatureGate::UNVERIFIED_SUFFIX`] or [`FeatureGate::INCOMPATIBLE_SUFFIX`]
    /// — so both surfaces say the same thing.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            PivExtension::MoveKey => {
                "Moving keys between slots needs YubiKey 5.7+ or a compatible third-party device."
            }
            PivExtension::DeleteKey => {
                "Key deletion needs YubiKey 5.7+ or a compatible third-party device."
            }
        }
    }
}

/// The white/blacklist shared by [`PivExtension::MoveKey`] and
/// [`PivExtension::DeleteKey`]: on a YubiKey the operation is unsupported before
/// firmware 5.7 and supported from 5.7 onward, and keyroost has no data for
/// any other applet. The empty-slice version on the blacklist verdict is a
/// "from the very first version" sentinel — it orders below every real
/// version (`[] < [5, 7]`), so that verdict is the one that applies to
/// anything older than 5.7.
const YUBICO_5_7_KEY_OPS: &[FingerprintVerdicts] = &[FingerprintVerdicts {
    fingerprint: AppletFingerprint::YubiKey,
    verdicts: &[
        VersionVerdict {
            version: &[],
            verdict: Verdict::Blacklisted,
        },
        VersionVerdict {
            version: &[5, 7],
            verdict: Verdict::Whitelisted,
        },
    ],
}];

/// One fingerprint's row in an extension's white/blacklist.
struct FingerprintVerdicts {
    fingerprint: AppletFingerprint,
    /// This fingerprint's per-version verdicts, **ascending by
    /// [`VersionVerdict::version`]** and non-empty.
    verdicts: &'static [VersionVerdict],
}

/// "At [`Self::version`] (and, until the next one, above it) the extension's
/// verdict is [`Self::verdict`]." Versions are compared as plain byte slices,
/// the same ordering `keyroost_transport::PivStatus::version` uses elsewhere
/// (`[] < [5, 7] < [5, 7, 0] < [5, 8]`).
struct VersionVerdict {
    version: &'static [u8],
    verdict: Verdict,
}

/// One recorded white/blacklist verdict, carried by a [`VersionVerdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Extension known to be supported at this version (and, by the
    /// no-regression assumption in [`resolve`], at every later one until a
    /// contrary verdict).
    Whitelisted,
    /// Extension known to be unsupported at this version.
    Blacklisted,
}

/// The UI-facing resolution of a [`PivExtension`] against a live applet,
/// produced by [`resolve`]. Not `#[non_exhaustive]`: it is a closed
/// three-way outcome and every caller is expected to render all three
/// (enable / enable-and-flag / dim) rather than fall through a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureGate {
    /// Enable the control, no warning: the extension is whitelisted at the
    /// reported version, or at an earlier one and assumed not to have
    /// regressed.
    Supported,
    /// Enable the control, but flag it: keyroost has no white/blacklist for
    /// this fingerprint, none at or below the reported version, no reported
    /// version to match, or only a blacklist verdict old enough that a later
    /// firmware may have added the extension. See [`Self::UNVERIFIED_SUFFIX`].
    Unverified,
    /// Disable the control (dimmed): a blacklist verdict covers the reported
    /// version, so the extension is known to be unsupported here.
    Unsupported,
}

impl FeatureGate {
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unverified`](Self::Unverified): the device isn't on the
    /// white/blacklist, so support can't be confirmed either way.
    pub const UNVERIFIED_SUFFIX: &'static str =
        "This device is unverified; the operation may fail.";
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unsupported`](Self::Unsupported): a blacklist verdict covers
    /// this device's version.
    pub const INCOMPATIBLE_SUFFIX: &'static str = "This device is known to be incompatible.";
}

/// Resolve `extension` for an applet fingerprinted as `fingerprint` and
/// reporting `applet_version` (the PIV applet's own version bytes; `None` when
/// the card never reported one).
///
/// The lookup:
///
/// 1. `applet_version` is `None` → [`FeatureGate::Unverified`] (nothing to
///    version-match).
/// 2. No white/blacklist row for `fingerprint` → [`FeatureGate::Unverified`]
///    (support unknown; don't block).
/// 3. A row exists: take the verdict with the greatest version `<=` the applet
///    version. If there is none (the applet is older than every verdict) →
///    [`FeatureGate::Unverified`]. Otherwise:
///    * whitelisted → [`FeatureGate::Supported`] (covers both an exact-version
///      match and an earlier whitelist assumed not to have regressed);
///    * blacklisted, verdict version **equals** the applet version →
///      [`FeatureGate::Unsupported`];
///    * blacklisted, verdict version **below** the applet version, and it is
///      the last (highest) verdict in the row → [`FeatureGate::Unverified`]:
///      the blacklist may predate a firmware that added the extension;
///    * blacklisted, verdict version **below** the applet version, but a later
///      verdict exists (for a version above this applet's) → the row's
///      blacklist knowledge brackets this version, so it is treated as
///      authoritative: [`FeatureGate::Unsupported`].
#[must_use]
pub fn resolve(
    extension: PivExtension,
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
) -> FeatureGate {
    resolve_in(extension.verdicts(), fingerprint, applet_version)
}

/// [`resolve`] against an explicit set of white/blacklist rows, so a test can
/// supply its own without wiring one into the const tables.
fn resolve_in(
    rows: &[FingerprintVerdicts],
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
) -> FeatureGate {
    let Some(version) = applet_version else {
        return FeatureGate::Unverified;
    };
    let Some(row) = rows.iter().find(|row| row.fingerprint == fingerprint) else {
        return FeatureGate::Unverified;
    };
    let Some(idx) = row.verdicts.iter().rposition(|v| v.version <= version) else {
        return FeatureGate::Unverified;
    };
    let chosen = &row.verdicts[idx];
    match chosen.verdict {
        // Known supported at or below the reported version — and assumed not
        // to have regressed in any newer version we have no verdict for.
        Verdict::Whitelisted => FeatureGate::Supported,
        // Blacklist verdict for exactly this version: a direct observation
        // that this build lacks the extension. Nothing softens that.
        Verdict::Blacklisted if chosen.version == version => FeatureGate::Unsupported,
        // Blacklist verdict from an *older* version with nothing newer on
        // record: the extension may have been added in a firmware we haven't
        // observed, so warn rather than block.
        Verdict::Blacklisted if idx + 1 == row.verdicts.len() => FeatureGate::Unverified,
        // Blacklist verdict from an older version, but a later verdict exists
        // (for a version above this applet's): our blacklist knowledge
        // brackets this version, so treat it as authoritative and block.
        Verdict::Blacklisted => FeatureGate::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- User-facing wording: requirement() + a suffix -------------------

    #[test]
    fn requirement_is_distinct_per_extension_and_composes_with_a_suffix() {
        let move_req = PivExtension::MoveKey.requirement();
        let del_req = PivExtension::DeleteKey.requirement();
        assert_ne!(move_req, del_req);
        for req in [move_req, del_req] {
            // Ends a sentence, so "<req> <suffix>" reads as two.
            assert!(req.ends_with('.'), "{req:?}");
        }
        for suffix in [
            FeatureGate::UNVERIFIED_SUFFIX,
            FeatureGate::INCOMPATIBLE_SUFFIX,
        ] {
            assert!(suffix.ends_with('.'), "{suffix:?}");
            assert!(!suffix.is_empty());
        }
    }

    // --- YubiKey: the seeded 5.7 gate, both extensions -------------------

    #[test]
    fn yubikey_below_5_7_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            // Matches the blacklist sentinel verdict (version `[]`), which is
            // not the last verdict, so the blacklist is authoritative.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 6, 0])),
                FeatureGate::Unsupported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[4, 3, 7])),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn yubikey_5_7_and_newer_is_supported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            // Bare [5, 7] clears the bar: `[5, 7] <= [5, 7]`.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 7])),
                FeatureGate::Supported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 7, 4])),
                FeatureGate::Supported
            );
            // A later version with no verdict of its own falls to the [5, 7]
            // whitelist, assumed not to have regressed.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[6, 0, 0])),
                FeatureGate::Supported
            );
        }
    }

    #[test]
    fn yubikey_without_a_reported_version_is_unverified() {
        assert_eq!(
            resolve(PivExtension::MoveKey, AppletFingerprint::YubiKey, None),
            FeatureGate::Unverified
        );
    }

    // --- No row for the fingerprint -------------------------------------

    #[test]
    fn unknown_fingerprint_is_unverified_regardless_of_version() {
        for version in [None, Some(&[5, 7, 4][..]), Some(&[1, 0][..])] {
            assert_eq!(
                resolve(PivExtension::DeleteKey, AppletFingerprint::Generic, version),
                FeatureGate::Unverified
            );
            assert_eq!(
                resolve(PivExtension::MoveKey, AppletFingerprint::Token2, version),
                FeatureGate::Unverified
            );
        }
    }

    // --- The resolve() rules, exercised against a synthetic row ---------

    fn gate(verdicts: &'static [VersionVerdict], version: Option<&[u8]>) -> FeatureGate {
        let rows = [FingerprintVerdicts {
            fingerprint: AppletFingerprint::Generic,
            verdicts,
        }];
        resolve_in(&rows, AppletFingerprint::Generic, version)
    }

    #[test]
    fn applet_older_than_every_verdict_is_unverified() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::Whitelisted,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn exact_version_blacklist_match_is_unsupported() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::Blacklisted,
                }],
                Some(&[5, 7]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn trailing_stale_blacklist_is_unverified() {
        // Only a blacklist, from a version below the applet's, and it is the
        // last verdict — the extension might have been added since.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::Blacklisted,
                }],
                Some(&[5, 4]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn bracketed_blacklist_stays_authoritative() {
        // A blacklist below the applet's version, with a later verdict above
        // it: keyroost's blacklist knowledge brackets the applet version.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::Blacklisted,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::Whitelisted,
                    },
                ],
                Some(&[5, 4]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn earlier_whitelist_is_assumed_not_to_regress() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::Whitelisted,
                }],
                Some(&[9, 1, 2]),
            ),
            FeatureGate::Supported
        );
    }
}
