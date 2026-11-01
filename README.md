# YTDiag

Read-only diagnostics for YouTube's sign-in / stream-protection wall.

Purpose: decide, on device, whether a re-signed YouTube can attest itself at all
(Apple **App Attest**), and which of YouTube's two integrity-token managers it ends up
using (`IGDAppAttest` vs `IGDNoAppAttestIntegrityTokenManager`).

## What it shows

A red **DIAG** chip in the top-left of the app. Tap it to expand, tap again to collapse.
The same text is written to `Library/Caches/ytdiag.txt` in the app container.

Report contents:

* every entitlement the *running process* actually has (`application-identifier`,
  `keychain-access-groups`, `com.apple.developer.devicecheck.appattest-environment`,
  `get-task-allow`, `associated-domains`)
* `DCAppAttestService.isSupported`, `generateKey…`, `attestKey…` and their error codes
* presence of `IGDAppAttest`, `IGDAppAttestChallenge`, `IGDIntegrityTokenManagerFactory`,
  `IGDNoAppAttestIntegrityTokenManager`
* their selector lists (so a deeper build can hook the right methods)
* `USED <class>` lines whenever one of those classes is instantiated — this is the line
  that decides the diagnosis

## Run procedure

1. Launch YouTube. A red **DIAG** chip appears top-left after ~3 s.
2. Tap it once to confirm the report renders, then tap again to collapse.
3. Attempt Google sign-in and let it fail.
4. The panel **auto-expands** the moment a `USED …` line is logged, which only happens
   during sign-in. Scroll to the bottom of the panel.
5. Screenshot it (or copy `Library/Caches/ytdiag.txt` if you can reach the container).

Steps 1-2 matter: the launch report never contains `USED` lines, because YouTube only
builds its token manager when sign-in starts.

## Reading the result

| `USED` line | Meaning |
|---|---|
| `USED IGDAppAttest` | the app is attesting; if sign-in still fails the wall is elsewhere |
| `USED IGDNoAppAttestIntegrityTokenManager` | the app has no attestation and is telling Google so |

If `generateKey` fails with a CodeSigning/`DeviceCheck` error, or
`appattest-environment` is `<absent>`, the cause is the signature — not a tweak.

## Build

No local toolchain on Windows; build on CI.

```
ytdiag/
  Sources/YTDiag.m
  build.sh
  .github/workflows/build.yml
```

Push this directory as a repo, run **build-ytdiag**, download `YTDiag.dylib`.

## Graft

```
python tools/graft_payload.py --ipa "...\YouTube-21.43.5-vanilla-noext-adhoc.ipa" \
    --out build/21.43.5-vanilla-ytdiag --no-extensions \
    --dylib YTDiag.dylib=ytdiag/out/YTDiag.dylib --load @rpath/YTDiag.dylib
tools\bin\zsign.exe -a -f build/21.43.5-vanilla-ytdiag/Payload/YouTube.app
python tools/verify_seal.py build/21.43.5-vanilla-ytdiag/Payload/YouTube.app
python tools/pack_ipa.py build/21.43.5-vanilla-ytdiag out/YouTube-21.43.5-ytdiag-noext-adhoc.ipa
```

Graft onto the **vanilla** build so the report describes the environment, not a tweak set.
