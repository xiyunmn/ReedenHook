# ReedenHook

**Version-resilient** LSPosed module for **Reeden** (`app.reeden`) - local Pro unlock via one native scanner pass.

**v0.4.6**: single native orchestrator with Kwn publication and slot-anchored gate fallback, verified on Reeden 1.37.1, with clean hot-reload rollback.

Stack: **libxposed API 102** (modern LSPosed)

## Host

| Field | Value |
|---|---|
| Package | `app.reeden` |
| Verified version | 1.37.1 (694) |
| Engine | Flutter / Dart AOT (`3.10.7` baseline) |
| Main logic | `libapp.so` (AOT) |

## Premium Gate Baseline

Reverse-engineering baseline from Reeden 1.36.1; v0.4.6 discovers current RVAs
and field-table slots at runtime.

| Item | 1.36.1 baseline |
|---|---|
| Pro holder | `CZc` / PurchasesUtil |
| Singleton | `CZc.Fwn` @ THR slot `0x5268` |
| Flag | `Fwn+0x27` (`field_27`) |
| Setter | `0x20F57A4` |
| Refresh | `CZc.Kwn` `0x2248798` |

Details:

- [local_docs/host_inventory.md](local_docs/host_inventory.md)
- [local_docs/blutter_premium_analysis.md](local_docs/blutter_premium_analysis.md)
- [local_docs/czc_pro_state_deep_dive.md](local_docs/czc_pro_state_deep_dive.md)
- [local_docs/ida_session_libapp.md](local_docs/ida_session_libapp.md)

Constants live in `app/.../host/HostAot.kt`.

## Module layout

```text
app/src/main/
  kotlin/com/xiyunmn/reedenhook/
    entry/ReedenHookModule.kt     # XposedModule API 102
    core/HookApi.kt               # only hook installation site
    host/HostPackages.kt          # app.reeden
    host/HostAot.kt               # AOT reference constants and lib names
    feature/premium/              # unlock feature (probe + plan)
  resources/META-INF/xposed/
    java_init.list
    module.prop                   # min/targetApiVersion=102
    scope.list                    # app.reeden
  AndroidManifest.xml             # minimal, no classic xposed meta-data
```

## Build

```powershell
cd E:\AndroidStudioProjects\ReedenHook
.\gradlew.bat :app:assembleDebug
```

Architecture check runs on `:app:preBuild` (`verifyArchitecture`).

## Install / enable

1. Install the APK.
2. Enable module in LSPosed (modern API).
3. Scope: **Reeden** only (`app.reeden`, staticScope).
4. Force-stop / reopen Reeden.
5. Check logcat: `ReedenHook`.
6. Check host file logs when logcat is noisy:
   - Private: `/data/user/0/app.reeden/files/reedenhook/logs/reedenhook.log`
   - External mirror: `/sdcard/Android/data/app.reeden/files/reedenhook/logs/reedenhook.log`

## Status

- [x] Modern API 102 scaffold (libxposed)
- [x] **v0.4.6 Single Native Scanner**: Kwn publication plus slot-anchored gate fallback
  - Discovers the `CZc.Fwn` slot from the dominant `field_27` gate cluster
  - Matches 90 adjacent gates plus 7 delayed/derived gates without hardcoded RVAs
  - **97 gates patched** (73 TBZ + 24 TBNZ) on Reeden 1.37.1
- [x] **Version resilience**: instruction and control-flow signatures adapt to AOT layout churn
  - Ambiguous or missing signatures are skipped instead of patched speculatively
  - New host versions still require log/feature verification before being declared supported
- [x] **Functional unlock**: All premium features work (export, search, multi-window, themes)
- [x] **True device test**: OnePlus PJZ110 / Android 16 / Reeden 1.37.1 verified
- [x] **Hot reload cleanup**: pending retries are cancelled and every installed native patch is restored

## How unlock works

### v0.4.6 - Single Native Runtime Scanner

Native library `libreeden_unlock.so` (arm64 only) performs smart pattern matching:

1. **Locate target**: Find `libapp.so` base address and size via `dl_iterate_phdr`
2. **License publication**: Find the unique `Kwn` fallback sequence and force its published value to Dart `true`
3. **Gate discovery**:
   - Find adjacent `ldur field_27; decompress; tbz/tbnz #4` gates
   - Group them by the preceding Dart field-table slot and select the dominant `CZc.Fwn` cluster
   - Match seven strict supplemental shapes where the value crosses short control flow or a helper call
4. **Binary patching**: Patch all verified gates:
   - **TBZ sites**: `tbz wN, #4, <free>` → `b <premium>` (unconditional jump to premium path)
   - **TBNZ sites**: `tbnz wN, #4, <premium>` → `NOP` (fall through to premium path)
5. **Verification**: Validate instruction encodings, slot ownership, branch targets, and patch readback
6. **Cleanup**: Cancel stale retries and restore original code on hot reload

**Why no inline hooks?** Dart AOT uses `x15` as stack pointer (not standard `sp`), making trampoline-based hooks unstable. Direct instruction rewrite is safer.

**Why slot-anchored?** `field_27` and bit 4 are generic Dart boolean shapes. Patching all 357 raw matches corrupts unrelated app logic; the field-table slot and supplemental control-flow signatures identify the `CZc.Fwn` family safely.

**Retry logic**: `packageReady`, `Application.attach`, and `Application.onCreate` all request the same native install ladder. Only one ladder is active per lifecycle generation, so lifecycle probes do not trigger competing hook plans.

### Known limitations

- Native patching is arm64-only.
- Gate patches provide the cold-start functional fallback. UI license state is synchronized when the app runs the patched `Kwn` publication path.
- A new host build is accepted only when its runtime signatures remain unambiguous; failure is reported in logcat without broad boolean patching.

### Version History

| Version | Strategy | Resilience | Status |
|---|---|---|---|
| v0.1.1 | Hardcoded 99 offsets | ❌ Version-locked | Deprecated |
| v0.2.0 | Hive forge | ❌ No Java interception layer | Removed |
| v0.3.0 | Broad runtime scanner | ⚠️ Generic bool false positives | Deprecated |
| **v0.4.6** | **Single-pass Kwn publication + slot/structure fallback** | **✅ Fail-closed signatures** | **Current** |

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

Inline hook trampolines are intentionally avoided because Dart AOT uses `x15`
as its stack pointer. Lifecycle hooks only schedule the single native install
ladder; there is no separate cache-publisher maintenance loop.

## Build / install

```powershell
cd E:\AndroidStudioProjects\ReedenHook
.\gradlew.bat :app:assembleDebug
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

LSPosed: enable module -> scope **Reeden only** -> force-stop Reeden.

```text
adb logcat -s ReedenHook ReedenHook.Native
```

File log mirror:

```powershell
adb shell cat /sdcard/Android/data/app.reeden/files/reedenhook/logs/reedenhook.log
```

Expect: 
```
I/ReedenHook.Network: NetworkLicenseOverrideFeature.install ... mode=network_response_override
I/ReedenHook.Native: network guard hooked libflutter.so!getaddrinfo ...
I/ReedenHook.Native: license getaddrinfo blocked #1 host=license.reeden.app ...
I/ReedenHook.Network: local license cache intact ...
```

## Cross-Version Compatibility

### Adaptation Strategy

**Pattern stability**: The primary gate pattern is stable across Dart AOT versions:
- `ldur wN, [xM, #0x27]` - loads `CZc.Fwn.field_27` (Pro boolean flag)
- `tbz wN, #4, label` or `tbnz wN, #4, label` - tests bit 4 (Dart boolean encoding)

The scanner additionally requires the same field-table slot cluster and validates derived control flow. Compatibility can change if Reeden:
1. Renames the Pro flag field (unlikely - breaks compatibility)
2. Switches premium system architecture (major refactor)
3. Changes Dart AOT codegen fundamentally (requires Flutter upgrade)

**Tested Versions**: 1.36.1 build 684, 1.37.1 build 694 (current device, verified 2026-07-22)

**Expected compatibility**: Minor versions may work without source changes, but must be verified from runtime counts and feature tests. Major versions may require new structural signatures.

### Future Roadmap

| Feature | Priority | Complexity | Benefit |
|---|---|---|---|
| Host-signature regression corpus | High | Medium | Verifies scanner coverage before release |
| Multi-version structural fixtures | Medium | Medium | Detects AOT codegen changes early |
| Typed network intercept | Low | High | Only revisit if a real Dart response/body object can be preserved |

See [local_docs/后续计划.md](local_docs/后续计划.md) for detailed roadmap.
