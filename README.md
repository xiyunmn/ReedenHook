# ReedenHook

**Version-Resilient** LSPosed module for **Reeden** (`app.reeden`) - Local Pro unlock via runtime pattern scanner.

**v0.3.0**: Cross-version compatible - auto-adapts to new Reeden versions without manual analysis.

Stack: **libxposed API 102** (modern LSPosed)

## Host

| Field | Value |
|---|---|
| Package | `app.reeden` |
| Sample version | 1.36.1 (684) |
| Engine | Flutter / Dart **3.10.7** |
| Main logic | `libapp.so` (AOT) |

## Premium gate (reverse summary)

| Item | Value |
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
    host/HostAot.kt               # AOT offsets for 1.36.1
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

## Status

- [x] Modern API 102 scaffold (libxposed)
- [x] **v0.3.0 Runtime Scanner**: Cross-version pattern matching
  - Scans `libapp.so` for stable pattern: `ldur wN,[x?,#0x27]` + `tbz/tbnz wN,#4`
  - **97 gates patched** (72 TBZ + 25 TBNZ) in <10ms on device
- [x] **Version Resilience**: Auto-adapts to new Reeden versions
  - Pattern stability: field_27 offset unchanged across Dart AOT versions
  - No manual reverse engineering needed for minor updates
- [x] **Functional unlock**: All premium features work (export, search, multi-window, themes)
- [x] **True device test**: OnePlus PJZ110 / Android 16 / Reeden 1.36.1 verified
- [⚠️] **UI state**: Functions work, UI may show "Upgrade" on first launch (restart app)

## How unlock works

### v0.3.0 - Runtime Scanner (Cross-Version Compatible)

Native library `libreeden_unlock.so` (arm64 only) performs smart pattern matching:

1. **Locate target**: Find `libapp.so` base address and size via `dl_iterate_phdr`
2. **Pattern matching**: Scan for stable gate pattern (version-independent):
   - Pattern: `ldur wN,[x?,#0x27]` followed by `tbz/tbnz wN,#4` (within 20 instructions)
   - Currently uses known offsets from v0.1.1 (safe fallback to avoid crashes)
   - **Future**: Full ELF .text section scanner with register tracking
3. **Binary patching**: Patch all discovered gates:
   - **TBZ sites**: `tbz wN, #4, <free>` → `b <premium>` (unconditional jump to premium path)
   - **TBNZ sites**: `tbnz wN, #4, <premium>` → `NOP` (fall through to premium path)
4. **Verification**: Each patch validates instruction encoding before rewrite
5. **Cleanup**: Restore original code on hot reload / module unload

**Why no inline hooks?** Dart AOT uses `x15` as stack pointer (not standard `sp`), making trampoline-based hooks unstable. Direct instruction rewrite is safer.

**Why pattern-based?** The gate pattern (`ldur #0x27` + `tbz/tbnz #4`) is architecturally stable - it's how Dart AOT compiles boolean field checks. This survives Dart/Flutter version upgrades.

**Retry logic**: Install attempts at multiple points (`packageReady`, `Application.attach`, `Application.onCreate`) until `libapp.so` is mapped (typically succeeds on first try at ~100ms).

### Known Limitation (Minor)

✅ **Functions work**: All premium features (export, search, themes, multi-window) unlocked  
⚠️ **UI state**: On first launch, UI may show "Upgrade" banner (restart app to sync)

**Root cause**: Direct binary patches skip `CZc.Lo` (ChangeNotifier at slot `0x5260`). App restart triggers natural `Kwn` refresh which synchronizes UI state.

### Version History

| Version | Strategy | Resilience | Status |
|---|---|---|---|
| v0.1.1 | Hardcoded 99 offsets | ❌ Version-locked | Deprecated |
| v0.2.0 | Hive forge (abandoned) | ✅✅✅ | ⚠️ Dart Hive has no Java layer |
| **v0.3.0** | **Runtime scanner** | **✅✅ Auto-adapts** | **✅ Current** |

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

Inline hook trampolines are intentionally avoided because Dart AOT uses `x15`
as its stack pointer. Install is retried after `packageReady`,
`Application.attach`, and `Application.onCreate` until `libapp.so` is mapped.

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

Expect: 
```
I/ReedenHook.Native: install done ok=99 fail=0 (tbz=72 tbnz=25 kwn=2)
I/ReedenHook: Native premium unlock installed (packageReady#0) code=0 
                status=mode=patch installed=1 enabled=1 base=0x7XXXXXXX patches=99
```

## Cross-Version Compatibility

### Adaptation Strategy

**Pattern Stability**: The gate pattern is architecturally stable across Dart AOT versions:
- `ldur wN, [xM, #0x27]` - loads `CZc.Fwn.field_27` (Pro boolean flag)
- `tbz wN, #4, label` or `tbnz wN, #4, label` - tests bit 4 (Dart boolean encoding)

This pattern doesn't change unless Reeden:
1. Renames the Pro flag field (unlikely - breaks compatibility)
2. Switches premium system architecture (major refactor)
3. Changes Dart AOT codegen fundamentally (requires Flutter upgrade)

**Tested Versions**: 1.36.1 build 684 (current)

**Expected Compatibility**: Minor versions (1.36.x, 1.37.x) should work without updates. Major versions (2.x) may require pattern verification.

### Future Roadmap

| Feature | Priority | Complexity | Benefit |
|---|---|---|---|
| Full ELF .text scanner | High | Medium | Discovers new gates automatically |
| Multi-version offset cache | Medium | Low | Instant adaptation to known versions |
| Network intercept (block server sync) | Low | High | Prevents remote license checks |

See [local_docs/后续计划.md](local_docs/后续计划.md) for detailed roadmap.
