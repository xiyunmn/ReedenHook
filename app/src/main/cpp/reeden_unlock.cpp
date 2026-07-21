#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

#define LOG_TAG "ReedenHook.Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

// Reeden 1.36.1 / Dart 3.10.7 arm64 libapp.so
constexpr const char *kLibApp = "libapp.so";

// Feature-gate sites: `tbz wN, #4, premium` after loading CZc.Fwn.field_27.
// true -> bit4 clear -> branch to premium. We rewrite TBZ into unconditional B
// to the same target so free-path fallthrough is never taken.
//
// IMPORTANT: do NOT use inline-hook interceptors on Dart AOT code. Dart uses
// x15 as stack pointer (not SP); trampolines corrupt the isolate and hang UI.
//
// Full coverage: 73 tbz sites (complete scan of libapp.so for ldur #0x27 patterns)
constexpr uintptr_t kGateTbz[] = {
    0xDAD0A0ULL, 0xEB70E4ULL, 0xF6062CULL, 0xFD45E0ULL, 0x16C8A2CULL,
    0x170C3D0ULL, 0x176ECB4ULL, 0x1772974ULL, 0x17F1060ULL, 0x1835098ULL,
    0x18D4FBCULL, 0x18FDBA0ULL, 0x1957940ULL, 0x1A0C8E0ULL, 0x1A8B158ULL,
    0x1A8E424ULL, 0x1B52058ULL, 0x1B5D77CULL, 0x1B74A44ULL, 0x1BF2324ULL,
    0x1C5AE78ULL, 0x1C8BFE8ULL, 0x1C8C65CULL, 0x1C91A88ULL, 0x1C94EACULL,
    0x1CB62D8ULL, 0x1CBC914ULL, 0x1CD0F68ULL, 0x1CDE270ULL, 0x1CDFBF0ULL,
    0x1DFFC10ULL, 0x2299E28ULL, 0x22DCCF4ULL, 0x23D0CF4ULL, 0x23D0EE0ULL,
    0x23E6A2CULL, 0x23E6F7CULL, 0x23E7B24ULL, 0x23FFC34ULL, 0x2415590ULL,
    0x2486924ULL, 0x24CA3A0ULL, 0x24CAE8CULL, 0x24CAF94ULL, 0x24CCF78ULL,
    0x24EE608ULL, 0x24F966CULL, 0x24FFF4CULL, 0x2500024ULL, 0x2500120ULL,
    0x250A4E4ULL, 0x2520A60ULL, 0x252D4A4ULL, 0x2546558ULL, 0x254FFD4ULL,
    0x255C46CULL, 0x2584D34ULL, 0x25856ECULL, 0x25AE228ULL, 0x25AF584ULL,
    0x25B5398ULL, 0x25B64D4ULL, 0x25C7FA4ULL, 0x25C87BCULL, 0x25CBE3CULL,
    0x25D9948ULL, 0x25DE41CULL, 0x25DEC68ULL, 0x260046CULL, 0x2603B8CULL,
    0x2603D34ULL, 0x26B43ACULL,
};

// TBNZ sites: `tbnz wN, #4, free_path` -> if false, take free path (inverse polarity).
// Convert to `b free_path` (always take free path = always deny premium).
// We NOP these instead to skip the branch and fall through to premium path.
constexpr uintptr_t kGateTbnz[] = {
    0x1014524ULL, 0x104E6FCULL, 0x104F088ULL, 0x11B3B5CULL, 0x11B4830ULL,
    0x13BDBE0ULL, 0x15F7130ULL, 0x17172FCULL, 0x17AE338ULL, 0x17AF104ULL,
    0x1A0CA5CULL, 0x1AAAA48ULL, 0x1ADA7E8ULL, 0x1B22F00ULL, 0x1B30988ULL,
    0x1D5ECB8ULL, 0x21C8B54ULL, 0x22B3020ULL, 0x22CE784ULL, 0x23BA254ULL,
    0x23FABACULL, 0x2443E58ULL, 0x2443F00ULL, 0x25E22D0ULL, 0x25E9394ULL,
};

struct ExactPatchSite {
    uintptr_t off;
    uint32_t expected;
    uint32_t patched;
    const char *name;
};

// Kwn refresh path:
//   0x224883c  b.ne 0x2248844
//   0x2248840  add x2, x22, #0x30   ; false
//   0x2248844  bl  0x20F57A4        ; setter(Fwn, x2)
//
// NOP the conditional branch and turn false into true so Kwn always publishes
// true to CZc.Fwn.field_27.
constexpr ExactPatchSite kExactPatches[] = {
    {0x224883CULL, 0x54000041u, 0xD503201Fu, "Kwn.force_setter_fallthrough"},
    {0x2248840ULL, 0x9100C2C2u, 0x910082C2u, "Kwn.false_to_true"},
};

struct Patch {
    void *addr;
    uint32_t original;
    uint32_t patched;
};

std::mutex g_mu;
std::atomic<bool> g_enabled{true};
std::atomic<bool> g_installed{false};
std::atomic<int> g_patchCount{0};
void *g_libapp_base = nullptr;
std::vector<Patch> g_patches;

struct PhdrInfo {
    const char *name;
    void *base;
};

int find_lib_cb(struct dl_phdr_info *info, size_t, void *data) {
    auto *out = static_cast<PhdrInfo *>(data);
    if (info->dlpi_name == nullptr) {
        return 0;
    }
    const char *slash = strrchr(info->dlpi_name, '/');
    const char *base_name = slash ? slash + 1 : info->dlpi_name;
    if (strcmp(base_name, out->name) == 0) {
        out->base = reinterpret_cast<void *>(info->dlpi_addr);
        return 1;
    }
    return 0;
}

void *find_lib_base(const char *soname) {
    PhdrInfo info{soname, nullptr};
    dl_iterate_phdr(find_lib_cb, &info);
    return info.base;
}

static bool make_writable(void *addr, size_t len) {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto start = reinterpret_cast<uintptr_t>(addr) & ~(page - 1);
    auto end = (reinterpret_cast<uintptr_t>(addr) + len + page - 1) & ~(page - 1);
    if (mprotect(reinterpret_cast<void *>(start), end - start, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect RWX failed addr=%p errno=%d", addr, errno);
        return false;
    }
    return true;
}

static bool restore_rx(void *addr, size_t len) {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto start = reinterpret_cast<uintptr_t>(addr) & ~(page - 1);
    auto end = (reinterpret_cast<uintptr_t>(addr) + len + page - 1) & ~(page - 1);
    if (mprotect(reinterpret_cast<void *>(start), end - start, PROT_READ | PROT_EXEC) != 0) {
        LOGW("mprotect RX restore failed addr=%p errno=%d", addr, errno);
        return false;
    }
    return true;
}

// Convert the confirmed ARM64 `tbz wN, #4, label` gates into unconditional
// `b label`, keeping the same PC-relative target (imm14 -> imm26).
//
// Also accepts any wN register, not just w1, since full scan found gates using
// different registers after ldur #0x27.
static bool premium_tbz_to_unconditional_b(uint32_t insn, uint32_t *out_b) {
    // TBZ/TBNZ:  x0110110 b40:imm14:Rt  with bit31 = b5 of bit number.
    // Confirm only 32-bit TBZ (op=0x36), bit index=4, any Rt.
    const uint32_t op = (insn >> 24) & 0x7Fu;
    const uint32_t bit_index = ((insn >> 19) & 0x1Fu) | ((insn >> 26) & 0x20u);
    if (op != 0x36u || bit_index != 4u) {
        return false;
    }
    // imm14 is bits [18:5]
    int32_t imm14 = static_cast<int32_t>((insn >> 5) & 0x3FFFu);
    // sign-extend 14-bit
    if (imm14 & 0x2000) {
        imm14 |= ~0x3FFF;
    }
    // B encoding: 000101 imm26, offset = imm26 * 4, same units as imm14.
    const int32_t imm26 = imm14;  // already instruction units
    if (imm26 < -(1 << 25) || imm26 >= (1 << 25)) {
        return false;
    }
    *out_b = 0x14000000u | (static_cast<uint32_t>(imm26) & 0x03FFFFFFu);
    return true;
}

// Convert TBNZ wN, #4, free_path into NOP. TBNZ jumps if bit is set (if false),
// so we NOP it to always fall through to premium path.
static bool premium_tbnz_to_nop(uint32_t insn) {
    const uint32_t op = (insn >> 24) & 0x7Fu;
    const uint32_t bit_index = ((insn >> 19) & 0x1Fu) | ((insn >> 26) & 0x20u);
    return (op == 0x37u && bit_index == 4u);
}

static bool patch_one_tbz(void *addr) {
    auto *p = reinterpret_cast<uint32_t *>(addr);
    const uint32_t original = *p;
    uint32_t patched = 0;
    if (!premium_tbz_to_unconditional_b(original, &patched)) {
        LOGE("not expected tbz wN,#4 gate at %p insn=0x%08x", addr, original);
        return false;
    }
    if (original == patched) {
        return true;
    }
    if (!make_writable(addr, sizeof(uint32_t))) {
        return false;
    }
    *p = patched;
    __builtin___clear_cache(reinterpret_cast<char *>(addr),
                            reinterpret_cast<char *>(addr) + sizeof(uint32_t));
    restore_rx(addr, sizeof(uint32_t));
    if (*p != patched) {
        LOGE("patch readback failed at %p wrote=0x%08x read=0x%08x",
             addr,
             patched,
             *p);
        return false;
    }
    g_patches.push_back(Patch{addr, original, patched});
    LOGI("patched tbz %p: 0x%08x -> 0x%08x", addr, original, patched);
    return true;
}

static bool patch_one_tbnz(void *addr) {
    auto *p = reinterpret_cast<uint32_t *>(addr);
    const uint32_t original = *p;
    if (!premium_tbnz_to_nop(original)) {
        LOGE("not expected tbnz wN,#4 at %p insn=0x%08x", addr, original);
        return false;
    }
    const uint32_t patched = 0xD503201Fu;  // NOP
    if (original == patched) {
        return true;
    }
    if (!make_writable(addr, sizeof(uint32_t))) {
        return false;
    }
    *p = patched;
    __builtin___clear_cache(reinterpret_cast<char *>(addr),
                            reinterpret_cast<char *>(addr) + sizeof(uint32_t));
    restore_rx(addr, sizeof(uint32_t));
    if (*p != patched) {
        LOGE("patch readback failed at %p wrote=0x%08x read=0x%08x",
             addr,
             patched,
             *p);
        return false;
    }
    g_patches.push_back(Patch{addr, original, patched});
    LOGI("patched tbnz %p: 0x%08x -> 0x%08x (NOP)", addr, original, patched);
    return true;
}

static bool patch_exact(void *addr, uint32_t expected, uint32_t patched, const char *name) {
    auto *p = reinterpret_cast<uint32_t *>(addr);
    const uint32_t original = *p;
    if (original != expected) {
        LOGE("unexpected instruction for %s at %p expected=0x%08x actual=0x%08x",
             name,
             addr,
             expected,
             original);
        return false;
    }
    if (!make_writable(addr, sizeof(uint32_t))) {
        return false;
    }
    *p = patched;
    __builtin___clear_cache(reinterpret_cast<char *>(addr),
                            reinterpret_cast<char *>(addr) + sizeof(uint32_t));
    restore_rx(addr, sizeof(uint32_t));
    if (*p != patched) {
        LOGE("patch readback failed for %s at %p wrote=0x%08x read=0x%08x",
             name,
             addr,
             patched,
             *p);
        return false;
    }
    g_patches.push_back(Patch{addr, original, patched});
    LOGI("patched %s %p: 0x%08x -> 0x%08x", name, addr, original, patched);
    return true;
}

int do_install_locked() {
    if (g_installed.load()) {
        return 0;
    }

    void *base = find_lib_base(kLibApp);
    if (base == nullptr) {
        LOGE("libapp.so not loaded yet");
        return -1;
    }
    g_libapp_base = base;
    LOGI("libapp base=%p (binary-patch mode, no interceptors)", base);

    int ok = 0;
    int fail = 0;

    // Patch all TBZ sites (tbz wN, #4, premium -> b premium)
    for (uintptr_t off : kGateTbz) {
        void *addr = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(base) + off);
        if (patch_one_tbz(addr)) {
            ++ok;
        } else {
            ++fail;
        }
    }

    // Patch all TBNZ sites (tbnz wN, #4, free -> NOP)
    for (uintptr_t off : kGateTbnz) {
        void *addr = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(base) + off);
        if (patch_one_tbnz(addr)) {
            ++ok;
        } else {
            ++fail;
        }
    }

    // Patch exact Kwn sites
    for (const ExactPatchSite &site : kExactPatches) {
        void *addr = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(base) + site.off);
        if (patch_exact(addr, site.expected, site.patched, site.name)) {
            ++ok;
        } else {
            ++fail;
        }
    }

    if (ok == 0) {
        LOGE("no patches applied");
        return -2;
    }

    g_patchCount.store(ok);
    g_installed.store(true);
    LOGI("install done ok=%d fail=%d (tbz=%zu tbnz=%zu kwn=%zu)",
         ok, fail,
         sizeof(kGateTbz)/sizeof(kGateTbz[0]),
         sizeof(kGateTbnz)/sizeof(kGateTbnz[0]),
         sizeof(kExactPatches)/sizeof(kExactPatches[0]));
    return fail == 0 ? 0 : 1;
}

void do_uninstall_locked() {
    for (const Patch &patch : g_patches) {
        if (!make_writable(patch.addr, sizeof(uint32_t))) {
            continue;
        }
        *reinterpret_cast<uint32_t *>(patch.addr) = patch.original;
        __builtin___clear_cache(reinterpret_cast<char *>(patch.addr),
                                reinterpret_cast<char *>(patch.addr) + sizeof(uint32_t));
        restore_rx(patch.addr, sizeof(uint32_t));
    }
    g_patches.clear();
    g_patchCount.store(0);
    g_installed.store(false);
    LOGI("uninstalled / restored originals");
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativePremiumUnlock_nativeInstall(
    JNIEnv *,
    jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_enabled.store(true);
    return do_install_locked();
}

extern "C" JNIEXPORT void JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativePremiumUnlock_nativeUninstall(
    JNIEnv *,
    jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_enabled.store(false);
    do_uninstall_locked();
}

extern "C" JNIEXPORT void JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativePremiumUnlock_nativeSetEnabled(
    JNIEnv *,
    jclass,
    jboolean enabled) {
    // Binary patches are always-on once installed; flag kept for API parity.
    g_enabled.store(enabled == JNI_TRUE);
    LOGI("enabled=%d (patch mode ignores runtime disable until uninstall)",
         enabled == JNI_TRUE);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativePremiumUnlock_nativeIsInstalled(
    JNIEnv *,
    jclass) {
    return g_installed.load() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativePremiumUnlock_nativeStatus(
    JNIEnv *env,
    jclass) {
    char buf[256];
    snprintf(buf,
             sizeof(buf),
             "mode=patch installed=%d enabled=%d base=%p patches=%d",
             g_installed.load() ? 1 : 0,
             g_enabled.load() ? 1 : 0,
             g_libapp_base,
             g_patchCount.load());
    return env->NewStringUTF(buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    LOGI("JNI_OnLoad reeden_unlock (binary-patch mode)");
    return JNI_VERSION_1_6;
}
