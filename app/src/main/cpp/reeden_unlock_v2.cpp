#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <netdb.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <mutex>
#include <vector>

#define LOG_TAG "ReedenHook.Native"

namespace {

constexpr size_t kNativeLogPathCount = 2;
constexpr size_t kNativeLogPathMax = 512;
constexpr size_t kNativeLogLineMax = 1536;
constexpr off_t kNativeLogMaxBytes = 512 * 1024;

std::mutex g_native_log_mu;
char g_native_log_paths[kNativeLogPathCount][kNativeLogPathMax] = {};

pid_t current_tid() {
    return static_cast<pid_t>(syscall(__NR_gettid));
}

void write_all(int fd, const char *data, size_t len) {
    while (len > 0) {
        const ssize_t written = write(fd, data, len);
        if (written <= 0) {
            return;
        }
        data += written;
        len -= static_cast<size_t>(written);
    }
}

void rotate_native_log_if_needed(const char *path, size_t incoming_bytes) {
    struct stat st {};
    if (stat(path, &st) != 0 ||
        st.st_size + static_cast<off_t>(incoming_bytes) <= kNativeLogMaxBytes) {
        return;
    }
    char backup[kNativeLogPathMax + 4] {};
    const int len = snprintf(backup, sizeof(backup), "%s.1", path);
    if (len <= 0 || static_cast<size_t>(len) >= sizeof(backup)) {
        return;
    }
    unlink(backup);
    rename(path, backup);
}

void append_native_file_log(const char *level, const char *message) {
    char paths[kNativeLogPathCount][kNativeLogPathMax] {};
    {
        std::lock_guard<std::mutex> lock(g_native_log_mu);
        for (size_t i = 0; i < kNativeLogPathCount; ++i) {
            snprintf(paths[i], sizeof(paths[i]), "%s", g_native_log_paths[i]);
        }
    }

    bool has_path = false;
    for (size_t i = 0; i < kNativeLogPathCount; ++i) {
        if (paths[i][0] != '\0') {
            has_path = true;
            break;
        }
    }
    if (!has_path) {
        return;
    }

    struct timespec ts {};
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_value {};
    localtime_r(&ts.tv_sec, &tm_value);
    char stamp[32] {};
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm_value);

    char line[kNativeLogLineMax] {};
    const int line_len = snprintf(
        line,
        sizeof(line),
        "%s.%03ld %s/%s(%d:%d): %s\n",
        stamp,
        ts.tv_nsec / 1000000L,
        level,
        LOG_TAG,
        getpid(),
        current_tid(),
        message ? message : "");
    if (line_len <= 0) {
        return;
    }
    const size_t bytes =
        static_cast<size_t>(line_len) < sizeof(line) ?
        static_cast<size_t>(line_len) :
        sizeof(line) - 1;

    std::lock_guard<std::mutex> lock(g_native_log_mu);
    for (size_t i = 0; i < kNativeLogPathCount; ++i) {
        const char *path = g_native_log_paths[i];
        if (path[0] == '\0') {
            continue;
        }
        rotate_native_log_if_needed(path, bytes);
        const int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0) {
            continue;
        }
        write_all(fd, line, bytes);
        close(fd);
    }
}

void log_message(int priority, const char *level, const char *fmt, ...) {
    char message[1024] {};
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    __android_log_print(priority, LOG_TAG, "%s", message);
    append_native_file_log(level, message);
}

#define LOGI(...) log_message(ANDROID_LOG_INFO, "I", __VA_ARGS__)
#define LOGW(...) log_message(ANDROID_LOG_WARN, "W", __VA_ARGS__)
#define LOGE(...) log_message(ANDROID_LOG_ERROR, "E", __VA_ARGS__)

// Single-pass native unlock strategy (v0.4.6):
//
// 1) License publication (primary, UI-friendly):
//    Scan Kwn's unique GZc.valid -> null/false fallback -> setter sequence and
//    force the fallback value to Dart `true`. When Kwn runs, Fwn.field_27 is
//    published through the app's own ChangeNotifier path.
//
// 2) Feature-gate scan (fallback, functional unlock):
//    Scan stable AOT micro-sequences that test Fwn.field_27 bit4:
//      ldur wN, [x?, #0x27]
//      add  xN, xN, x28, lsl #32   ; decompress compressed pointer
//      tbz / tbnz wN, #4, target   ; immediately after decompress
//    TBZ  (jump if false/bit clear) -> unconditional B same target (premium)
//    TBNZ (jump if true/bit set to free path) -> NOP (fall through premium)
//
// Why this shape: the field publication and gate cluster are stable across the
// currently known 1.36.x / 1.37.x builds, while the license/checkLicense async
// chain proved brittle under runtime return-shape changes.

constexpr const char *kLibApp = "libapp.so";
constexpr const char *kLibFlutter = "libflutter.so";
constexpr const char *kMode = "single_pass_gate_scan";
constexpr uint32_t kNop = 0xD503201Fu;
constexpr uint32_t kDartFalseOffset = 0x30u;
constexpr uint32_t kDartTrueOffset = 0x20u;
constexpr uint32_t kField27Imm9 = 0x27u;
constexpr uint32_t kGzcValidImm9 = 0x0Fu;
// Sentinel for "no static-field slot found".
constexpr uint32_t kNoSlot = 0xFFFFFFFFu;

struct ExecutableSegment {
    uint8_t *start;
    size_t size;
};

struct ImageInfo {
    void *base = nullptr;
    size_t image_size = 0;
    std::vector<ExecutableSegment> executable_segments;
};

struct Patch {
    uint32_t *addr;
    uint32_t original;
    uint32_t patched;
};

struct LicensePublishSite {
    uint32_t *branch;
    uint32_t *false_value;
    uintptr_t rva;
};

enum class GateKind : uint8_t {
    kTbz = 0,
    kTbnz = 1,
};

struct GateSite {
    uint32_t *branch;
    GateKind kind;
    uintptr_t rva;
    uint32_t slot;  // THR field-table byte offset of the anchoring static field.
    bool supplemental;
};

std::mutex g_mu;
std::atomic<bool> g_enabled{true};
std::atomic<bool> g_installed{false};
std::atomic<int> g_patch_count{0};
std::atomic<int> g_gate_tbz{0};
std::atomic<int> g_gate_tbnz{0};
std::atomic<int> g_gate_supplemental{0};
std::atomic<int> g_license_patches{0};
void *g_libapp_base = nullptr;
size_t g_libapp_size = 0;
uintptr_t g_license_publish_rva = 0;
std::vector<Patch> g_patches;

using GetAddrInfoFn = int (*)(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res);

std::atomic<bool> g_network_guard_enabled{true};
std::atomic<bool> g_network_guard_installed{false};
std::atomic<int> g_network_guard_hits{0};
std::atomic<int> g_network_guard_attempts{0};
void **g_getaddrinfo_slot = nullptr;
GetAddrInfoFn g_real_getaddrinfo = nullptr;

bool is_license_host(const char *node) {
    if (node == nullptr) {
        return false;
    }
    return strcmp(node, "license.reeden.app") == 0 ||
        strcmp(node, "license-cn.reeden.app") == 0;
}

int hooked_getaddrinfo(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res) {
    if (g_network_guard_enabled.load() && is_license_host(node)) {
        const int hit = g_network_guard_hits.fetch_add(1) + 1;
        if (hit <= 8 || hit % 20 == 0) {
            LOGI(
                "license getaddrinfo blocked #%d host=%s service=%s",
                hit,
                node,
                service ? service : "");
        }
        if (res != nullptr) {
            *res = nullptr;
        }
        return EAI_NONAME;
    }
    GetAddrInfoFn real = g_real_getaddrinfo;
    if (real == nullptr) {
        real = reinterpret_cast<GetAddrInfoFn>(dlsym(RTLD_NEXT, "getaddrinfo"));
    }
    return real ? real(node, service, hints, res) : EAI_FAIL;
}

struct ImportHookRequest {
    const char *library_name;
    const char *symbol_name;
    void *replacement;
    void **original;
    void ***slot_out;
    bool patched;
    bool library_seen;
};

template <typename T>
T *dynamic_ptr(ElfW(Addr) value, ElfW(Addr) base) {
    const uintptr_t raw = static_cast<uintptr_t>(value);
    if (raw >= static_cast<uintptr_t>(base)) {
        return reinterpret_cast<T *>(raw);
    }
    return reinterpret_cast<T *>(static_cast<uintptr_t>(base) + raw);
}

bool patch_pointer_slot(void **slot, void *replacement, void **original) {
    if (slot == nullptr || replacement == nullptr) {
        return false;
    }
    if (*slot == replacement) {
        return true;
    }
    if (original != nullptr && *original == nullptr) {
        *original = *slot;
    }

    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const uintptr_t start = reinterpret_cast<uintptr_t>(slot) & ~(page - 1);
    if (mprotect(reinterpret_cast<void *>(start), page, PROT_READ | PROT_WRITE) != 0) {
        LOGE("network guard mprotect RW failed slot=%p errno=%d", slot, errno);
        return false;
    }
    *slot = replacement;
    // Keep the GOT page writable after patching. Some Android builds co-locate
    // mutable runtime data with GOT/RELRO pages; restoring read-only here can
    // break those builds even though this target currently uses BIND_NOW.
    if (mprotect(reinterpret_cast<void *>(start), page, PROT_READ | PROT_WRITE) != 0) {
        LOGW("network guard mprotect restore failed slot=%p errno=%d", slot, errno);
    }
    return *slot == replacement;
}

int hook_import_cb(struct dl_phdr_info *info, size_t, void *data) {
    auto *request = static_cast<ImportHookRequest *>(data);
    if (info->dlpi_name == nullptr) {
        return 0;
    }
    const char *slash = strrchr(info->dlpi_name, '/');
    const char *base_name = slash ? slash + 1 : info->dlpi_name;
    if (strcmp(base_name, request->library_name) != 0) {
        return 0;
    }
    request->library_seen = true;

    auto *dynamic = static_cast<ElfW(Dyn) *>(nullptr);
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &phdr = info->dlpi_phdr[i];
        if (phdr.p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<ElfW(Dyn) *>(info->dlpi_addr + phdr.p_vaddr);
            break;
        }
    }
    if (dynamic == nullptr) {
        LOGW("network guard: PT_DYNAMIC not found for %s", request->library_name);
        return 1;
    }

    auto *symtab = static_cast<ElfW(Sym) *>(nullptr);
    auto *strtab = static_cast<const char *>(nullptr);
    auto *rela = static_cast<ElfW(Rela) *>(nullptr);
    size_t rela_count = 0;

    for (ElfW(Dyn) *entry = dynamic; entry->d_tag != DT_NULL; ++entry) {
        switch (entry->d_tag) {
            case DT_SYMTAB:
                symtab = dynamic_ptr<ElfW(Sym)>(entry->d_un.d_ptr, info->dlpi_addr);
                break;
            case DT_STRTAB:
                strtab = dynamic_ptr<const char>(entry->d_un.d_ptr, info->dlpi_addr);
                break;
            case DT_JMPREL:
                rela = dynamic_ptr<ElfW(Rela)>(entry->d_un.d_ptr, info->dlpi_addr);
                break;
            case DT_PLTRELSZ:
                rela_count = static_cast<size_t>(entry->d_un.d_val) / sizeof(ElfW(Rela));
                break;
            default:
                break;
        }
    }

    if (symtab == nullptr || strtab == nullptr || rela == nullptr || rela_count == 0) {
        LOGW(
            "network guard: relocation data incomplete for %s symtab=%p strtab=%p rela=%p count=%zu",
            request->library_name,
            symtab,
            strtab,
            rela,
            rela_count);
        return 1;
    }

    for (size_t i = 0; i < rela_count; ++i) {
        const auto type = ELF64_R_TYPE(rela[i].r_info);
        if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT) {
            continue;
        }
        const auto symbol_index = ELF64_R_SYM(rela[i].r_info);
        const char *name = strtab + symtab[symbol_index].st_name;
        if (strcmp(name, request->symbol_name) != 0) {
            continue;
        }

        auto **slot = reinterpret_cast<void **>(info->dlpi_addr + rela[i].r_offset);
        if (patch_pointer_slot(slot, request->replacement, request->original)) {
            if (request->slot_out != nullptr) {
                *request->slot_out = slot;
            }
            request->patched = true;
            LOGI(
                "network guard hooked %s!%s slot=%p original=%p replacement=%p",
                request->library_name,
                request->symbol_name,
                slot,
                request->original ? *request->original : nullptr,
                request->replacement);
        } else {
            LOGE(
                "network guard failed to hook %s!%s slot=%p",
                request->library_name,
                request->symbol_name,
                slot);
        }
        return 1;
    }

    LOGW(
        "network guard: symbol %s not found in %s PLT relocations",
        request->symbol_name,
        request->library_name);
    return 1;
}

int install_network_guard_locked() {
    g_network_guard_attempts.fetch_add(1);
    g_network_guard_enabled.store(true);
    if (g_network_guard_installed.load()) {
        return 0;
    }

    void *real = dlsym(RTLD_NEXT, "getaddrinfo");
    if (real == nullptr) {
        real = dlsym(RTLD_DEFAULT, "getaddrinfo");
    }
    if (real == nullptr) {
        LOGE("network guard: dlsym(getaddrinfo) failed");
        return -2;
    }
    g_real_getaddrinfo = reinterpret_cast<GetAddrInfoFn>(real);

    void *original = reinterpret_cast<void *>(g_real_getaddrinfo);
    ImportHookRequest request{
        kLibFlutter,
        "getaddrinfo",
        reinterpret_cast<void *>(hooked_getaddrinfo),
        &original,
        &g_getaddrinfo_slot,
        false,
        false,
    };
    dl_iterate_phdr(hook_import_cb, &request);

    if (!request.library_seen) {
        LOGW("network guard: %s not loaded yet", kLibFlutter);
        return -1;
    }
    if (!request.patched) {
        return -3;
    }

    g_real_getaddrinfo = reinterpret_cast<GetAddrInfoFn>(original);
    g_network_guard_installed.store(true);
    LOGI(
        "network guard installed mode=flutter_getaddrinfo_block slot=%p attempts=%d",
        g_getaddrinfo_slot,
        g_network_guard_attempts.load());
    return 0;
}

int find_lib_cb(struct dl_phdr_info *info, size_t, void *data) {
    auto *out = static_cast<ImageInfo *>(data);
    if (info->dlpi_name == nullptr) {
        return 0;
    }

    const char *slash = strrchr(info->dlpi_name, '/');
    const char *base_name = slash ? slash + 1 : info->dlpi_name;
    if (strcmp(base_name, kLibApp) != 0) {
        return 0;
    }

    out->base = reinterpret_cast<void *>(info->dlpi_addr);
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD) {
            continue;
        }

        const size_t end = static_cast<size_t>(phdr.p_vaddr + phdr.p_memsz);
        if (end > out->image_size) {
            out->image_size = end;
        }

        if ((phdr.p_flags & PF_X) == 0 || phdr.p_memsz < 24) {
            continue;
        }

        auto *start = reinterpret_cast<uint8_t *>(info->dlpi_addr + phdr.p_vaddr);
        out->executable_segments.push_back(
            ExecutableSegment{start, static_cast<size_t>(phdr.p_memsz)});
    }
    return 1;
}

bool find_libapp(ImageInfo *out) {
    dl_iterate_phdr(find_lib_cb, out);
    return out->base != nullptr && !out->executable_segments.empty();
}

bool set_page_permissions(void *addr, size_t len, int permissions) {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const uintptr_t start = reinterpret_cast<uintptr_t>(addr) & ~(page - 1);
    const uintptr_t end =
        (reinterpret_cast<uintptr_t>(addr) + len + page - 1) & ~(page - 1);
    if (mprotect(reinterpret_cast<void *>(start), end - start, permissions) != 0) {
        LOGE("mprotect failed addr=%p permissions=0x%x errno=%d", addr, permissions, errno);
        return false;
    }
    return true;
}

bool patch_instruction(uint32_t *addr, uint32_t patched) {
    const uint32_t original = *addr;
    if (original == patched) {
        return true;
    }
    if (!set_page_permissions(addr, sizeof(*addr), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return false;
    }

    *addr = patched;
    __builtin___clear_cache(
        reinterpret_cast<char *>(addr),
        reinterpret_cast<char *>(addr) + sizeof(*addr));
    set_page_permissions(addr, sizeof(*addr), PROT_READ | PROT_EXEC);

    if (*addr != patched) {
        LOGE("patch readback failed at %p wrote=0x%08x read=0x%08x", addr, patched, *addr);
        return false;
    }
    g_patches.push_back(Patch{addr, original, patched});
    return true;
}

// ---------------------------------------------------------------------------
// ARM64 instruction predicates
// ---------------------------------------------------------------------------

bool is_ldur_w_imm(uint32_t insn, uint32_t imm9) {
    return ((insn >> 21) & 0x7FFu) == 0x5C2u &&
        ((insn >> 12) & 0x1FFu) == imm9 &&
        ((insn >> 10) & 0x3u) == 0;
}

bool is_decompress_with_x28(uint32_t insn, uint32_t value_reg) {
    // add xN, xN, x28, lsl #32
    return ((insn >> 24) & 0xFFu) == 0x8Bu &&
        ((insn >> 22) & 0x3u) == 0 &&
        ((insn >> 16) & 0x1Fu) == 28u &&
        ((insn >> 10) & 0x3Fu) == 32u &&
        ((insn >> 5) & 0x1Fu) == value_reg &&
        (insn & 0x1Fu) == value_reg;
}

bool is_cmp_w_reg_w22(uint32_t insn, uint32_t value_reg) {
    return ((insn >> 21) & 0x7FFu) == 0x358u &&
        ((insn >> 16) & 0x1Fu) == 22u &&
        ((insn >> 10) & 0x3Fu) == 0 &&
        ((insn >> 5) & 0x1Fu) == value_reg &&
        (insn & 0x1Fu) == 31u;
}

bool is_b_ne_skip_one(uint32_t insn) {
    return ((insn >> 24) & 0xFFu) == 0x54u &&
        ((insn >> 5) & 0x7FFFFu) == 2u &&
        (insn & 0x1Fu) == 1u;
}

bool is_add_x_reg_x22_imm(uint32_t insn, uint32_t value_reg, uint32_t imm12) {
    return ((insn >> 23) & 0x1FFu) == 0x122u &&
        ((insn >> 22) & 0x1u) == 0 &&
        ((insn >> 10) & 0xFFFu) == imm12 &&
        ((insn >> 5) & 0x1Fu) == 22u &&
        (insn & 0x1Fu) == value_reg;
}

bool is_bl(uint32_t insn) {
    return ((insn >> 26) & 0x3Fu) == 0x25u;
}

bool is_ldur_x_from_fp(uint32_t insn, uint32_t value_reg) {
    return ((insn >> 21) & 0x7FFu) == 0x7C2u &&
        ((insn >> 5) & 0x1Fu) == 29u &&
        (insn & 0x1Fu) == value_reg;
}

bool is_cmp_w_regs(uint32_t insn, uint32_t left_reg, uint32_t right_reg) {
    return ((insn >> 21) & 0x7FFu) == 0x358u &&
        ((insn >> 16) & 0x1Fu) == right_reg &&
        ((insn >> 10) & 0x3Fu) == 0 &&
        ((insn >> 5) & 0x1Fu) == left_reg &&
        (insn & 0x1Fu) == 31u;
}

uintptr_t pc_relative_target(uint32_t *addr, uint32_t encoded, uint32_t mask) {
    int64_t immediate = static_cast<int64_t>(encoded & mask);
    const int64_t sign_bit = static_cast<int64_t>(mask + 1u) >> 1;
    if ((immediate & sign_bit) != 0) {
        immediate -= static_cast<int64_t>(mask) + 1;
    }
    return reinterpret_cast<uintptr_t>(addr) + immediate * sizeof(uint32_t);
}

bool is_b_cond_to(
    uint32_t *addr, uint32_t insn, uint32_t condition, uint32_t *target) {
    if ((insn & 0xFF000010u) != 0x54000000u ||
        (insn & 0xFu) != condition) {
        return false;
    }
    const uint32_t imm19 = (insn >> 5) & 0x7FFFFu;
    return pc_relative_target(addr, imm19, 0x7FFFFu) ==
        reinterpret_cast<uintptr_t>(target);
}

bool is_b_to(uint32_t *addr, uint32_t insn, uint32_t **target) {
    if (((insn >> 26) & 0x3Fu) != 0x05u) {
        return false;
    }
    *target = reinterpret_cast<uint32_t *>(
        pc_relative_target(addr, insn & 0x03FFFFFFu, 0x03FFFFFFu));
    return true;
}

bool is_bl_to(uint32_t *addr, uint32_t insn, uint32_t **target) {
    if (!is_bl(insn)) {
        return false;
    }
    *target = reinterpret_cast<uint32_t *>(
        pc_relative_target(addr, insn & 0x03FFFFFFu, 0x03FFFFFFu));
    return true;
}

bool is_ldr_x0_thr_field_table(uint32_t insn) {
    // ldr x0, [x26, #0x78]
    return insn == 0xF9403F40u;
}

// ldr x?, [x26, #0x78] : load THR::field_table_values into any destination reg.
// (x26 == THR in Dart AOT). This anchors every InitLateStaticField prologue.
bool is_ldr_thr_field_table_any(uint32_t insn) {
    // LDR (immediate, 64-bit, unsigned offset): size=11 V=0 opc=01 -> 0b1111100101
    // Rn must be x26, imm12 == 0x78/8 == 0xf.
    return ((insn >> 22) & 0x3FFu) == 0x3E5u &&
        ((insn >> 10) & 0xFFFu) == 0x0Fu &&
        ((insn >> 5) & 0x1Fu) == 26u;
}

// LDR (immediate, 64-bit, unsigned offset). Returns byte offset (imm12 * 8),
// or kNoSlot if the instruction is not this form.
uint32_t ldr_x_unsigned_byte_offset(uint32_t insn) {
    if (((insn >> 22) & 0x3FFu) != 0x3E5u) {
        return kNoSlot;
    }
    return ((insn >> 10) & 0xFFFu) * 8u;
}

uint32_t tbz_tbnz_bit_index(uint32_t insn) {
    // bit number = {b5=insn[31], b40=insn[23:19]}
    return ((insn >> 19) & 0x1Fu) | (((insn >> 31) & 0x1u) << 5);
}

bool is_tbz_bit4(uint32_t insn, uint32_t reg) {
    // TBZ: op=0x36, bit=4, Rt=reg
    return ((insn >> 24) & 0x7Fu) == 0x36u &&
        tbz_tbnz_bit_index(insn) == 4u &&
        (insn & 0x1Fu) == reg;
}

bool is_tbnz_bit4(uint32_t insn, uint32_t reg) {
    // TBNZ: op=0x37, bit=4, Rt=reg
    return ((insn >> 24) & 0x7Fu) == 0x37u &&
        tbz_tbnz_bit_index(insn) == 4u &&
        (insn & 0x1Fu) == reg;
}

bool decode_gate_kind(uint32_t insn, uint32_t reg, GateKind *kind) {
    if (is_tbz_bit4(insn, reg)) {
        *kind = GateKind::kTbz;
        return true;
    }
    if (is_tbnz_bit4(insn, reg)) {
        *kind = GateKind::kTbnz;
        return true;
    }
    return false;
}

uint32_t replace_add_imm12(uint32_t insn, uint32_t imm12) {
    return (insn & ~(0xFFFu << 10)) | ((imm12 & 0xFFFu) << 10);
}

// TBZ imm14 -> unconditional B with same PC-relative target (instruction units).
bool tbz_to_unconditional_b(uint32_t insn, uint32_t *out_b) {
    if (((insn >> 24) & 0x7Fu) != 0x36u || tbz_tbnz_bit_index(insn) != 4u) {
        return false;
    }
    int32_t imm14 = static_cast<int32_t>((insn >> 5) & 0x3FFFu);
    if (imm14 & 0x2000) {
        imm14 |= ~0x3FFF;
    }
    if (imm14 < -(1 << 25) || imm14 >= (1 << 25)) {
        return false;
    }
    *out_b = 0x14000000u | (static_cast<uint32_t>(imm14) & 0x03FFFFFFu);
    return true;
}

bool segment_contains(
    const ExecutableSegment &segment, const uint32_t *addr, size_t count);

// ---------------------------------------------------------------------------
// License publication scanner (unique Kwn micro-sequence)
// ---------------------------------------------------------------------------
//
//   ldur wN, [xM, #0xf]       ; GZc.valid
//   add  xN, xN, x28, lsl #32
//   cmp  wN, w22              ; null?
//   b.ne setter               ; non-null -> use value
//   add  xN, x22, #0x30       ; null -> Dart false
//   bl   setter
//   ldr  x0, [x26, #0x78]     ; next THR field-table access (anchors the site)

std::vector<LicensePublishSite> scan_license_publish_sites(const ImageInfo &image) {
    std::vector<LicensePublishSite> sites;

    for (const ExecutableSegment &segment : image.executable_segments) {
        for (size_t offset = 0; offset + 28 <= segment.size; offset += sizeof(uint32_t)) {
            auto *instructions =
                reinterpret_cast<uint32_t *>(segment.start + offset);
            const uint32_t value_reg = instructions[0] & 0x1Fu;

            if (!is_ldur_w_imm(instructions[0], kGzcValidImm9) ||
                !is_decompress_with_x28(instructions[1], value_reg) ||
                !is_cmp_w_reg_w22(instructions[2], value_reg) ||
                !is_b_ne_skip_one(instructions[3]) ||
                !is_add_x_reg_x22_imm(
                    instructions[4], value_reg, kDartFalseOffset) ||
                !is_bl(instructions[5]) ||
                !is_ldr_x0_thr_field_table(instructions[6])) {
                continue;
            }

            const uintptr_t rva =
                reinterpret_cast<uintptr_t>(instructions) -
                reinterpret_cast<uintptr_t>(image.base);
            sites.push_back(
                LicensePublishSite{&instructions[3], &instructions[4], rva});
        }
    }
    return sites;
}

// ---------------------------------------------------------------------------
// Feature-gate scanner (cross-version, slot-anchored)
// ---------------------------------------------------------------------------
//
// Every real premium gate tests CZc.Fwn.field_27, and Fwn is a `static late`
// field always reached through the identical InitLateStaticField prologue:
//
//   ldr  x?, [x26, #0x78]     ; THR::field_table_values
//   ldr  x?, [x?,  #SLOT]     ; <- CZc.Fwn lives in one specific slot
//   ...  InitLateStaticFieldStub ...
//   ldur wN, [x?, #0x27]      ; Fwn.field_27
//   add  xN, xN, x28, lsl #32 ; decompress
//   tbz / tbnz wN, #4, ...    ; premium branch
//
// The bare `ldur#0x27 + decompress + tbz/tbnz#4` shape is NOT unique — offset
// 0x27 / bit 4 is a generic Dart bool layout, so patching all matches (357 on
// 1.36.1) corrupts unrelated logic and breaks core screens. Instead we tag each
// candidate with the field-table SLOT loaded in its InitLateStaticField prologue
// (scanning back a bounded window), then patch ONLY the dominant slot's cluster.
//
// Offline against 1.36.1: dominant slot = 0x5268, 90 adjacent gates, ZERO false
// positives. Seven more gates use delayed or derived control flow; they are picked
// up by the supplemental structural scanner below. The slot is still discovered
// at runtime, so neither scanner depends on a hardcoded RVA or field-table slot.

constexpr size_t kSlotBackWindow = 20;  // instructions to scan back for prologue

uint32_t find_anchor_slot(
    const ExecutableSegment &segment, uint32_t *ldur_addr) {
    // Walk back from the ldur, looking for `ldr x?,[x26,#0x78]` immediately
    // followed by `ldr x?,[x?,#SLOT]`. Return SLOT byte offset, else kNoSlot.
    for (size_t back = 1; back <= kSlotBackWindow; ++back) {
        uint32_t *at = ldur_addr - back;
        if (reinterpret_cast<uint8_t *>(at) < segment.start) {
            break;
        }
        if (!is_ldr_thr_field_table_any(*at)) {
            continue;
        }
        // Next instruction should load the static field's cell from a slot.
        const uint32_t slot = ldr_x_unsigned_byte_offset(*(at + 1));
        if (slot != kNoSlot) {
            return slot;
        }
    }
    return kNoSlot;
}

std::vector<GateSite> scan_feature_gates(const ImageInfo &image) {
    std::vector<GateSite> sites;

    for (const ExecutableSegment &segment : image.executable_segments) {
        if (segment.size < 12) {
            continue;
        }
        const size_t limit = segment.size - 12;
        for (size_t offset = 0; offset <= limit; offset += sizeof(uint32_t)) {
            auto *instructions =
                reinterpret_cast<uint32_t *>(segment.start + offset);
            const uint32_t value_reg = instructions[0] & 0x1Fu;

            if (!is_ldur_w_imm(instructions[0], kField27Imm9) ||
                !is_decompress_with_x28(instructions[1], value_reg)) {
                continue;
            }

            GateKind kind;
            if (!decode_gate_kind(instructions[2], value_reg, &kind)) {
                continue;
            }

            const uint32_t slot = find_anchor_slot(segment, &instructions[0]);
            const uintptr_t rva =
                reinterpret_cast<uintptr_t>(&instructions[2]) -
                reinterpret_cast<uintptr_t>(image.base);
            sites.push_back(
                GateSite{&instructions[2], kind, rva, slot, false});
        }
    }
    return sites;
}

// Pick the field-table slot that anchors the most gates (excluding kNoSlot).
// That cluster is the CZc.Fwn premium-gate family.
uint32_t dominant_gate_slot(const std::vector<GateSite> &gates) {
    // Small linear tally: slot counts. Gate counts are in the low hundreds.
    std::vector<std::pair<uint32_t, int>> counts;
    for (const GateSite &gate : gates) {
        if (gate.slot == kNoSlot) {
            continue;
        }
        bool found = false;
        for (auto &entry : counts) {
            if (entry.first == gate.slot) {
                ++entry.second;
                found = true;
                break;
            }
        }
        if (!found) {
            counts.emplace_back(gate.slot, 1);
        }
    }
    uint32_t best_slot = kNoSlot;
    int best_count = 0;
    for (const auto &entry : counts) {
        if (entry.second > best_count) {
            best_count = entry.second;
            best_slot = entry.first;
        }
    }
    return best_slot;
}

bool segment_contains(
    const ExecutableSegment &segment, const uint32_t *addr, size_t count) {
    const uintptr_t start = reinterpret_cast<uintptr_t>(segment.start);
    const uintptr_t end = start + segment.size;
    const uintptr_t at = reinterpret_cast<uintptr_t>(addr);
    return at >= start && at <= end && count <= (end - at) / sizeof(uint32_t);
}

void append_supplemental_gate(
    std::vector<GateSite> *sites,
    uint32_t *branch,
    GateKind kind,
    uint32_t slot,
    const ImageInfo &image) {
    for (const GateSite &site : *sites) {
        if (site.branch == branch) {
            return;
        }
    }
    const uintptr_t rva =
        reinterpret_cast<uintptr_t>(branch) -
        reinterpret_cast<uintptr_t>(image.base);
    sites->push_back(GateSite{branch, kind, rva, slot, true});
}

// Some AOT gates are not the adjacent three-instruction micro-sequence:
//
//  * switch-like code carries the Fwn boolean across a short control-flow block;
//  * helper calls combine Fwn with another value and branch on the result;
//  * one helper receives the Fwn boolean as an argument and tests it at entry.
//
// These structural signatures are intentionally strict. Each begins at an
// `ldur field_27 + decompress` pair anchored to the already-discovered dominant
// slot, and all control-flow targets/registers are verified before a gate is
// accepted. On 1.36.1 this contributes seven gates (97 total) with no RVAs.
std::vector<GateSite> scan_supplemental_feature_gates(
    const ImageInfo &image, uint32_t dominant_slot) {
    std::vector<GateSite> sites;

    for (const ExecutableSegment &segment : image.executable_segments) {
        for (size_t offset = 0; offset + 8 <= segment.size;
             offset += sizeof(uint32_t)) {
            auto *instructions =
                reinterpret_cast<uint32_t *>(segment.start + offset);
            const uint32_t value_reg = instructions[0] & 0x1Fu;
            if (!is_ldur_w_imm(instructions[0], kField27Imm9) ||
                !is_decompress_with_x28(instructions[1], value_reg) ||
                find_anchor_slot(segment, instructions) != dominant_slot) {
                continue;
            }

            GateKind kind;

            // Delayed test: two conditional arms preserve the Fwn register and
            // converge at the bit test; the other arms bypass it.
            if (segment_contains(segment, instructions, 18)) {
                uint32_t *first_bypass = nullptr;
                uint32_t *second_bypass = nullptr;
                if (is_b_cond_to(
                        &instructions[6], instructions[6], 1u,
                        &instructions[10]) &&
                    is_b_to(
                        &instructions[9], instructions[9], &first_bypass) &&
                    is_b_cond_to(
                        &instructions[13], instructions[13], 1u,
                        &instructions[17]) &&
                    is_b_to(
                        &instructions[16], instructions[16], &second_bypass) &&
                    first_bypass == second_bypass &&
                    first_bypass > &instructions[17] &&
                    decode_gate_kind(instructions[17], value_reg, &kind)) {
                    append_supplemental_gate(
                        &sites, &instructions[17], kind, dominant_slot, image);
                }
            }

            // Fwn is passed to a local boolean helper together with two values;
            // the following branch consumes that helper's result in w0.
            if (segment_contains(segment, instructions, 6) &&
                is_ldur_x_from_fp(instructions[2], 1u) &&
                is_ldur_x_from_fp(instructions[3], 2u) &&
                is_bl(instructions[4]) &&
                decode_gate_kind(instructions[5], 0u, &kind)) {
                append_supplemental_gate(
                    &sites, &instructions[5], kind, dominant_slot, image);
            }

            // A true Fwn value skips a secondary helper; the false path tests
            // its result. Both paths converge immediately after this gate.
            if (segment_contains(segment, instructions, 18)) {
                const uint32_t true_reg = instructions[2] & 0x1Fu;
                if (is_add_x_reg_x22_imm(
                        instructions[2], true_reg, kDartTrueOffset) &&
                    is_cmp_w_regs(instructions[3], value_reg, true_reg) &&
                    is_b_cond_to(
                        &instructions[4], instructions[4], 0u,
                        &instructions[17]) &&
                    is_bl(instructions[15]) &&
                    decode_gate_kind(instructions[16], 0u, &kind)) {
                    append_supplemental_gate(
                        &sites, &instructions[16], kind, dominant_slot, image);
                }
            }

            // The Fwn value is the x2 argument to a nearby leaf helper. Patch
            // the helper's x2 test, not the adjacent x5 test from the old
            // hardcoded table.
            if (segment_contains(segment, instructions, 7) &&
                is_ldur_x_from_fp(instructions[2], 1u) &&
                is_ldur_x_from_fp(instructions[3], 3u) &&
                is_ldur_x_from_fp(instructions[4], 5u) &&
                is_ldur_x_from_fp(instructions[5], 6u)) {
                uint32_t *callee = nullptr;
                if (is_bl_to(&instructions[6], instructions[6], &callee) &&
                    segment_contains(segment, callee, 2) &&
                    decode_gate_kind(callee[0], 5u, &kind) &&
                    decode_gate_kind(callee[1], value_reg, &kind)) {
                    append_supplemental_gate(
                        &sites, &callee[1], kind, dominant_slot, image);
                }
            }
        }
    }
    return sites;
}

int apply_license_publish_patches(const LicensePublishSite &site) {
    const uint32_t true_value =
        replace_add_imm12(*site.false_value, kDartTrueOffset);

    if (!patch_instruction(site.branch, kNop)) {
        return -4;
    }
    if (!patch_instruction(site.false_value, true_value)) {
        // Roll back the first write on failure.
        if (!g_patches.empty()) {
            const Patch first = g_patches.back();
            if (set_page_permissions(
                    first.addr,
                    sizeof(*first.addr),
                    PROT_READ | PROT_WRITE | PROT_EXEC)) {
                *first.addr = first.original;
                __builtin___clear_cache(
                    reinterpret_cast<char *>(first.addr),
                    reinterpret_cast<char *>(first.addr) + sizeof(*first.addr));
                set_page_permissions(
                    first.addr, sizeof(*first.addr), PROT_READ | PROT_EXEC);
            }
            g_patches.pop_back();
        }
        return -5;
    }
    g_license_publish_rva = site.rva;
    g_license_patches.store(2);
    LOGI(
        "license publisher forced true rva=0x%zx patches=2",
        static_cast<size_t>(site.rva));
    return 0;
}

// Patch only gates anchored on `dominant_slot` (the CZc.Fwn cluster). Gates on
// other slots / kNoSlot are unrelated bool checks and MUST be left alone, or the
// app's core screens break.
int apply_gate_patches(
    const std::vector<GateSite> &gates, uint32_t dominant_slot) {
    int tbz_ok = 0;
    int tbnz_ok = 0;
    int supplemental_ok = 0;
    int fail = 0;
    int skipped = 0;

    for (const GateSite &gate : gates) {
        if (gate.slot != dominant_slot) {
            ++skipped;
            continue;
        }
        if (gate.kind == GateKind::kTbz) {
            uint32_t patched = 0;
            if (!tbz_to_unconditional_b(*gate.branch, &patched)) {
                ++fail;
                continue;
            }
            if (patch_instruction(gate.branch, patched)) {
                ++tbz_ok;
                if (gate.supplemental) {
                    ++supplemental_ok;
                }
            } else {
                ++fail;
            }
        } else {
            if (patch_instruction(gate.branch, kNop)) {
                ++tbnz_ok;
                if (gate.supplemental) {
                    ++supplemental_ok;
                }
            } else {
                ++fail;
            }
        }
    }

    g_gate_tbz.store(tbz_ok);
    g_gate_tbnz.store(tbnz_ok);
    g_gate_supplemental.store(supplemental_ok);
    LOGI(
        "feature gates patched tbz=%d tbnz=%d supplemental=%d failed=%d skipped=%d "
        "candidates=%zu dominant_slot=0x%x",
        tbz_ok,
        tbnz_ok,
        supplemental_ok,
        fail,
        skipped,
        gates.size(),
        dominant_slot);
    return tbz_ok + tbnz_ok;
}

int do_install_locked() {
    if (g_installed.load()) {
        return 0;
    }

    ImageInfo image;
    if (!find_libapp(&image)) {
        LOGW("libapp.so not loaded yet");
        return -1;
    }

    g_libapp_base = image.base;
    g_libapp_size = image.image_size;
    LOGI(
        "libapp base=%p size=0x%zx executableSegments=%zu mode=%s",
        image.base,
        image.image_size,
        image.executable_segments.size(),
        kMode);

    // --- Phase 1: license publication (best-effort unique hit) ---
    const std::vector<LicensePublishSite> license_sites =
        scan_license_publish_sites(image);
    int license_rc = 0;
    if (license_sites.empty()) {
        LOGW("license publish pattern not found; continuing with gate scan only");
        license_rc = 1;
    } else if (license_sites.size() != 1) {
        LOGW(
            "license publish pattern ambiguous matches=%zu; skipping license patches",
            license_sites.size());
        for (const LicensePublishSite &site : license_sites) {
            LOGW("license candidate rva=0x%zx", static_cast<size_t>(site.rva));
        }
        license_rc = 2;
    } else {
        const int rc = apply_license_publish_patches(license_sites.front());
        if (rc != 0) {
            LOGE("license publish patch failed code=%d", rc);
            license_rc = rc;
        }
    }

    // --- Phase 2: feature-gate pattern scan (functional unlock) ---
    std::vector<GateSite> gates = scan_feature_gates(image);
    const uint32_t dominant_slot = dominant_gate_slot(gates);
    if (gates.empty() || dominant_slot == kNoSlot) {
        LOGE(
            "feature gate cluster not found (gates=%zu dominant=0x%x)",
            gates.size(),
            dominant_slot);
        if (g_patches.empty()) {
            return -6;
        }
        // License patches alone may still help if Kwn runs later.
        g_patch_count.store(static_cast<int>(g_patches.size()));
        g_installed.store(true);
        return 3;
    }

    const std::vector<GateSite> supplemental =
        scan_supplemental_feature_gates(image, dominant_slot);
    gates.insert(gates.end(), supplemental.begin(), supplemental.end());
    LOGI(
        "feature gate scan direct_candidates=%zu supplemental=%zu",
        gates.size() - supplemental.size(),
        supplemental.size());

    const int gate_ok = apply_gate_patches(gates, dominant_slot);
    if (gate_ok == 0 && g_patches.empty()) {
        LOGE("no patches applied");
        return -7;
    }

    g_patch_count.store(static_cast<int>(g_patches.size()));
    g_installed.store(true);
    LOGI(
        "install done mode=%s total_patches=%d license_rc=%d "
        "gates=%d license_site=0x%zx",
        kMode,
        g_patch_count.load(),
        license_rc,
        gate_ok,
        static_cast<size_t>(g_license_publish_rva));
    // 0 = full success. 1 = functional fallback success with a soft miss.
    return (license_rc == 0 && gate_ok > 0) ? 0 : 1;
}

void do_uninstall_locked() {
    for (auto it = g_patches.rbegin(); it != g_patches.rend(); ++it) {
        const Patch &patch = *it;
        if (!set_page_permissions(
                patch.addr,
                sizeof(*patch.addr),
                PROT_READ | PROT_WRITE | PROT_EXEC)) {
            continue;
        }
        *patch.addr = patch.original;
        __builtin___clear_cache(
            reinterpret_cast<char *>(patch.addr),
            reinterpret_cast<char *>(patch.addr) + sizeof(*patch.addr));
        set_page_permissions(patch.addr, sizeof(*patch.addr), PROT_READ | PROT_EXEC);
    }
    g_patches.clear();
    g_patch_count.store(0);
    g_gate_tbz.store(0);
    g_gate_tbnz.store(0);
    g_gate_supplemental.store(0);
    g_license_patches.store(0);
    g_license_publish_rva = 0;
    g_installed.store(false);
    LOGI("uninstalled and restored patches");
}

void set_native_log_path(JNIEnv *env, jstring value, size_t index) {
    if (index >= kNativeLogPathCount) {
        return;
    }
    const char *chars = nullptr;
    if (value != nullptr) {
        chars = env->GetStringUTFChars(value, nullptr);
    }

    {
        std::lock_guard<std::mutex> lock(g_native_log_mu);
        if (chars != nullptr && chars[0] != '\0') {
            snprintf(g_native_log_paths[index], kNativeLogPathMax, "%s", chars);
        } else {
            g_native_log_paths[index][0] = '\0';
        }
    }

    if (chars != nullptr) {
        env->ReleaseStringUTFChars(value, chars);
    }
}

void native_log_paths_snapshot(char *primary, size_t primary_size, char *mirror, size_t mirror_size) {
    std::lock_guard<std::mutex> lock(g_native_log_mu);
    snprintf(primary, primary_size, "%s", g_native_log_paths[0]);
    snprintf(mirror, mirror_size, "%s", g_native_log_paths[1]);
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
    g_enabled.store(enabled == JNI_TRUE);
    LOGI("enabled=%d mode=%s", enabled == JNI_TRUE, kMode);
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
    char buf[448];
    snprintf(
        buf,
        sizeof(buf),
        "mode=%s installed=%d enabled=%d base=%p size=0x%zx "
        "license_site=0x%zx license_patches=%d "
        "gates_tbz=%d gates_tbnz=%d gates_supplemental=%d patches=%d",
        kMode,
        g_installed.load() ? 1 : 0,
        g_enabled.load() ? 1 : 0,
        g_libapp_base,
        g_libapp_size,
        static_cast<size_t>(g_license_publish_rva),
        g_license_patches.load(),
        g_gate_tbz.load(),
        g_gate_tbnz.load(),
        g_gate_supplemental.load(),
        g_patch_count.load());
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT void JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativeNetworkGuard_nativeSetFileLogPaths(
    JNIEnv *env,
    jclass,
    jstring private_path,
    jstring external_path) {
    set_native_log_path(env, private_path, 0);
    set_native_log_path(env, external_path, 1);

    char primary[kNativeLogPathMax] {};
    char mirror[kNativeLogPathMax] {};
    native_log_paths_snapshot(primary, sizeof(primary), mirror, sizeof(mirror));
    LOGI(
        "network guard file logging configured private=%s external=%s",
        primary[0] != '\0' ? primary : "n/a",
        mirror[0] != '\0' ? mirror : "n/a");
}

extern "C" JNIEXPORT jint JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativeNetworkGuard_nativeInstall(
    JNIEnv *,
    jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
    return install_network_guard_locked();
}

extern "C" JNIEXPORT void JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativeNetworkGuard_nativeSetEnabled(
    JNIEnv *,
    jclass,
    jboolean enabled) {
    g_network_guard_enabled.store(enabled == JNI_TRUE);
    LOGI(
        "network guard enabled=%d installed=%d hits=%d",
        enabled == JNI_TRUE,
        g_network_guard_installed.load() ? 1 : 0,
        g_network_guard_hits.load());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativeNetworkGuard_nativeIsInstalled(
    JNIEnv *,
    jclass) {
    return g_network_guard_installed.load() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xiyunmn_reedenhook_feature_premium_NativeNetworkGuard_nativeStatus(
    JNIEnv *env,
    jclass) {
    char buf[320];
    snprintf(
        buf,
        sizeof(buf),
        "mode=flutter_getaddrinfo_block installed=%d enabled=%d attempts=%d "
        "hits=%d slot=%p real=%p",
        g_network_guard_installed.load() ? 1 : 0,
        g_network_guard_enabled.load() ? 1 : 0,
        g_network_guard_attempts.load(),
        g_network_guard_hits.load(),
        g_getaddrinfo_slot,
        reinterpret_cast<void *>(g_real_getaddrinfo));
    return env->NewStringUTF(buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    LOGI("JNI_OnLoad reeden_unlock v0.5.2 network guard with AOT fallback available");
    return JNI_VERSION_1_6;
}
