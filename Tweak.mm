#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/ptrace.h>
#import <objc/runtime.h>
#import <string.h>
#import "fishhook.h"

// ─────────────────────────────────────────────────────────────────────
// Identity constants — make the game look like the official build
// ─────────────────────────────────────────────────────────────────────

static const char *kBundleID      = "com.activision.callofduty.shooter";
static const char *kTeamID        = "6KZFBJ4CBY";
static const char *kAppID         = "6KZFBJ4CBY.com.activision.callofduty.shooter";
static const char *kAppPrefix     = "6KZFBJ4CBY.";
static const char *kKeychainWild  = "6KZFBJ4CBY.*";
static const char *kAppGroup      = "group.com.activision.callofduty.shooter";
static const char *kCertSubject   = "Apple Distribution: Activision Publishing, Inc. (6KZFBJ4CBY)";
static const char *kAnoVersion    = "7.7.58.42114";

// ─────────────────────────────────────────────────────────────────────
// Hidden-image classifier — any image path containing these is hidden
// ─────────────────────────────────────────────────────────────────────

static const char *kHiddenNeedles[] = {
    "bypass", "cheat", "hack", "inject",
    "substrate", "substitute", "frida",
    "cynject", "libhooker",
};
static const size_t kHiddenNeedleCount =
    sizeof(kHiddenNeedles) / sizeof(kHiddenNeedles[0]);

static BOOL shouldHideImage(const char *path) {
    if (!path) return NO;
    for (size_t i = 0; i < kHiddenNeedleCount; i++) {
        if (strstr(path, kHiddenNeedles[i]) != NULL) return YES;
    }
    return NO;
}

// ─────────────────────────────────────────────────────────────────────
// 1. dyld virtualization
// ─────────────────────────────────────────────────────────────────────

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);

static uint32_t hook_dyld_image_count(void) {
    if (!orig_dyld_image_count) return 0;
    uint32_t n = orig_dyld_image_count();
    if (!orig_dyld_get_image_name) return n;
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (shouldHideImage(orig_dyld_get_image_name(i))) hidden++;
    }
    return n - hidden;
}

// Maps filtered index → real index, returns UINT32_MAX if out of range.
static uint32_t filtered_to_real(uint32_t filtered) {
    if (!orig_dyld_image_count || !orig_dyld_get_image_name) return UINT32_MAX;
    uint32_t n = orig_dyld_image_count();
    uint32_t visible = 0;
    for (uint32_t real = 0; real < n; real++) {
        if (shouldHideImage(orig_dyld_get_image_name(real))) continue;
        if (visible == filtered) return real;
        visible++;
    }
    return UINT32_MAX;
}

static const char *hook_dyld_get_image_name(uint32_t idx) {
    uint32_t real = filtered_to_real(idx);
    if (real == UINT32_MAX) return NULL;
    return orig_dyld_get_image_name(real);
}

static const struct mach_header *hook_dyld_get_image_header(uint32_t idx) {
    uint32_t real = filtered_to_real(idx);
    if (real == UINT32_MAX) return NULL;
    return orig_dyld_get_image_header(real);
}

static intptr_t hook_dyld_get_image_vmaddr_slide(uint32_t idx) {
    uint32_t real = filtered_to_real(idx);
    if (real == UINT32_MAX) return 0;
    return orig_dyld_get_image_vmaddr_slide(real);
}

// ─────────────────────────────────────────────────────────────────────
// 2. dladdr path spoof
// ─────────────────────────────────────────────────────────────────────

struct dl_info_s {
    const char *dli_fname;
    void       *dli_fbase;
    const char *dli_sname;
    void       *dli_saddr;
};

typedef int (*dladdr_fn)(const void *, struct dl_info_s *);
static dladdr_fn orig_dladdr;

static int hook_dladdr(const void *addr, struct dl_info_s *info) {
    if (!orig_dladdr) return 0;
    int ok = orig_dladdr(addr, info);
    if (ok && info && info->dli_fname && shouldHideImage(info->dli_fname)) {
        info->dli_fname = "/usr/lib/system/libsystem_c.dylib";
        info->dli_sname = NULL;
    }
    return ok;
}

// ─────────────────────────────────────────────────────────────────────
// 3. __LINKEDIT spoofing
// ─────────────────────────────────────────────────────────────────────

#define FAKE_LINKEDIT_SIZE 0x7ED160ULL

typedef void *(*getsegbyname_fn)(const char *);
typedef void *(*getsegmentdata_fn)(const void *, const char *, unsigned long *);

static getsegbyname_fn orig_getsegbyname;
static getsegmentdata_fn orig_getsegmentdata;

static void *hook_getsegbyname(const char *seg) {
    if (!orig_getsegbyname) return NULL;
    void *ret = orig_getsegbyname(seg);
    if (ret && seg && strcmp(seg, "__LINKEDIT") == 0) {
        // Mutate the returned segment command in place.
        struct segment_command_64 *sc = (struct segment_command_64 *)ret;
        sc->vmsize = FAKE_LINKEDIT_SIZE;
        sc->filesize = FAKE_LINKEDIT_SIZE;
    }
    return ret;
}

static void *hook_getsegmentdata(const void *mh, const char *seg,
                                  unsigned long *size) {
    if (!orig_getsegmentdata) return NULL;
    void *ret = orig_getsegmentdata(mh, seg, size);
    if (ret && seg && strcmp(seg, "__LINKEDIT") == 0 && size) {
        *size = (unsigned long)FAKE_LINKEDIT_SIZE;
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────
// 4. Entitlement / code-sign spoofing (Security.framework)
// ─────────────────────────────────────────────────────────────────────

typedef CFTypeRef (*SecTaskCopyValueForEntitlement_fn)(void *, CFStringRef, CFErrorRef *);
typedef OSStatus (*SecCodeCheckValidity_fn)(void *, uint32_t, void *);
typedef OSStatus (*SecStaticCodeCheckValidity_fn)(void *, uint32_t, void *);
typedef CFStringRef (*SecCertificateCopySubjectSummary_fn)(void *);

static SecTaskCopyValueForEntitlement_fn orig_SecTaskCopyValueForEntitlement;
static SecCodeCheckValidity_fn orig_SecCodeCheckValidity;
static SecStaticCodeCheckValidity_fn orig_SecStaticCodeCheckValidity;
static SecCertificateCopySubjectSummary_fn orig_SecCertSubjSummary;

static CFStringRef cfstr(const char *s) {
    return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

static CFArrayRef arr2(const char *a, const char *b) {
    const void *vals[2] = { cfstr(a), cfstr(b) };
    return CFArrayCreate(NULL, vals, 2, &kCFTypeArrayCallBacks);
}

static CFArrayRef arr1(const char *a) {
    const void *vals[1] = { cfstr(a) };
    return CFArrayCreate(NULL, vals, 1, &kCFTypeArrayCallBacks);
}

static CFTypeRef hook_SecTaskCopyValueForEntitlement(void *task,
                                                      CFStringRef key,
                                                      CFErrorRef *err) {
    if (key) {
        const char *k = CFStringGetCStringPtr(key, kCFStringEncodingUTF8);
        if (!k) {
            char buf[256] = {0};
            CFStringGetCString(key, buf, sizeof(buf), kCFStringEncodingUTF8);
            k = buf;
        }
        if (k) {
            if (strcmp(k, "application-identifier") == 0)
                return cfstr(kAppID);
            if (strcmp(k, "com.apple.developer.team-identifier") == 0)
                return cfstr(kTeamID);
            if (strcmp(k, "aps-environment") == 0)
                return cfstr("production");
            if (strcmp(k, "keychain-access-groups") == 0)
                return arr2(kAppID, kKeychainWild);
            if (strcmp(k, "com.apple.security.application-groups") == 0)
                return arr1(kAppGroup);
            if (strcmp(k, "get-task-allow") == 0)
                return kCFBooleanFalse;
        }
    }
    if (orig_SecTaskCopyValueForEntitlement)
        return orig_SecTaskCopyValueForEntitlement(task, key, err);
    return NULL;
}

static OSStatus hook_SecCodeCheckValidity(void *code, uint32_t flags, void *err) {
    return errSecSuccess;
}

static OSStatus hook_SecStaticCodeCheckValidity(void *code, uint32_t flags, void *err) {
    return errSecSuccess;
}

static CFStringRef hook_SecCertSubjSummary(void *cert) {
    return cfstr(kCertSubject);
}

// ─────────────────────────────────────────────────────────────────────
// 5. Process / debug / env concealment
// ─────────────────────────────────────────────────────────────────────

typedef int (*sysctl_fn)(int *, unsigned int, void *, size_t *, void *, size_t);
typedef int (*sysctlbyname_fn)(const char *, void *, size_t *, void *, size_t);
typedef int (*ptrace_fn)(int, int, void *, int);
typedef char *(*getenv_fn)(const char *);

static sysctl_fn orig_sysctl;
static sysctlbyname_fn orig_sysctlbyname;
static ptrace_fn orig_ptrace;
static getenv_fn orig_getenv;

static int hook_sysctl(int *name, unsigned int namelen, void *oldp,
                       size_t *oldlenp, void *newp, size_t newlen) {
    if (name && namelen >= 2 && name[0] == 1 && name[1] == 14) {
        if (oldp && oldlenp && *oldlenp) memset(oldp, 0, *oldlenp);
        return 0;
    }
    if (orig_sysctl) return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    return -1;
}

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                              void *newp, size_t newlen) {
    if (name && (strstr(name, "kern.proc") || strstr(name, "proc_translated"))) {
        if (oldp && oldlenp && *oldlenp) memset(oldp, 0, *oldlenp);
        return 0;
    }
    if (orig_sysctlbyname)
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    return -1;
}

static int hook_ptrace(int request, int pid, void *addr, int data) {
    if (request == 0x1F) return 0;   // PT_DENY_ATTACH
    if (orig_ptrace) return orig_ptrace(request, pid, addr, data);
    return -1;
}

static char *hook_getenv(const char *name) {
    if (name && (strstr(name, "DYLD_") || strstr(name, "INSERT_LIBRARIES")))
        return NULL;
    return orig_getenv ? orig_getenv(name) : NULL;
}

// ─────────────────────────────────────────────────────────────────────
// 6. AnoSDKIoctl suppression — the direct ACE hook
// ─────────────────────────────────────────────────────────────────────

#define ANO_BLOCKED_MASK 0x0002C6000E040002ULL
// Bits set: 1, 18, 25, 26, 27, 41, 42, 46, 47, 49

typedef uintptr_t (*AnoSDKIoctl_fn)(uint32_t, uintptr_t, void *, size_t);
static AnoSDKIoctl_fn orig_AnoSDKIoctl;

static uintptr_t hook_AnoSDKIoctl(uint32_t req, uintptr_t a1,
                                   void *out, size_t outCap) {
    if (req <= 0x31) {
        if (ANO_BLOCKED_MASK & (1ULL << req)) return 0;
        if (req == 0x0E) {
            if (out && outCap >= 0x10)
                memcpy(out, kAnoVersion, strlen(kAnoVersion) + 1);
            return 0;
        }
    }
    if (orig_AnoSDKIoctl)
        return orig_AnoSDKIoctl(req, a1, out, outCap);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────
// 7. NSBundle identity swizzle
// ─────────────────────────────────────────────────────────────────────

@implementation NSBundle (RavenBypass)

- (NSString *)raven_bundleIdentifier {
    if (self == [NSBundle mainBundle]) return @(kBundleID);
    return [self raven_bundleIdentifier];
}

- (id)raven_objectForInfoDictionaryKey:(NSString *)key {
    if (self == [NSBundle mainBundle]) {
        if ([key isEqualToString:@"CFBundleIdentifier"])     return @(kBundleID);
        if ([key isEqualToString:@"AppIdentifierPrefix"])    return @(kAppPrefix);
        if ([key isEqualToString:@"application-identifier"]) return @(kAppID);
        if ([key isEqualToString:@"com.apple.developer.team-identifier"]) return @(kTeamID);
    }
    return [self raven_objectForInfoDictionaryKey:key];
}

- (NSDictionary *)raven_infoDictionary {
    NSDictionary *orig = [self raven_infoDictionary];
    if (self == [NSBundle mainBundle] && orig) {
        NSMutableDictionary *m = [orig mutableCopy];
        m[@"CFBundleIdentifier"] = @(kBundleID);
        m[@"AppIdentifierPrefix"] = @(kAppPrefix);
        m[@"application-identifier"] = @(kAppID);
        m[@"com.apple.developer.team-identifier"] = @(kTeamID);
        return [m copy];
    }
    return orig;
}

@end

static void installNSBundleSwizzles(void) {
    Class c = [NSBundle class];
    method_exchangeImplementations(
        class_getInstanceMethod(c, @selector(bundleIdentifier)),
        class_getInstanceMethod(c, @selector(raven_bundleIdentifier)));
    method_exchangeImplementations(
        class_getInstanceMethod(c, @selector(objectForInfoDictionaryKey:)),
        class_getInstanceMethod(c, @selector(raven_objectForInfoDictionaryKey:)));
    method_exchangeImplementations(
        class_getInstanceMethod(c, @selector(infoDictionary)),
        class_getInstanceMethod(c, @selector(raven_infoDictionary)));
}

// ─────────────────────────────────────────────────────────────────────
// Constructor — install everything at load
// ─────────────────────────────────────────────────────────────────────

__attribute__((constructor(101)))
static void raven_init(void) {
    NSLog(@"[RavenBypass] installing ANOGS/ACE bypass");

    // 1. fishhook rebindings
    struct rebinding rb[] = {
        { "_dyld_image_count",              (void *)hook_dyld_image_count,              (void **)&orig_dyld_image_count },
        { "_dyld_get_image_name",           (void *)hook_dyld_get_image_name,           (void **)&orig_dyld_get_image_name },
        { "_dyld_get_image_header",         (void *)hook_dyld_get_image_header,         (void **)&orig_dyld_get_image_header },
        { "_dyld_get_image_vmaddr_slide",   (void *)hook_dyld_get_image_vmaddr_slide,   (void **)&orig_dyld_get_image_vmaddr_slide },
        { "dladdr",                         (void *)hook_dladdr,                        (void **)&orig_dladdr },
        { "getsegbyname",                   (void *)hook_getsegbyname,                  (void **)&orig_getsegbyname },
        { "getsegmentdata",                 (void *)hook_getsegmentdata,                (void **)&orig_getsegmentdata },
        { "SecTaskCopyValueForEntitlement", (void *)hook_SecTaskCopyValueForEntitlement,(void **)&orig_SecTaskCopyValueForEntitlement },
        { "SecCodeCheckValidity",           (void *)hook_SecCodeCheckValidity,          (void **)&orig_SecCodeCheckValidity },
        { "SecStaticCodeCheckValidity",     (void *)hook_SecStaticCodeCheckValidity,    (void **)&orig_SecStaticCodeCheckValidity },
        { "SecCertificateCopySubjectSummary",(void *)hook_SecCertSubjSummary,           (void **)&orig_SecCertSubjSummary },
        { "sysctl",                         (void *)hook_sysctl,                        (void **)&orig_sysctl },
        { "sysctlbyname",                   (void *)hook_sysctlbyname,                  (void **)&orig_sysctlbyname },
        { "ptrace",                         (void *)hook_ptrace,                        (void **)&orig_ptrace },
        { "getenv",                         (void *)hook_getenv,                        (void **)&orig_getenv },
        { "AnoSDKIoctl",                    (void *)hook_AnoSDKIoctl,                   (void **)&orig_AnoSDKIoctl },
    };
    int n = sizeof(rb) / sizeof(rb[0]);
    int ret = rebind_symbols(rb, n);
    NSLog(@"[RavenBypass] rebind_symbols returned %d", ret);

    // 2. NSBundle swizzles
    installNSBundleSwizzles();

    // 3. Register add-image callback so future dylibs get filtered too
    _dyld_register_func_for_add_image(^(const struct mach_header *mh, intptr_t slide) {
        // Re-run rebinds against the newly-loaded image
        rebind_symbols(rb, n);
    });

    NSLog(@"[RavenBypass] bypass active");
}
