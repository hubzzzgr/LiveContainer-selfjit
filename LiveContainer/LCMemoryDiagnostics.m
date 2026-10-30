#import "LCMemoryDiagnostics.h"
#import <CommonCrypto/CommonDigest.h>
#import <TargetConditionals.h>
#import <dlfcn.h>
#import <mach-o/loader.h>
#import <mach/machine.h>
#import <string.h>
#if TARGET_OS_IOS
#import <os/proc.h>
#endif

static NSString * const MemoryEntitlement = @"com.apple.developer.kernel.increased-memory-limit";
typedef NS_ENUM(NSInteger, MemoryValue) {
    MemoryUnknown = -1, MemoryAbsent = 0, MemoryPresent = 1, MemoryInvalid = 2
};

// Only actual plist booleans count. NSNumber(1) and the string "true" are not entitlements.
static MemoryValue MemoryBoolean(id value) {
    if (!value) return MemoryAbsent;
    if (CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID()) return MemoryInvalid;
    return [value boolValue] ? MemoryPresent : MemoryAbsent;
}

static NSString *MemoryValueText(MemoryValue value) {
    switch (value) {
        case MemoryPresent: return @"Present (true)";
        case MemoryAbsent: return @"Absent or false";
        case MemoryInvalid: return @"Invalid entitlement value";
        default: return @"Unable to Verify";
    }
}

static NSString *MemoryStatus(MemoryValue entitlement, MemoryValue validated, BOOL changed) {
    if (changed) return @"Restart Required";
    if (entitlement == MemoryAbsent) return @"Not Enabled";
    if (entitlement == MemoryPresent && validated == MemoryPresent) return @"Enabled";
    return @"Unable to Verify";
}

typedef CFTypeRef (*MemoryCreateTask)(CFAllocatorRef);
typedef CFTypeRef (*MemoryCopyEntitlement)(CFTypeRef, CFStringRef, CFErrorRef *);
typedef Boolean (*MemoryValidateTask)(CFTypeRef);
typedef void *(*MemoryResolver)(const char *);

static void *MemorySymbol(const char *name) { return dlsym(RTLD_DEFAULT, name); }

// SecTask is public on macOS, SPI on iOS (as in the existing host entitlement code).
// Resolve all entry points optionally: no new mandatory/private symbol linkage.
// CopyValue alone reads a signature; EntitlementsValidated supplies separate OS validation evidence.
static NSDictionary *MemoryProcessEvidence(MemoryResolver resolve) {
    MemoryCreateTask create = (MemoryCreateTask)resolve("SecTaskCreateFromSelf");
    MemoryCopyEntitlement copy = (MemoryCopyEntitlement)resolve("SecTaskCopyValueForEntitlement");
    MemoryValidateTask validate = (MemoryValidateTask)resolve("SecTaskEntitlementsValidated");
    MemoryValue entitlement = MemoryUnknown, validated = MemoryUnknown;
    NSString *detail = @"Runtime entitlement inspection is unavailable on this OS.";
    CFTypeRef task = create && copy ? create(NULL) : NULL;
    if (task) {
        CFErrorRef error = NULL;
        CFTypeRef value = copy(task, (__bridge CFStringRef)MemoryEntitlement, &error);
        if (error) {
            detail = [NSString stringWithFormat:@"Runtime inspection failed: %@", (__bridge NSError *)error];
        } else {
            entitlement = MemoryBoolean((__bridge id)value);
            if (validate && validate(task)) validated = MemoryPresent;
            detail = validated == MemoryPresent
                ? @"The running task's code-signing entitlements are validated by iOS. This does not measure a memory increase."
                : @"iOS entitlement validation could not be confirmed. Signature presence alone is insufficient.";
        }
        if (value) CFRelease(value);
        if (error) CFRelease(error);
        CFRelease(task);
    }
    return @{@"entitlement": @(entitlement), @"validated": @(validated), @"detail": detail};
}

static BOOL MemoryRange(NSUInteger offset, NSUInteger length, NSUInteger total) {
    return offset <= total && length <= total - offset;
}

static uint32_t MemoryBE32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t MemoryBE64(const uint8_t *p) {
    return ((uint64_t)MemoryBE32(p) << 32) | MemoryBE32(p + 4);
}

// Bounds-checked arm64 Mach-O reader. Does not validate cryptographic signatures.
// DER-only entitlements remain unknown; the runtime SecTask query can still read them.
static NSDictionary *MemorySignature(NSData *file) {
    NSDictionary *unknown = @{@"value": @(MemoryUnknown), @"detail": @"Installed signature could not be read (unsupported or malformed Mach-O)."};
    if (file.length < sizeof(struct mach_header_64)) return unknown;
    const uint8_t *bytes = file.bytes;
    NSUInteger base = 0, sliceSize = file.length;
    uint32_t magic = MemoryBE32(bytes);
    if (magic == 0xcafebabe || magic == 0xcafebabf) {
        NSUInteger stride = magic == 0xcafebabf ? 32 : 20;
        uint32_t count = MemoryBE32(bytes + 4);
        if (count > (file.length - 8) / stride) return unknown;
        BOOL found = NO;
        for (uint32_t i = 0; i < count; i++) {
            const uint8_t *arch = bytes + 8 + i * stride;
            if (MemoryBE32(arch) != CPU_TYPE_ARM64) continue;
            // Prefer the generic arm64 slice used by these targets; never guess between subtypes.
            if ((MemoryBE32(arch + 4) & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64_ALL) continue;
            uint64_t offset = stride == 32 ? MemoryBE64(arch + 8) : MemoryBE32(arch + 8);
            uint64_t size = stride == 32 ? MemoryBE64(arch + 16) : MemoryBE32(arch + 12);
            if (offset > file.length || size > file.length - offset) return unknown;
            base = (NSUInteger)offset; sliceSize = (NSUInteger)size; found = YES; break;
        }
        if (!found) return unknown;
    }
    if (sliceSize < sizeof(struct mach_header_64)) return unknown;
    struct mach_header_64 header;
    memcpy(&header, bytes + base, sizeof(header));
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        !MemoryRange(sizeof(header), header.sizeofcmds, sliceSize)) return unknown;
    NSUInteger cursor = sizeof(header), end = cursor + header.sizeofcmds;
    NSData *signature = nil;
    for (uint32_t i = 0; i < header.ncmds; i++) {
        if (!MemoryRange(cursor, sizeof(struct load_command), end)) return unknown;
        struct load_command command;
        memcpy(&command, bytes + base + cursor, sizeof(command));
        if (command.cmdsize < sizeof(command) || !MemoryRange(cursor, command.cmdsize, end)) return unknown;
        if (command.cmd == LC_CODE_SIGNATURE) {
            if (signature || command.cmdsize < sizeof(struct linkedit_data_command)) return unknown;
            struct linkedit_data_command linkedit;
            memcpy(&linkedit, bytes + base + cursor, sizeof(linkedit));
            if (!MemoryRange(linkedit.dataoff, linkedit.datasize, sliceSize)) return unknown;
            signature = [file subdataWithRange:NSMakeRange(base + linkedit.dataoff, linkedit.datasize)];
        }
        cursor += command.cmdsize;
    }
    if (cursor != end) return unknown;
    if (!signature) return @{@"value": @(MemoryAbsent), @"detail": @"Executable has no embedded signature.", @"signature": NSData.data};
    if (signature.length < 12) return unknown;
    const uint8_t *blob = signature.bytes;
    uint32_t length = MemoryBE32(blob + 4), count = MemoryBE32(blob + 8);
    if (MemoryBE32(blob) != 0xfade0cc0 || length < 12 || length > signature.length || count > (length - 12) / 8) return unknown;
    NSDictionary *entitlements = nil;
    BOOL hasDER = NO;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t type = MemoryBE32(blob + 12 + i * 8), offset = MemoryBE32(blob + 16 + i * 8);
        if (offset < 12 + count * 8 || !MemoryRange(offset, 8, length)) return unknown;
        uint32_t size = MemoryBE32(blob + offset + 4);
        if (size < 8 || !MemoryRange(offset, size, length)) return unknown;
        if (type == 7) hasDER = YES;
        if (type != 5) continue;
        if (entitlements || MemoryBE32(blob + offset) != 0xfade7171) return unknown;
        NSData *xml = [signature subdataWithRange:NSMakeRange(offset + 8, size - 8)];
        id plist = [NSPropertyListSerialization propertyListWithData:xml options:NSPropertyListImmutable format:NULL error:NULL];
        if (![plist isKindOfClass:NSDictionary.class]) return unknown;
        entitlements = plist;
    }
    MemoryValue value = entitlements ? MemoryBoolean(entitlements[MemoryEntitlement]) : (hasDER ? MemoryUnknown : MemoryAbsent);
    return @{@"value": @(value), @"detail": !entitlements && hasDER ? @"Installed signature uses DER-only entitlements; use the running-process result." : @"Read from the installed executable; cryptographic validity is established separately by iOS.",
             @"signature": signature, @"entitlements": entitlements ?: @{}};
}

// A provisioning profile is CMS-wrapped XML. Extract only for advisory diagnostics.
// Parsing its payload does NOT authenticate the CMS, certificate, device or installation.
static NSDictionary *MemoryProfile(NSData *data) {
    if (!data.length || data.length > 4 * 1024 * 1024) return nil;
    NSData *start = [@"<plist" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *finish = [@"</plist>" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange first = [data rangeOfData:start options:0 range:NSMakeRange(0, data.length)];
    if (first.location == NSNotFound) return nil;
    NSRange last = [data rangeOfData:finish options:0 range:NSMakeRange(first.location, data.length - first.location)];
    if (last.location == NSNotFound) return nil;
    NSData *xml = [data subdataWithRange:NSMakeRange(first.location, NSMaxRange(last) - first.location)];
    id profile = [NSPropertyListSerialization propertyListWithData:xml options:NSPropertyListImmutable format:NULL error:NULL];
    return [profile isKindOfClass:NSDictionary.class] ? profile : nil;
}

static NSDictionary *MemoryProfileEvidence(NSDictionary *profile, NSDictionary *signedEntitlements, NSDate *now) {
    NSMutableArray *issues = [NSMutableArray array];
    id entitlements = profile[@"Entitlements"];
    if (![entitlements isKindOfClass:NSDictionary.class]) {
        return @{@"summary": @"Unable to Verify", @"issues": @[@"No readable embedded provisioning profile. The signing certificate and profile cannot be checked locally."]};
    }
    MemoryValue value = MemoryBoolean(entitlements[MemoryEntitlement]);
    if (value != MemoryPresent) [issues addObject:@"The embedded profile does not allow a true Increased Memory Limit entitlement. Enable the capability for this host's App ID, regenerate the profile, then re-sign and reinstall."];
    id expiration = profile[@"ExpirationDate"];
    if (![expiration isKindOfClass:NSDate.class]) {
        [issues addObject:@"The provisioning profile has no valid expiration date."];
    } else if ([expiration compare:now] != NSOrderedDescending) {
        [issues addObject:@"The provisioning profile has expired. Renew it and reinstall the signed app."];
    }
    id creation = profile[@"CreationDate"];
    if ([creation isKindOfClass:NSDate.class] && [creation compare:now] == NSOrderedDescending)
        [issues addObject:@"The profile is not yet valid. Check the device date and signing profile."];
    id allowedID = entitlements[@"application-identifier"], signedID = signedEntitlements[@"application-identifier"];
    if ([allowedID isKindOfClass:NSString.class] && [signedID isKindOfClass:NSString.class]) {
        BOOL matches = [allowedID isEqual:signedID];
        if ([allowedID hasSuffix:@".*"]) matches = [signedID hasPrefix:[allowedID substringToIndex:[allowedID length] - 1]];
        if (!matches) [issues addObject:@"The installed signature's application identifier does not match the embedded profile."];
    } else {
        [issues addObject:@"The profile or readable signature is missing an application identifier. Their signing compatibility could not be verified."];
    }
    id allowedTeam = entitlements[@"com.apple.developer.team-identifier"], signedTeam = signedEntitlements[@"com.apple.developer.team-identifier"];
    if (![allowedTeam isKindOfClass:NSString.class] || ![signedTeam isKindOfClass:NSString.class])
        [issues addObject:@"The profile or readable signature is missing a team identifier. Their signing compatibility could not be verified."];
    else if (![allowedTeam isEqual:signedTeam])
        [issues addObject:@"The installed signature's team identifier does not match the embedded profile."];
    return @{@"summary": value == MemoryPresent ? @"Allows request (payload only)" : MemoryValueText(value), @"issues": issues};
}

static NSData *MemoryFingerprint(NSData *signature, NSData *profile) {
    if (!signature) return nil;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    CC_SHA256_Update(&context, signature.bytes, (CC_LONG)signature.length);
    // Hash profile separately so missing/readable transitions are also detected.
    unsigned char profileHash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(profile.bytes, (CC_LONG)profile.length, profileHash);
    CC_SHA256_Update(&context, profileHash, sizeof(profileHash));
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    return [NSData dataWithBytes:digest length:sizeof(digest)];
}

static NSDictionary *MemoryInstalledEvidence(NSBundle *bundle) {
    NSData *file = bundle.executableURL ? [NSData dataWithContentsOfURL:bundle.executableURL options:NSDataReadingMappedIfSafe error:NULL] : nil;
    NSDictionary *signature = MemorySignature(file);
    NSURL *profileURL = [bundle.bundleURL URLByAppendingPathComponent:@"embedded.mobileprovision"];
    NSError *profileError = nil;
    NSData *profileData = [NSData dataWithContentsOfURL:profileURL options:NSDataReadingMappedIfSafe error:&profileError];
    NSDictionary *profile = MemoryProfileEvidence(MemoryProfile(profileData), signature[@"entitlements"], NSDate.date);
    NSMutableDictionary *evidence = [@{@"signature": signature, @"profile": profile} mutableCopy];
    BOOL profileReadable = !profileError || ([profileError.domain isEqual:NSCocoaErrorDomain] &&
        (profileError.code == NSFileReadNoSuchFileError || profileError.code == NSFileNoSuchFileError));
    NSData *fingerprint = profileReadable ? MemoryFingerprint(signature[@"signature"], profileData) : nil;
    if (fingerprint) evidence[@"fingerprint"] = fingerprint;
    return evidence;
}

static NSBundle *memoryHostBundle;
static NSData *memoryLaunchFingerprint;

@implementation LCMemoryDiagnostics
+ (void)captureLaunchConfiguration:(NSBundle *)hostBundle {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        memoryHostBundle = hostBundle;
        memoryLaunchFingerprint = MemoryInstalledEvidence(hostBundle)[@"fingerprint"];
    });
}

+ (NSDictionary<NSString *, id> *)snapshot {
    NSBundle *host = memoryHostBundle ?: NSBundle.mainBundle;
    NSDictionary *installed = MemoryInstalledEvidence(host);
    NSDictionary *process;
#if TARGET_OS_SIMULATOR || !TARGET_OS_IOS || TARGET_OS_MACCATALYST
    process = @{@"entitlement": @(MemoryUnknown), @"validated": @(MemoryUnknown), @"detail": @"Verify on a physical iPhone or iPad. This environment cannot establish the iOS entitlement grant."};
#else
    process = MemoryProcessEvidence(MemorySymbol);
#endif
    NSData *current = installed[@"fingerprint"];
    BOOL changed = memoryLaunchFingerprint && current && ![memoryLaunchFingerprint isEqual:current];
    MemoryValue entitlement = [process[@"entitlement"] integerValue];
    MemoryValue validated = [process[@"validated"] integerValue];
    NSMutableArray *issues = [installed[@"profile"][@"issues"] mutableCopy];
    if ([installed[@"signature"][@"value"] integerValue] != MemoryPresent)
        [issues addObject:@"The installed host signature does not confirm the requested entitlement. SideStore/AltStore or another signer must preserve it in the final IPA."];
    if (entitlement == MemoryAbsent)
        [issues addObject:@"The running host has no true Increased Memory Limit entitlement. Changing a guest's settings or importing a guest-signing certificate cannot enable it."];
    if (changed) [issues addObject:@"The installed signature or provisioning profile has changed since this process started. Fully close LiveContainer and its guest processes, then relaunch and refresh."];
    NSString *headroom = @"Unavailable";
#if TARGET_OS_IOS && !TARGET_OS_SIMULATOR && !TARGET_OS_MACCATALYST
    size_t bytes = os_proc_available_memory();
    headroom = bytes ? [NSByteCountFormatter stringFromByteCount:(int64_t)bytes countStyle:NSByteCountFormatterCountStyleMemory] : @"Unavailable (system returned zero)";
#endif
    NSMutableDictionary *result = [@{
        @"status": MemoryStatus(entitlement, validated, changed),
        @"host": host.bundleIdentifier ?: @"Unknown host",
        @"buildRequest": MemoryBoolean(host.infoDictionary[@"LCIncreasedMemoryLimitRequested"]) == MemoryPresent ? @"Requested" : @"Not declared",
        @"runningSignature": MemoryValueText(entitlement),
        @"grant": entitlement == MemoryAbsent ? @"Not granted" : (entitlement == MemoryPresent && validated == MemoryPresent ? @"Verified for running process" : @"Unable to Verify"),
        @"installedSignature": MemoryValueText([installed[@"signature"][@"value"] integerValue]),
        @"signatureDetail": installed[@"signature"][@"detail"],
        @"profile": installed[@"profile"][@"summary"],
        @"runtimeDetail": process[@"detail"],
        @"headroom": headroom,
        @"issues": issues,
        @"checkedAt": NSDate.date
    } mutableCopy];
    NSBundle *liveProcess = [NSBundle bundleWithURL:[host.bundleURL URLByAppendingPathComponent:@"PlugIns/LiveProcess.appex"]];
    if (liveProcess) {
        NSDictionary *extension = MemoryInstalledEvidence(liveProcess);
        result[@"liveProcessSignature"] = MemoryValueText([extension[@"signature"][@"value"] integerValue]);
        result[@"liveProcessProfile"] = extension[@"profile"][@"summary"];
        result[@"liveProcessIssues"] = extension[@"profile"][@"issues"];
    }
    return result;
}
@end
