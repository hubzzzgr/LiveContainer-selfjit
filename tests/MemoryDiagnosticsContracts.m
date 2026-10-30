// Compile the actual implementation with mocked optional Security entry points.
// No iOS device or large allocations are needed. Run on macOS in CI.
#import "../LiveContainer/LCMemoryDiagnostics.m"
#import <libkern/OSByteOrder.h>

static void Expect(BOOL condition, NSString *message) {
    if (!condition) { fprintf(stderr, "%s\n", message.UTF8String); exit(1); }
}

static id mockValue;
static BOOL mockValidated, mockFailure, mockNoTask, mockNoValidator;
static CFTypeRef MockCreate(CFAllocatorRef allocator) { return mockNoTask ? NULL : CFRetain(CFSTR("test-task")); }
static CFTypeRef MockCopy(CFTypeRef task, CFStringRef key, CFErrorRef *error) {
    Expect(CFEqual(key, (__bridge CFStringRef)MemoryEntitlement), @"Wrong entitlement queried");
    if (mockFailure) *error = CFErrorCreate(NULL, kCFErrorDomainPOSIX, 1, NULL);
    return mockValue ? CFRetain((__bridge CFTypeRef)mockValue) : NULL;
}
static Boolean MockValidate(CFTypeRef task) { return mockValidated; }
static void *MockResolve(const char *name) {
    if (!strcmp(name, "SecTaskCreateFromSelf")) return (void *)MockCreate;
    if (!strcmp(name, "SecTaskCopyValueForEntitlement")) return (void *)MockCopy;
    if (!strcmp(name, "SecTaskEntitlementsValidated") && !mockNoValidator) return (void *)MockValidate;
    return NULL;
}
static void *Unavailable(const char *name) { return NULL; }
static NSString *MockStatus(void) {
    NSDictionary *evidence = MemoryProcessEvidence(MockResolve);
    return MemoryStatus([evidence[@"entitlement"] integerValue], [evidence[@"validated"] integerValue], NO);
}

static void AppendBE(NSMutableData *data, uint32_t value) {
    uint32_t big = OSSwapHostToBigInt32(value);
    [data appendBytes:&big length:4];
}

static NSData *Signature(NSDictionary *entitlements, BOOL derOnly) {
    NSData *xml = derOnly ? [NSData dataWithBytes:"\x30\x00" length:2] :
        [NSPropertyListSerialization dataWithPropertyList:entitlements format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    NSMutableData *blob = [NSMutableData data];
    AppendBE(blob, 0xfade0cc0); AppendBE(blob, (uint32_t)xml.length + 28); AppendBE(blob, 1);
    AppendBE(blob, derOnly ? 7 : 5); AppendBE(blob, 20);
    AppendBE(blob, derOnly ? 0xfade7172 : 0xfade7171); AppendBE(blob, (uint32_t)xml.length + 8);
    [blob appendData:xml];
    return blob;
}

static NSMutableData *Executable(NSData *signature) {
    struct mach_header_64 header = {0};
    header.magic = MH_MAGIC_64; header.cputype = CPU_TYPE_ARM64; header.filetype = MH_EXECUTE;
    header.ncmds = signature ? 1 : 0;
    header.sizeofcmds = signature ? sizeof(struct linkedit_data_command) : 0;
    NSMutableData *file = [NSMutableData dataWithBytes:&header length:sizeof(header)];
    if (signature) {
        struct linkedit_data_command command = {LC_CODE_SIGNATURE, sizeof(command), sizeof(header) + sizeof(command), (uint32_t)signature.length};
        [file appendBytes:&command length:sizeof(command)];
        [file appendData:signature];
    }
    return file;
}

int main(void) {
    @autoreleasepool {
        mockValue = @YES; mockValidated = YES;
        Expect([MockStatus() isEqual:@"Enabled"], @"Granted running entitlement was not recognized");
        mockValue = nil;
        Expect([MockStatus() isEqual:@"Not Enabled"], @"Missing running entitlement reported enabled");
        mockValue = @NO;
        Expect([MockStatus() isEqual:@"Not Enabled"], @"False entitlement reported enabled");
        mockValue = @YES; mockValidated = NO;
        Expect([MockStatus() isEqual:@"Unable to Verify"], @"Unvalidated signature was treated as a grant");
        mockNoValidator = YES; mockValidated = YES;
        Expect([MockStatus() isEqual:@"Unable to Verify"], @"Unavailable validation API was treated as a grant");
        mockNoValidator = NO; mockFailure = YES;
        Expect([MockStatus() isEqual:@"Unable to Verify"], @"API error was treated as absence or success");
        mockFailure = NO; mockNoTask = YES;
        Expect([MockStatus() isEqual:@"Unable to Verify"], @"Task creation failure was treated as success");
        mockNoTask = NO;
        for (id invalid in @[@"true", @1, NSNull.null]) {
            mockValue = invalid;
            Expect([MockStatus() isEqual:@"Unable to Verify"], @"Nonboolean entitlement was accepted");
        }
        NSDictionary *unavailable = MemoryProcessEvidence(Unavailable);
        Expect([unavailable[@"entitlement"] integerValue] == MemoryUnknown, @"Unavailable API was treated as absence");
        Expect([MemoryStatus(MemoryPresent, MemoryPresent, YES) isEqual:@"Restart Required"], @"Changed signing configuration was ignored");
        Expect([MemoryStatus(MemoryAbsent, MemoryUnknown, YES) isEqual:@"Restart Required"], @"Changed signing configuration must take precedence");

        NSDictionary *enabled = @{MemoryEntitlement: @YES};
        NSDictionary *disabled = @{MemoryEntitlement: @NO};
        NSData *enabledSignature = Signature(enabled, NO);
        Expect([MemorySignature(Executable(enabledSignature))[@"value"] integerValue] == MemoryPresent, @"Signed entitlement not parsed");
        Expect([MemorySignature(Executable(Signature(@{}, NO)))[@"value"] integerValue] == MemoryAbsent, @"Missing signed entitlement not detected");
        Expect([MemorySignature(Executable(Signature(disabled, NO)))[@"value"] integerValue] == MemoryAbsent, @"False signed entitlement not detected");
        Expect([MemorySignature(Executable(nil))[@"value"] integerValue] == MemoryAbsent, @"Unsigned binary not detected");
        Expect([MemorySignature(Executable(Signature(enabled, YES)))[@"value"] integerValue] == MemoryUnknown, @"DER-only signature was guessed");
        Expect([MemorySignature(Executable(Signature(@{MemoryEntitlement: @"true"}, NO)))[@"value"] integerValue] == MemoryInvalid, @"Invalid signed type accepted");
        NSMutableData *file = Executable(enabledSignature);
        for (NSUInteger length = 0; length < file.length; length++) {
            NSData *truncated = [file subdataWithRange:NSMakeRange(0, length)];
            Expect([MemorySignature(truncated)[@"value"] integerValue] == MemoryUnknown, @"Truncated signature was accepted");
        }
        struct linkedit_data_command broken = {LC_CODE_SIGNATURE, 0, UINT32_MAX, UINT32_MAX};
        [file replaceBytesInRange:NSMakeRange(sizeof(struct mach_header_64), sizeof(broken)) withBytes:&broken];
        Expect([MemorySignature(file)[@"value"] integerValue] == MemoryUnknown, @"Malformed load command accepted");
        for (NSNumber *offset in @[@0, @4, @8, @16, @20, @24]) {
            NSMutableData *corrupt = enabledSignature.mutableCopy;
            uint32_t invalid = UINT32_MAX;
            [corrupt replaceBytesInRange:NSMakeRange(offset.unsignedIntegerValue, 4) withBytes:&invalid];
            Expect([MemorySignature(Executable(corrupt))[@"value"] integerValue] == MemoryUnknown, @"Malformed signature blob accepted");
        }
        NSMutableData *fat = [NSMutableData data];
        NSData *thin = Executable(enabledSignature);
        AppendBE(fat, 0xcafebabe); AppendBE(fat, 1); AppendBE(fat, CPU_TYPE_ARM64); AppendBE(fat, CPU_SUBTYPE_ARM64_ALL);
        AppendBE(fat, 28); AppendBE(fat, (uint32_t)thin.length); AppendBE(fat, 0); [fat appendData:thin];
        Expect([MemorySignature(fat)[@"value"] integerValue] == MemoryPresent, @"Universal arm64 slice not parsed");

        NSDate *now = NSDate.date;
        NSDictionary *identity = @{@"application-identifier": @"TEAM.com.example.host", @"com.apple.developer.team-identifier": @"TEAM"};
        NSMutableDictionary *profileEntitlements = [identity mutableCopy]; profileEntitlements[MemoryEntitlement] = @YES;
        NSMutableDictionary *profile = [@{@"Entitlements": profileEntitlements, @"ExpirationDate": [now dateByAddingTimeInterval:3600]} mutableCopy];
        Expect([MemoryProfileEvidence(profile, identity, now)[@"issues"] count] == 0, @"Valid profile produced an issue");
        NSData *profileXML = [NSPropertyListSerialization dataWithPropertyList:profile format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        NSMutableData *wrapped = [[@"CMS-prefix" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        [wrapped appendData:profileXML]; [wrapped appendData:[@"CMS-suffix" dataUsingEncoding:NSUTF8StringEncoding]];
        // XML plists serialize NSDate at whole-second precision. Compare with the
        // serialized payload, not the original dictionary's fractional timestamp.
        NSDictionary *serializedProfile = [NSPropertyListSerialization propertyListWithData:profileXML options:NSPropertyListImmutable format:NULL error:NULL];
        Expect([MemoryProfile(wrapped) isEqual:serializedProfile], @"CMS payload extraction failed");
        Expect(MemoryProfile([@"broken" dataUsingEncoding:NSUTF8StringEncoding]) == nil, @"Malformed profile accepted");
        profile[@"ExpirationDate"] = [now dateByAddingTimeInterval:-1];
        Expect([MemoryProfileEvidence(profile, identity, now)[@"issues"] count] > 0, @"Expired profile accepted");
        profile[@"ExpirationDate"] = [now dateByAddingTimeInterval:3600];
        profileEntitlements[@"application-identifier"] = @"OTHER.com.example.host";
        Expect([MemoryProfileEvidence(profile, identity, now)[@"issues"] count] > 0, @"Mismatched App ID accepted");
        profileEntitlements[@"application-identifier"] = @"TEAM.*";
        Expect([MemoryProfileEvidence(profile, identity, now)[@"issues"] count] == 0, @"Valid wildcard App ID rejected");
        profileEntitlements[@"com.apple.developer.team-identifier"] = @"OTHER";
        Expect([MemoryProfileEvidence(profile, identity, now)[@"issues"] count] > 0, @"Mismatched team accepted");
        profileEntitlements[@"com.apple.developer.team-identifier"] = @"TEAM";
        [profileEntitlements removeObjectForKey:MemoryEntitlement];
        Expect([MemoryProfileEvidence(profile, identity, now)[@"issues"] count] > 0, @"Profile missing entitlement accepted");
        Expect([MemoryProfileEvidence(nil, identity, now)[@"issues"] count] > 0, @"Missing profile accepted");

        NSData *initial = MemoryFingerprint(enabledSignature, profileXML);
        Expect([initial isEqual:MemoryFingerprint(enabledSignature, profileXML)], @"Unchanged signing requires a restart");
        Expect(![initial isEqual:MemoryFingerprint(Signature(disabled, NO), profileXML)], @"Changed entitlement not detected");
        Expect(![initial isEqual:MemoryFingerprint(enabledSignature, nil)], @"Changed profile not detected");
        Expect(MemoryFingerprint(nil, profileXML) == nil, @"Unreadable signature generated a baseline");
        // No persisted setting can grant memory: every status is derived afresh, including after relaunch.
        Expect([MemoryStatus(MemoryAbsent, MemoryUnknown, NO) isEqual:@"Not Enabled"], @"Previous grant leaked into a new run");
        puts("Increased Memory Limit native contract checks passed");
    }
    return 0;
}
