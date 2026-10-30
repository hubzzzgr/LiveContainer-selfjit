// Foundation-only behavior checks, compiled and run by CI on macOS.
// Include the client to exercise its actual pairing parser and one-shot intent store.
#import "../LiveContainer/LCBuiltInJIT.m"

static NSUserDefaults *testSharedDefaults;
@implementation NSUserDefaults (JITContractTests)
+ (NSUserDefaults *)lcSharedDefaults { return testSharedDefaults; }
+ (NSUserDefaults *)lcUserDefaults { return NSUserDefaults.standardUserDefaults; }
+ (NSBundle *)lcMainBundle { return NSBundle.mainBundle; }
@end

// These collaborators are not used by the parser/intent tests.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincomplete-implementation"
@implementation LCSharedUtils
@end
#pragma clang diagnostic pop
int csops(pid_t pid, unsigned int ops, void *address, size_t size) { return -1; }

static void Expect(BOOL condition, NSString *message) {
    if (!condition) { fprintf(stderr, "%s\n", message.UTF8String); exit(1); }
}

int main(void) {
    @autoreleasepool {
        testSharedDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"LCBuiltInJITContractTests"];
        [NSUserDefaults.standardUserDefaults removeObjectForKey:intentKey];
        NSData *key = [NSMutableData dataWithLength:32];
        NSDictionary *valid = @{@"public_key": key, @"private_key": key, @"identifier": @"synthetic-test-only"};
        for (NSNumber *format in @[@(NSPropertyListXMLFormat_v1_0), @(NSPropertyListBinaryFormat_v1_0)]) {
            NSData *data = [NSPropertyListSerialization dataWithPropertyList:valid format:format.integerValue options:0 error:nil];
            Expect(ValidPairing(data), @"Valid XML/binary RP record rejected");
        }
        Expect(!ValidPairing([@"not a plist" dataUsingEncoding:NSUTF8StringEncoding]), @"Malformed RP record accepted");
        for (NSString *field in valid) {
            NSMutableDictionary *broken = valid.mutableCopy;
            [broken removeObjectForKey:field];
            Expect(!ValidPairing([NSPropertyListSerialization dataWithPropertyList:broken format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil]), @"Missing required field accepted");
        }
        for (id badKey in @[@"text is not a key", [NSMutableData dataWithLength:31], [NSMutableData dataWithLength:33]]) {
            NSMutableDictionary *broken = valid.mutableCopy;
            broken[@"private_key"] = badKey;
            Expect(!ValidPairing([NSPropertyListSerialization dataWithPropertyList:broken format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil]), @"Wrong key type/length accepted");
        }
        Expect(!ValidPairing([NSMutableData dataWithLength:1024 * 1024 + 1]), @"Oversized RP record accepted");

        [LCBuiltInJIT stageForGuest:@"guest-a" container:@"container-a" script:@"script-a" enabled:YES];
        [LCBuiltInJIT stageForGuest:@"guest-b" container:@"container-b" script:@"script-b" enabled:NO];
        Expect([LCBuiltInJIT takeIntentForGuest:@"guest-a" container:@"wrong"] == nil, @"Mismatched container received an intent");
        NSDictionary *first = [LCBuiltInJIT takeIntentForGuest:@"guest-a" container:@"container-a"];
        Expect([first[@"script"] isEqual:@"script-a"] && [first[@"enabled"] boolValue], @"Concurrent guest intent was lost or swapped");
        Expect([LCBuiltInJIT takeIntentForGuest:@"guest-a" container:@"container-a"] == nil, @"Launch intent was replayed");
        NSDictionary *second = [LCBuiltInJIT takeIntentForGuest:@"guest-b" container:@"container-b"];
        Expect(second && ![second[@"enabled"] boolValue], @"Explicit no-JIT override was lost");
        Expect(!second[@"pairing"] && !second[@"pid"], @"Credentials/PID persisted in launch intent");

        for (NSNumber *age in @[@(-61), @2]) {
            [LCBuiltInJIT stageForGuest:@"stale" container:nil script:nil enabled:YES];
            NSMutableDictionary *intents = [[NSUserDefaults.standardUserDefaults dictionaryForKey:intentKey] mutableCopy];
            NSMutableDictionary *intent = [intents[IntentSlot(@"stale", nil)] mutableCopy];
            intent[@"created"] = [NSDate dateWithTimeIntervalSinceNow:age.doubleValue];
            intents[IntentSlot(@"stale", nil)] = intent;
            [NSUserDefaults.standardUserDefaults setObject:intents forKey:intentKey];
            Expect([LCBuiltInJIT takeIntentForGuest:@"stale" container:nil] == nil, @"Expired/future launch intent accepted");
        }
        [NSUserDefaults.standardUserDefaults removeObjectForKey:intentKey];
        puts("Built-in JIT native contract checks passed");
    }
    return 0;
}
