#import "LCBuiltInJIT.h"
#import "LCSharedUtils.h"
#import "FoundationPrivate.h"
#import "utils.h"
#import <dlfcn.h>
#import <ifaddrs.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <notify.h>

static NSString * const intentKey = @"LCBuiltInJITLaunchIntents";
static NSString *IntentSlot(NSString *guest, NSString *container) {
    return [[NSJSONSerialization dataWithJSONObject:@[guest, container ?: @""] options:0 error:nil] base64EncodedStringWithOptions:0];
}
static NSError *JITError(NSString *message) {
    return [NSError errorWithDomain:@"LCBuiltInJIT" code:1 userInfo:@{NSLocalizedDescriptionKey: message}];
}

static NSBundle *HostBundle(void) {
    NSBundle *bundle = NSUserDefaults.lcMainBundle ?: NSBundle.mainBundle;
    if ([bundle.bundlePath.pathExtension isEqualToString:@"appex"]) {
        return [NSBundle bundleWithURL:bundle.bundleURL.URLByDeletingLastPathComponent.URLByDeletingLastPathComponent];
    }
    return bundle;
}

static NSURL *PairingURL(void) {
    // Captured before any guest changes HOME or Foundation's directory caches.
    static NSURL *url;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        url = [[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject
               URLByAppendingPathComponent:@"LiveContainer/BuiltInJIT/pairing.plist"];
    });
    return url;
}

static BOOL ValidPairing(NSData *data) {
    if (!data || data.length > 1024 * 1024) return NO;
    id plist = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
    if (![plist isKindOfClass:NSDictionary.class]) return NO;
    return [plist[@"public_key"] isKindOfClass:NSData.class] && [plist[@"public_key"] length] == 32 &&
           [plist[@"private_key"] isKindOfClass:NSData.class] && [plist[@"private_key"] length] == 32 &&
           [plist[@"identifier"] isKindOfClass:NSString.class] && [plist[@"identifier"] length] > 0;
}

static BOOL Debugged(void) {
    int flags = 0;
    return csops(getpid(), 0, &flags, sizeof(flags)) == 0 && (flags & CS_DEBUGGED) != 0;
}

// Each resolver owns its callbacks and deadline on the main run loop. Never waits on its callback queue.
@interface LCJITPortResolver : NSObject <NSNetServiceBrowserDelegate, NSNetServiceDelegate>
@property(nonatomic, strong) NSNetServiceBrowser *browser;
@property(nonatomic, strong) NSMutableArray<NSNetService *> *services;
@property(nonatomic, strong) NSTimer *timer;
@property(copy) void (^completion)(NSNumber *);
- (void)start:(void (^)(NSNumber *))completion;
@end

@implementation LCJITPortResolver
- (void)finish:(NSNumber *)port {
    if (!self.completion) return;
    void (^completion)(NSNumber *) = self.completion;
    self.completion = nil;
    [self.timer invalidate];
    self.timer = nil;
    self.browser.delegate = nil;
    [self.browser stop];
    for (NSNetService *service in self.services) { service.delegate = nil; [service stop]; }
    self.browser = nil;
    self.services = nil;
    completion(port);
}
- (void)start:(void (^)(NSNumber *))completion {
    self.completion = completion;
    self.services = [NSMutableArray new];
    self.browser = [NSNetServiceBrowser new];
    self.browser.delegate = self;
    self.timer = [NSTimer scheduledTimerWithTimeInterval:3 repeats:NO block:^(NSTimer *timer) { [self finish:nil]; }];
    [self.browser searchForServicesOfType:@"_remotepairing._tcp." inDomain:@"local."];
}
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didFindService:(NSNetService *)service moreComing:(BOOL)more {
    if (!self.completion) return;
    [self.services addObject:service];
    service.delegate = self;
    [service resolveWithTimeout:2];
}
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didNotSearch:(NSDictionary *)errorDict { [self finish:nil]; }
- (void)netServiceDidResolveAddress:(NSNetService *)service {
    if (!self.completion) return;
    // Ignore other phones on the LAN. Only this device's interface addresses may supply the port.
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return;
    BOOL local = NO;
    for (NSData *data in service.addresses) {
        const struct sockaddr *address = data.bytes;
        if (data.length < sizeof(struct sockaddr)) continue;
        for (struct ifaddrs *entry = interfaces; entry; entry = entry->ifa_next) {
            if (!entry->ifa_addr || entry->ifa_addr->sa_family != address->sa_family) continue;
            if (address->sa_family == AF_INET && data.length >= sizeof(struct sockaddr_in)) {
                local |= ((const struct sockaddr_in *)address)->sin_addr.s_addr == ((struct sockaddr_in *)entry->ifa_addr)->sin_addr.s_addr;
            } else if (address->sa_family == AF_INET6 && data.length >= sizeof(struct sockaddr_in6)) {
                local |= memcmp(&((const struct sockaddr_in6 *)address)->sin6_addr,
                                &((struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == 0;
            }
        }
    }
    freeifaddrs(interfaces);
    if (local && service.port > 0 && service.port <= UINT16_MAX) [self finish:@(service.port)];
}
@end

@interface NSExtension (LCJITCompletion)
- (void)setRequestCompletionBlock:(void (^)(NSUUID *, NSArray *))callback;
@end

@interface LCJITSession : NSObject
@property(nonatomic, strong) NSExtension *helper;
@property(nonatomic, strong) LCJITPortResolver *resolver;
@property(nonatomic, strong) NSString *requestID;
@property int notificationToken;
@property BOOL listening;
@property int targetPID;
@property BOOL attached;
@property BOOL completed;
@property BOOL success;
@property BOOL guestEntered;
@property(nonatomic, strong) NSUserDefaults *hostDefaults;
@property(nonatomic, strong) NSExtensionContext *targetContext;
@property(nonatomic, strong) NSError *error;
@property(copy) void (^completion)(NSString *, NSError *);
- (void)start:(NSString *)operation pairing:(nullable NSData *)pairing script:(nullable NSString *)script port:(nullable NSNumber *)port;
@end

// Kept until the debugger actually returns, including after the startup barrier opens.
static NSMutableSet<LCJITSession *> *sessions;
@implementation LCJITSession
- (void)finish:(BOOL)success message:(NSString *)message {
    if (self.completed) return;
    self.completed = YES;
    self.success = success;
    if (!success) self.error = JITError(message ?: @"The built-in JIT helper stopped.");
    if (self.listening) { notify_cancel(self.notificationToken); self.listening = NO; }
    if (self.completion) self.completion(message, self.error);
    self.completion = nil;
    [sessions removeObject:self];
    if (!success && self.guestEntered) {
        // A guest may make another breakpoint request later. Do not let it continue with a dead helper.
        [self.hostDefaults setObject:@"The built-in JIT debugger stopped while the guest was running. Check LocalDevVPN, then relaunch the guest." forKey:@"error"];
        [self.hostDefaults synchronize];
        [self.targetContext cancelRequestWithError:self.error];
        exit(1);
    }
}
- (void)start:(NSString *)operation pairing:(NSData *)pairing script:(NSString *)script port:(NSNumber *)port {
    NSAssert(NSThread.isMainThread, @"JIT sessions must start on the main thread");
    if (!sessions) sessions = [NSMutableSet new];
    [sessions addObject:self];
    self.requestID = NSUUID.UUID.UUIDString;
    __weak LCJITSession *weakSelf = self;
    NSString *notification = [@"com.kdt.livecontainer.jit." stringByAppendingFormat:@"%@.attached", self.requestID];
    int token = 0;
    uint32_t status = notify_register_dispatch(notification.UTF8String, &token, dispatch_get_main_queue(), ^(int token) {
        LCJITSession *session = weakSelf;
        if (session && !session.completed) session.attached = YES;
    });
    if (status != NOTIFY_STATUS_OK) { [self finish:NO message:@"Could not observe the built-in debugger's attach event."]; return; }
    self.notificationToken = token;
    self.listening = YES;
    if (!NSClassFromString(@"NSExtension")) dlopen("/System/Library/Frameworks/ExtensionFoundation.framework/ExtensionFoundation", RTLD_NOW);
    NSBundle *helperBundle = [NSBundle bundleWithURL:[HostBundle().builtInPlugInsURL URLByAppendingPathComponent:@"LCJITHelper.appex"]];
    if (!helperBundle.bundleIdentifier.length) { [self finish:NO message:@"LCJITHelper has no installed bundle identifier. Reinstall LiveContainer and keep its extensions."]; return; }
    NSError *error;
    self.helper = [NSClassFromString(@"NSExtension") extensionWithIdentifier:helperBundle.bundleIdentifier error:&error];
    if (!self.helper) { [self finish:NO message:@"Could not launch LCJITHelper. Reinstall LiveContainer and keep its extensions."]; return; }
    [self.helper setRequestCancellationBlock:^(NSUUID *uuid, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{ [weakSelf finish:NO message:@"The JIT helper was cancelled. Reopen LiveContainer and try again."]; });
    }];
    [self.helper setRequestInterruptionBlock:^(NSUUID *uuid) {
        dispatch_async(dispatch_get_main_queue(), ^{ [weakSelf finish:NO message:@"The JIT helper was interrupted. Reopen LiveContainer and try again."]; });
    }];
    [self.helper setRequestCompletionBlock:^(NSUUID *uuid, NSArray *items) {
        NSDictionary *response = [items.firstObject userInfo];
        dispatch_async(dispatch_get_main_queue(), ^{
            LCJITSession *session = weakSelf;
            if (!session) return;
            BOOL valid = [response[@"version"] integerValue] == 1 && [response[@"id"] isEqual:session.requestID] &&
                         [response[@"pid"] intValue] == session.targetPID;
            [session finish:valid && [response[@"success"] boolValue]
                    message:valid ? response[@"message"] : @"The JIT helper returned an invalid response."];
        });
    }];
    void (^begin)(NSNumber *) = ^(NSNumber *resolvedPort) {
        if (self.completed) return;
        self.resolver = nil;
        NSMutableDictionary *request = [@{@"version": @1, @"id": self.requestID, @"pid": @(self.targetPID),
            @"operation": operation, @"expires": @([NSDate timeIntervalSinceReferenceDate] + 300)} mutableCopy];
        request[@"pairing"] = pairing;
        request[@"script"] = script;
        request[@"port"] = resolvedPort ?: @49152;
        NSExtensionItem *item = [NSExtensionItem new];
        item.userInfo = request;
        [self.helper beginExtensionRequestWithInputItems:@[item] completion:^(NSUUID *identifier) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!identifier) [self finish:NO message:@"The JIT helper did not start. Keep Extensions must be enabled when installing."];
            });
        }];
    };
    if (port || [operation isEqualToString:@"resetDDI"]) begin(port);
    else { self.resolver = [LCJITPortResolver new]; [self.resolver start:begin]; }
}
@end

@implementation LCBuiltInJIT
+ (BOOL)selected { return [NSUserDefaults.lcSharedDefaults integerForKey:@"LCJITEnablerType"] == 7; }
+ (BOOL)hasPairing { return ValidPairing([NSData dataWithContentsOfURL:PairingURL()]); }
+ (NSString *)unavailableReason {
#if TARGET_OS_SIMULATOR || TARGET_OS_MACCATALYST
    return @"Built-in StikJIT requires a physical iOS device.";
#else
    if (@available(iOS 26.0, *)) {} else { return @"Built-in StikJIT requires iOS 26 or later."; }
    if (![NSBundle bundleWithURL:[HostBundle().builtInPlugInsURL URLByAppendingPathComponent:@"LCJITHelper.appex"]].bundleIdentifier.length)
        return @"LCJITHelper is missing. Reinstall LiveContainer and choose Keep Extensions.";
    void *task = SecTaskCreateFromSelf(NULL);
    CFTypeRef value = task ? SecTaskCopyValueForEntitlement(task, CFSTR("get-task-allow"), NULL) : NULL;
    BOOL allowed = value == kCFBooleanTrue;
    if (value) CFRelease(value);
    if (task) CFRelease(task);
    return allowed ? nil : @"This process lacks get-task-allow. Install with a development signing profile and enable Developer Mode.";
#endif
}
+ (BOOL)importPairingFile:(NSURL *)url error:(NSError **)error {
    if (!url.isFileURL) { if (error) *error = JITError(@"Select a local Remote Pairing plist from Files."); return NO; }
    BOOL scoped = [url startAccessingSecurityScopedResource];
    NSDictionary *attributes = [NSFileManager.defaultManager attributesOfItemAtPath:url.path error:error];
    NSData *data = [attributes[NSFileSize] unsignedLongLongValue] <= 1024 * 1024 ? [NSData dataWithContentsOfURL:url options:0 error:error] : nil;
    if (scoped) [url stopAccessingSecurityScopedResource];
    if (!ValidPairing(data)) {
        if (error) *error = JITError(@"Import a Remote Pairing (RP) plist containing public_key, private_key and identifier. A SideStore/lockdown .mobiledevicepairing file is a different format.");
        return NO;
    }
    NSURL *directory = PairingURL().URLByDeletingLastPathComponent;
    if (![NSFileManager.defaultManager createDirectoryAtURL:directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0700} error:error]) return NO;
    if (![data writeToURL:PairingURL() options:NSDataWritingAtomic | NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication error:error]) return NO;
    [NSFileManager.defaultManager setAttributes:@{NSFilePosixPermissions: @0600} ofItemAtPath:PairingURL().path error:nil];
    [PairingURL() setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
    return YES;
}
+ (BOOL)removePairingFileWithError:(NSError **)error {
    if (![NSFileManager.defaultManager fileExistsAtPath:PairingURL().path]) return YES;
    return [NSFileManager.defaultManager removeItemAtURL:PairingURL() error:error];
}
+ (NSNumber *)portOverride {
    NSInteger port = [NSUserDefaults.lcSharedDefaults integerForKey:@"LCBuiltInJITPort"];
    return port > 0 && port <= UINT16_MAX ? @(port) : nil;
}
+ (void)perform:(NSString *)operation completion:(void (^)(NSString *, NSError *))completion {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *reason = self.unavailableReason;
        NSData *pairing = [NSData dataWithContentsOfURL:PairingURL()];
        if (!reason && ![operation isEqualToString:@"resetDDI"] && !ValidPairing(pairing)) reason = @"Import your device's Remote Pairing file in Built-in StikJIT Setup first.";
        if (reason) { completion(nil, JITError(reason)); return; }
        if (sessions.count) { completion(nil, JITError(@"A JIT helper session is still active. Close the running JIT guest before preparing or resetting its cache.")); return; }
        LCJITSession *session = [LCJITSession new];
        session.completion = completion;
        [session start:operation pairing:pairing script:nil port:self.portOverride];
        // Preparation is not a debugger session and can safely be terminated on a deadline.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 240 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (!session.completed) {
                [session.helper _kill:9];
                [session finish:NO message:@"Device preparation timed out. Check LocalDevVPN, unlock the device, and try Prepare again."];
            }
        });
    });
}
+ (void)prepareWithCompletion:(void (^)(NSString *, NSError *))completion { [self perform:@"prepare" completion:completion]; }
+ (void)resetDDIWithCompletion:(void (^)(NSString *, NSError *))completion { [self perform:@"resetDDI" completion:completion]; }
+ (void)stageForGuest:(NSString *)guest container:(NSString *)container script:(NSString *)script enabled:(BOOL)enabled {
    @synchronized(self) {
        NSMutableDictionary *intents = [[NSUserDefaults.standardUserDefaults dictionaryForKey:intentKey] mutableCopy] ?: [NSMutableDictionary new];
        for (NSString *key in intents.allKeys) {
            NSDate *created = [intents[key] isKindOfClass:NSDictionary.class] ? intents[key][@"created"] : nil;
            if (![created isKindOfClass:NSDate.class] || -created.timeIntervalSinceNow > 60) [intents removeObjectForKey:key];
        }
        intents[IntentSlot(guest, container)] = @{@"version": @1, @"guest": guest, @"container": container ?: @"", @"script": script ?: @"",
            @"enabled": @(enabled), @"nonce": NSUUID.UUID.UUIDString, @"created": NSDate.date};
        [NSUserDefaults.standardUserDefaults setObject:intents forKey:intentKey];
        [NSUserDefaults.standardUserDefaults synchronize];
    }
}
+ (NSDictionary *)takeIntentForGuest:(NSString *)guest container:(NSString *)container {
    NSDictionary *intent;
    @synchronized(self) {
        NSMutableDictionary *intents = [[NSUserDefaults.standardUserDefaults dictionaryForKey:intentKey] mutableCopy];
        intent = intents[IntentSlot(guest, container)];
        [intents removeObjectForKey:IntentSlot(guest, container)];
        if (intents.count) [NSUserDefaults.standardUserDefaults setObject:intents forKey:intentKey];
        else [NSUserDefaults.standardUserDefaults removeObjectForKey:intentKey];
        [NSUserDefaults.standardUserDefaults synchronize];
    }
    if (![intent isKindOfClass:NSDictionary.class]) return nil;
    NSDate *created = intent[@"created"];
    if (![created isKindOfClass:NSDate.class] || -created.timeIntervalSinceNow > 60 || created.timeIntervalSinceNow > 1 ||
        ![intent[@"guest"] isEqual:guest] || ![intent[@"container"] isEqual:container ?: @""] || [intent[@"version"] integerValue] != 1 ||
        ![intent[@"nonce"] isKindOfClass:NSString.class] || ![[NSUUID alloc] initWithUUIDString:intent[@"nonce"]]) return nil;
    return intent;
}
+ (NSDictionary *)payloadForGuest:(NSString *)guest container:(NSString *)container error:(NSError **)error {
    NSDictionary *intent = [self takeIntentForGuest:guest container:container];
    if (!self.selected) return nil;
    // Other entry points (e.g. reopening a window) use the guest's saved policy.
    if (!intent) {
        BOOL shared = NO;
        NSBundle *bundle = [LCSharedUtils findBundleWithBundleId:guest isSharedAppOut:&shared];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfURL:[bundle.bundleURL URLByAppendingPathComponent:@"LCAppInfo.plist"]];
        [self stageForGuest:guest container:container script:[info[@"is32bit"] boolValue] ? nil : info[@"jitLaunchScriptJs"]
                   enabled:[info[@"isJITNeeded"] boolValue] || [info[@"is32bit"] boolValue]];
        intent = [self takeIntentForGuest:guest container:container];
    }
    NSMutableDictionary *payload = intent.mutableCopy;
    if (![payload[@"enabled"] boolValue]) return payload;
    NSData *pairing = [NSData dataWithContentsOfURL:PairingURL()];
    if (!ValidPairing(pairing)) { if (error) *error = JITError(@"Import a Remote Pairing file before launching this guest."); return nil; }
    payload[@"pairing"] = pairing;
    payload[@"port"] = self.portOverride;
    return payload;
}
+ (NSString *)waitForGuest:(NSString *)guest container:(NSString *)container info:(NSDictionary *)info liveProcessPayload:(NSDictionary *)payload {
    NSAssert(NSThread.isMainThread, @"The guest entry barrier requires the main run loop");
    BOOL liveProcess = [HostBundle().bundlePath isEqualToString:(NSUserDefaults.lcMainBundle ?: NSBundle.mainBundle).bundlePath] == NO;
    NSDictionary *intent = liveProcess ? payload : [self takeIntentForGuest:guest container:container];
    if (!self.selected && !payload) return nil;
    if (liveProcess && !payload) return @"No built-in JIT launch payload was supplied by the controller. Reopen this window from LiveContainer.";
    if (liveProcess) {
        NSDate *created = intent[@"created"];
        if (![created isKindOfClass:NSDate.class] || -created.timeIntervalSinceNow > 60 || created.timeIntervalSinceNow > 1 ||
            [intent[@"version"] integerValue] != 1 || ![intent[@"nonce"] isKindOfClass:NSString.class])
            return @"The built-in JIT launch payload expired. Close this window and relaunch the guest.";
    }
    if (intent && (![intent[@"guest"] isEqual:guest] || ![intent[@"container"] isEqual:container ?: @""])) return @"The built-in JIT launch intent does not match this guest.";
    BOOL enabled = intent ? [intent[@"enabled"] boolValue] : [info[@"isJITNeeded"] boolValue] || [info[@"is32bit"] boolValue];
    if (!enabled) return nil;
    NSString *reason = self.unavailableReason;
    if (reason) return reason;
    NSData *pairing = liveProcess ? payload[@"pairing"] : [NSData dataWithContentsOfURL:PairingURL()];
    if (!ValidPairing(pairing)) return @"Import your device's Remote Pairing file in Built-in StikJIT Setup first.";
    NSString *script = intent ? intent[@"script"] : ([info[@"is32bit"] boolValue] ? nil : info[@"jitLaunchScriptJs"]);
    if (!script.length) script = [[NSData dataWithContentsOfURL:[HostBundle() URLForResource:@"universal" withExtension:@"js"]] base64EncodedStringWithOptions:0];
    NSData *source = [[NSData alloc] initWithBase64EncodedString:script ?: @"" options:0];
    if (!source.length || source.length > 1024 * 1024 || ![[NSString alloc] initWithData:source encoding:NSUTF8StringEncoding]) return @"The guest JIT script is missing or is not base64-encoded UTF-8 JavaScript.";
    LCJITSession *session = [LCJITSession new];
    session.targetPID = getpid();
    session.hostDefaults = NSUserDefaults.lcUserDefaults;
    session.targetContext = liveProcess ? [NSClassFromString(@"LiveProcessHandler") extensionContext] : nil;
    [session start:@"enable" pairing:pairing script:script port:liveProcess ? payload[@"port"] : self.portOverride];
    // Preparation is performed in the controller before a normal restart. Keep this early-launch wait bounded.
    NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 30;
    while (!session.error && NSProcessInfo.processInfo.systemUptime < deadline) {
        if ((session.attached || (session.completed && session.success)) && Debugged()) {
            session.guestEntered = YES;
            return nil;
        }
        if (session.completed) break;
        @autoreleasepool { [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]]; }
    }
    // The caller exits this target on error. Never kill an attached debugger and leave a suspended guest behind.
    return session.error.localizedDescription ?: @"Built-in JIT did not attach before the startup deadline. Reopen LiveContainer, connect LocalDevVPN, run Prepare, then launch again.";
}
@end
