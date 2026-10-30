#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LCBuiltInJIT : NSObject
@property(class, nonatomic, readonly) BOOL selected;
@property(class, nonatomic, readonly) BOOL hasPairing;
@property(class, nonatomic, readonly, nullable) NSString *unavailableReason;
+ (BOOL)importPairingFile:(NSURL *)url error:(NSError **)error NS_SWIFT_NAME(importPairingFile(_:));
+ (BOOL)removePairingFileWithError:(NSError **)error NS_SWIFT_NAME(removePairingFile());
+ (void)prepareWithCompletion:(void (^)(NSString * _Nullable message, NSError * _Nullable error))completion NS_SWIFT_NAME(prepare(completion:));
+ (void)resetDDIWithCompletion:(void (^)(NSString * _Nullable message, NSError * _Nullable error))completion NS_SWIFT_NAME(resetDDI(completion:));

// A short-lived, one-shot launch intent. Contains no credentials or PID.
+ (void)stageForGuest:(NSString *)guest container:(nullable NSString *)container
              script:(nullable NSString *)script enabled:(BOOL)enabled NS_SWIFT_NAME(stage(guest:container:script:enabled:));
+ (nullable NSDictionary *)takeIntentForGuest:(NSString *)guest container:(nullable NSString *)container;
// The controller sends credentials directly to a LiveProcess, which may not read the host's Library.
+ (nullable NSDictionary *)payloadForGuest:(NSString *)guest container:(nullable NSString *)container
                                    error:(NSError **)error;
// Before bundle/home/dyld replacement and before any guest initializers run. Main thread only.
+ (nullable NSString *)waitForGuest:(NSString *)guest container:(nullable NSString *)container
                              info:(NSDictionary *)info liveProcessPayload:(nullable NSDictionary *)payload;
@end

NS_ASSUME_NONNULL_END
