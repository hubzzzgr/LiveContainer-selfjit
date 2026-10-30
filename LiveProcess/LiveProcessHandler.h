#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Shared declarations for callers that resolve the handler at runtime.
@interface LiveProcessHandler : NSObject <NSExtensionRequestHandling>
+ (nullable NSExtensionContext *)extensionContext;
+ (nullable NSDictionary *)retrievedAppInfo;
+ (nullable NSDictionary *)takeBuiltInJITPayload;
@end

NS_ASSUME_NONNULL_END
