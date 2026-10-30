#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Read-only diagnostics for the executable hosting a guest, never the guest's signature.
@interface LCMemoryDiagnostics : NSObject
/// Called before guest bundle/executable hooks are installed. Keeps a process-local baseline only.
+ (void)captureLaunchConfiguration:(NSBundle *)hostBundle;
/// Performs file I/O; call away from the main queue. No allocation stress test is performed.
+ (NSDictionary<NSString *, id> *)snapshot;
@end

NS_ASSUME_NONNULL_END
