#pragma once
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <stdint.h>

// Minimal ABI declarations for the registry queries used by LiveContainer and StikJIT.
// iOS SDKs do not consistently ship IOKit's public macOS headers. Keep the iOS
// linkage in the selected SDK rather than importing a versioned macOS SDK path.
// Signatures: apple-oss-distributions/IOKitUser, IOKitLib.h; key: xnu/IOKitKeys.h.
typedef mach_port_t io_object_t;
typedef io_object_t io_registry_entry_t;
#define IO_OBJECT_NULL ((io_object_t)0)
#define kIORegistryEntryPropertyKeysKey "IORegistryEntryPropertyKeys"
extern const mach_port_t kIOMainPortDefault;
io_registry_entry_t IORegistryEntryFromPath(mach_port_t mainPort, const char *path);
CFTypeRef IORegistryEntryCreateCFProperty(io_registry_entry_t entry, CFStringRef key,
                                        CFAllocatorRef allocator, uint32_t options);
kern_return_t IOObjectRelease(io_object_t object);
