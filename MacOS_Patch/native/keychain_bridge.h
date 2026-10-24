#ifndef NAVICAT_KEYCHAIN_BRIDGE_H
#define NAVICAT_KEYCHAIN_BRIDGE_H

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

__attribute__((visibility("default"))) OSStatus NavicatBridgeAdd(CFDictionaryRef attributes, CFTypeRef *result);
__attribute__((visibility("default"))) OSStatus NavicatBridgeCopyMatching(CFDictionaryRef query, CFTypeRef *result);
__attribute__((visibility("default"))) OSStatus NavicatBridgeUpdate(CFDictionaryRef query, CFDictionaryRef attributes);
__attribute__((visibility("default"))) OSStatus NavicatBridgeDelete(CFDictionaryRef query);
__attribute__((visibility("default"))) unsigned int NavicatBridgeStatus(void);

#endif
