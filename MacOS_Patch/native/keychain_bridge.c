#include "keychain_bridge.h"
#include "bridge_config.h"
#include <mach/mach.h>
#include <mach/machine.h>
#include <mach/mach_vm.h>
#include <mach/vm_page_size.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static atomic_uint bridgeStatus = 0;

static bool isDictionary(CFTypeRef value)
{
    return value != NULL && CFGetTypeID(value) == CFDictionaryGetTypeID();
}

static bool isTarget(CFDictionaryRef query)
{
    if (!isDictionary(query))
    {
        return false;
    }
    CFTypeRef itemClass = CFDictionaryGetValue(query, kSecClass);
    CFTypeRef group = CFDictionaryGetValue(query, kSecAttrAccessGroup);
    return itemClass != NULL && group != NULL && CFEqual(itemClass, kSecClassGenericPassword) && CFEqual(group, CFSTR(BRIDGE_ACCESS_GROUP));
}

static CFMutableDictionaryRef localDictionary(CFDictionaryRef source, bool isQuery)
{
    if (!isDictionary(source) || CFDictionaryContainsKey(source, kSecAttrAccessControl))
    {
        return NULL;
    }
    CFTypeRef comment = CFDictionaryGetValue(source, kSecAttrComment);
    if (comment != NULL && !CFEqual(comment, CFSTR(BRIDGE_MARKER)))
    {
        return NULL;
    }
    CFMutableDictionaryRef result = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, source);
    if (result == NULL)
    {
        return NULL;
    }
    CFTypeRef service = CFDictionaryGetValue(source, kSecAttrService);
    if (service != NULL)
    {
        if (CFGetTypeID(service) != CFStringGetTypeID())
        {
            CFRelease(result);
            return NULL;
        }
        // 备注不属于唯一键；同时隔离 service，避免与原有同账户条目冲突。
        CFStringRef namespaced = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%@:%@"), CFSTR(BRIDGE_MARKER), service);
        if (namespaced == NULL)
        {
            CFRelease(result);
            return NULL;
        }
        CFDictionarySetValue(result, kSecAttrService, namespaced);
        CFRelease(namespaced);
    }
    CFDictionaryRemoveValue(result, kSecAttrAccessGroup);
    CFDictionaryRemoveValue(result, kSecAttrSynchronizable);
    CFDictionaryRemoveValue(result, kSecAttrAccessible);
    CFDictionaryRemoveValue(result, kSecUseDataProtectionKeychain);
    // 所有查询都必须携带隔离标记，避免无 service 的批量删除触及其他条目。
    CFDictionarySetValue(result, kSecAttrComment, CFSTR(BRIDGE_MARKER));
    if (isQuery)
    {
        CFDictionarySetValue(result, kSecUseDataProtectionKeychain, kCFBooleanFalse);
    }
    return result;
}

static CFTypeRef decodedResult(CFTypeRef original)
{
    CFTypeID type = CFGetTypeID(original);
    if (type == CFDictionaryGetTypeID())
    {
        CFMutableDictionaryRef result = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, original);
        if (result == NULL)
        {
            return NULL;
        }
        CFTypeRef service = CFDictionaryGetValue(result, kSecAttrService);
        CFStringRef prefix = CFSTR(BRIDGE_MARKER ":");
        if (service != NULL && CFGetTypeID(service) == CFStringGetTypeID() && CFStringHasPrefix(service, prefix))
        {
            CFIndex offset = CFStringGetLength(prefix);
            CFStringRef decoded = CFStringCreateWithSubstring(kCFAllocatorDefault, service, CFRangeMake(offset, CFStringGetLength(service) - offset));
            if (decoded == NULL)
            {
                CFRelease(result);
                return NULL;
            }
            CFDictionarySetValue(result, kSecAttrService, decoded);
            CFRelease(decoded);
        }
        CFDictionaryRemoveValue(result, kSecAttrComment);
        return result;
    }
    if (type == CFArrayGetTypeID())
    {
        CFMutableArrayRef result = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        if (result == NULL)
        {
            return NULL;
        }
        for (CFIndex index = 0; index < CFArrayGetCount(original); ++index)
        {
            CFTypeRef item = decodedResult(CFArrayGetValueAtIndex(original, index));
            if (item == NULL)
            {
                CFRelease(result);
                return NULL;
            }
            CFArrayAppendValue(result, item);
            CFRelease(item);
        }
        return result;
    }
    return CFRetain(original);
}

static OSStatus publishResult(OSStatus status, CFTypeRef original, CFTypeRef *result)
{
    if (original != NULL)
    {
        if (status == errSecSuccess && result != NULL)
        {
            *result = decodedResult(original);
            if (*result == NULL)
            {
                status = errSecAllocate;
            }
        }
        CFRelease(original);
    }
    return status;
}

OSStatus NavicatBridgeAdd(CFDictionaryRef attributes, CFTypeRef *result)
{
    if (!isTarget(attributes))
    {
        return SecItemAdd(attributes, result);
    }
    CFMutableDictionaryRef local = localDictionary(attributes, true);
    if (local == NULL)
    {
        return errSecParam;
    }
    CFTypeRef original = NULL;
    OSStatus status = SecItemAdd(local, result == NULL ? NULL : &original);
    CFRelease(local);
    return publishResult(status, original, result);
}

OSStatus NavicatBridgeCopyMatching(CFDictionaryRef query, CFTypeRef *result)
{
    if (!isTarget(query))
    {
        return SecItemCopyMatching(query, result);
    }
    CFMutableDictionaryRef local = localDictionary(query, true);
    if (local == NULL)
    {
        return errSecParam;
    }
    CFTypeRef original = NULL;
    OSStatus status = SecItemCopyMatching(local, result == NULL ? NULL : &original);
    CFRelease(local);
    return publishResult(status, original, result);
}

OSStatus NavicatBridgeUpdate(CFDictionaryRef query, CFDictionaryRef attributes)
{
    if (!isTarget(query))
    {
        return SecItemUpdate(query, attributes);
    }
    CFMutableDictionaryRef localQuery = localDictionary(query, true);
    CFMutableDictionaryRef localAttributes = localDictionary(attributes, false);
    if (localQuery == NULL || localAttributes == NULL)
    {
        if (localQuery != NULL)
        {
            CFRelease(localQuery);
        }
        if (localAttributes != NULL)
        {
            CFRelease(localAttributes);
        }
        return errSecParam;
    }
    OSStatus status = SecItemUpdate(localQuery, localAttributes);
    CFRelease(localAttributes);
    CFRelease(localQuery);
    return status;
}

OSStatus NavicatBridgeDelete(CFDictionaryRef query)
{
    if (!isTarget(query))
    {
        return SecItemDelete(query);
    }
    CFMutableDictionaryRef local = localDictionary(query, true);
    if (local == NULL)
    {
        return errSecParam;
    }
    OSStatus status = SecItemDelete(local);
    CFRelease(local);
    return status;
}

unsigned int NavicatBridgeStatus(void)
{
    return atomic_load_explicit(&bridgeStatus, memory_order_acquire);
}

static int installSlots(uintptr_t *slots[4])
{
    const uintptr_t originals[4] = {(uintptr_t)SecItemAdd, (uintptr_t)SecItemCopyMatching, (uintptr_t)SecItemUpdate, (uintptr_t)SecItemDelete};
    const uintptr_t replacements[4] = {(uintptr_t)NavicatBridgeAdd, (uintptr_t)NavicatBridgeCopyMatching, (uintptr_t)NavicatBridgeUpdate, (uintptr_t)NavicatBridgeDelete};
    mach_vm_size_t pageSize = (mach_vm_size_t)vm_page_size;
    mach_vm_address_t page = (mach_vm_address_t)slots[0] & ~(pageSize - 1);
    for (unsigned int index = 0; index < 4; ++index)
    {
        if (((uintptr_t)slots[index] & (sizeof(uintptr_t) - 1)) != 0 || ((mach_vm_address_t)slots[index] & ~(pageSize - 1)) != page || atomic_load_explicit((_Atomic(uintptr_t) *)slots[index], memory_order_acquire) != originals[index])
        {
            return 1;
        }
    }
    mach_vm_address_t regionAddress = page;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t status = mach_vm_region(mach_task_self(), &regionAddress, &regionSize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), object);
    }
    if (status != KERN_SUCCESS || regionAddress > page || regionAddress + regionSize < page + pageSize || (info.protection & VM_PROT_READ) == 0)
    {
        return 2;
    }
    status = mach_vm_protect(mach_task_self(), page, pageSize, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (status != KERN_SUCCESS)
    {
        return 3;
    }
    // 仅修改主程序的四个导入指针，不改系统函数机器码；原子发布避免并发撕裂。
    for (unsigned int index = 0; index < 4; ++index)
    {
        atomic_store_explicit((_Atomic(uintptr_t) *)slots[index], replacements[index], memory_order_release);
    }
    status = mach_vm_protect(mach_task_self(), page, pageSize, false, info.protection);
    if (status != KERN_SUCCESS)
    {
        return 4;
    }
    atomic_store_explicit(&bridgeStatus, 15, memory_order_release);
    return 0;
}

__attribute__((constructor)) static void initializeBridge(void)
{
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (header == NULL || header->magic != MH_MAGIC_64 || header->filetype != MH_EXECUTE || header->cputype != CPU_TYPE_ARM64)
    {
        fprintf(stderr, "钥匙串转接安装失败：主程序架构不匹配。\n");
        _exit(78);
    }
    uintptr_t base = (uintptr_t)header;
    uintptr_t *slots[4] = {(uintptr_t *)(base + BRIDGE_SLOT_ADD), (uintptr_t *)(base + BRIDGE_SLOT_COPY), (uintptr_t *)(base + BRIDGE_SLOT_UPDATE), (uintptr_t *)(base + BRIDGE_SLOT_DELETE)};
    int status = installSlots(slots);
    if (status != 0)
    {
        fprintf(stderr, "钥匙串转接安装失败：错误码=%d。\n", status);
        _exit(78);
    }
}
