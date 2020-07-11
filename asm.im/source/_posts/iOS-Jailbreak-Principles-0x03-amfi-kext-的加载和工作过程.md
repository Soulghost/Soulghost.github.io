# 系列文章
1. [iOS Jailbreak Principles 0x01 - rootfs remount r/w 原理](https://juejin.im/post/5e8ad7ccf265da47b1778e17)
2. [iOS Jailbreak Principles 0x02 - codesign and amfid bypass](https://juejin.im/post/5ee5a9f26fb9a04802148379)

# 前言
在上一篇文章中我们介绍了 amfid 的 codesign 机制及其绕过，amfid 是 codesign 逻辑在 userland 的一个 daemon，代表了 C/S 架构中的 Server。本文将介绍 kernel 侧的 amfi.kext，它是 amfid 的 Client，以 Kernel Extension 的形式被加载和注册到 Kernel 中。

# Kernel Extension
## 定义
XNU 是一个功能丰富的内核，包含了调度, 内存管理, I/O 等必要的服务，但它依然难以直接适配浩如烟海的硬件和外设，即使是宏内核也无法完全做到这一点[1]。

就像是 user mode application 中常常包含 dylib，在 kernel mode 也有 kernel modules 作为扩展，在 XNU 中被称为 kernel extensions，简称为 kext[1]。

## Pre-Linking
以常规视角而言，操作系统应当是先 boot kernel，随后 load kexts。在 iOS 中，kernel 和它的扩展不是以分离的文件形式存在，而是将 kernel 和 kexts 合并成一个 kernelcache 文件直接被 boot loader 加载。

kernelcache 带来了两个好处，其一是 kexts 不必再像 dylib 那样进行动态链接，省去了外部符号地址解析的过程，加快了加载速度；其二是 kernelcache 可以被完整的签名以降低 kext 被篡改的风险[1]。

# 分析 AppleMobileFileIntegrity.kext
## 从 kernelcache 中分离
由于 amfi.kext 被 prelink 到 kernelcache 中，因此其 Info.plist 和 binary 都直接包含在了庞大的 kernelcache 中，为了便于分析我们可以将它们从 kernelcache 中分离出来。

### 通过 joker 分离 kext binary
使用 joker (http://www.newosxbook.com/tools/joker.html) 可以分离出 kext 和进行部分符号化：

```bash
# 指定输出目录
> cd /tmp/kext
> export JOKER_DIR=/tmp/kext

# 准备好 kernelcache
> ls .
kernelcache

# 分离 amfi.kext
> joker -K com.apple.driver.AppleMobileFileIntegrity kernelcache
Writing kext out to /tmp/kext/com.apple.driver.AppleMobileFileIntegrity.kext
Symbolicated stubs to /tmp/kext/com.apple.driver.AppleMobileFileIntegrity.kext.ARM64.E815A4DD-90E7-3A38-A4BA-EFA2425BC543

# 查看产物
> ls .
com.apple.driver.AppleMobileFileIntegrity.kext
com.apple.driver.AppleMobileFileIntegrity.kext.ARM64.E815A4DD-90E7-3A38-A4BA-EFA2425BC543
kernelcache
```

可以看到我们得到了 kext 的 binary 和一份符号表，由于 kext 是从内核中分离的，与从 `dyld_shared_cache` 分离出 dylib 类似，有大量的外部地址无法正常解析，通过符号表或是在 kernelcache 中定位都可以帮助判断这些地址的含义和内容。

### 使用 jtool 分离 PRELINK_INFO
与 App 通过 Info.plist 描述关键信息类似，kext 也有其 Info.plist 来描述 kext 的各种信息，其中包含了标识符、加载地址等关键信息，为了方便分析，我们还需要从 kernelcache 中分离出 amfi 的 Info.plist。这里我们使用 jtool (http://www.newosxbook.com/tools/jtool.html) 来完成分离：

```bash
# 指定输出目录
export JTOOLDIR=/tmp/kext

# 分离 PRELINK_INFO
> jtool -e __PRELINK_INFO kernelcache
Requested segment found at offset 1e10000!
Extracting __PRELINK_INFO at 31522816, 2342912 (23c000) bytes into kernelcache.__PRELINK_INFO

# 查看产物
> ls .
com.apple.driver.AppleMobileFileIntegrity.kext
com.apple.driver.AppleMobileFileIntegrity.kext.ARM64.E815A4DD-90E7-3A38-A4BA-EFA2425BC543
kernelcache
kernelcache.__PRELINK_INFO
```

打开 `kernelcache.__PRELINK_INFO` 可以看到这里包含了大量被 prelink 到 kernelcache 中的 kext 的信息，在其中还混入了大量被 base64 编码的 Data Blob。

## 在 PRELINK_INFO 中查找关键信息
在 `kernelcache.__PRELINK_INFO` 中搜索 `<key>_PrelinkBundlePath</key><string>/System/Library/Extensions/AppleMobileFileIntegrity.kext</string>` 可以定位到 amfi.kext 的 Info.plist，这里包含了 amfi.kext 的一些关键信息：

```xml
<dict>
  <key>BuildMachineOSBuild</key>
  <string>18A391011</string>
  <key>_PrelinkExecutableLoadAddr</key>
  <integer ID="32" size="64">0xfffffff005ab1980</integer>
  <key>CFBundlePackageType</key>
  <string>KEXT</string>
  <key>_PrelinkExecutableSourceAddr</key>
  <integer IDREF="32"/>
  <key>CFBundleDevelopmentRegion</key>
  <string>English</string>
  <key>MinimumOSVersion</key>
  <string>13.1</string>
  <key>CFBundleVersion</key>
  <string>1.0.5</string>
  <key>DTXcodeBuild</key>
  <string>11L374m</string>
  <key>DTPlatformBuild</key>
  <string ID="33"/>
  <key>_PrelinkBundlePath</key>
  <string>/System/Library/Extensions/AppleMobileFileIntegrity.kext</string>
  <key>_PrelinkExecutableSize</key>
  <integer size="64">0x5211</integer>
  <key>_PrelinkKmodInfo</key>
  <integer size="64">0xfffffff0077e51c8</integer>
  <key>UIDeviceFamily</key>
  <array>
    <integer IDREF="10"/>
  </array>
  <key>OSBundleRequired</key>
  <string>Root</string>
  <key>CFBundleIdentifier</key>
  <string>com.apple.driver.AppleMobileFileIntegrity</string>
  <key>DTXcode</key>
  <string>1100</string>
  <key>CFBundleExecutable</key>
  <string IDREF="31"/>
</dict>
```

其中以 `_Prelink` 开头的字段非常重要：

```xml
<dict>
  <key>_PrelinkExecutableLoadAddr</key>
  <integer ID="32" size="64">0xfffffff005ab1980</integer>
  <key>_PrelinkExecutableSourceAddr</key>
  <integer ID="32" size="64">0xfffffff005ab1980</integer>
  <key>_PrelinkBundlePath</key>
  <string>/System/Library/Extensions/AppleMobileFileIntegrity.kext</string>
  <key>_PrelinkExecutableSize</key>
  <integer size="64">0x5211</integer>
  <key>_PrelinkKmodInfo</key>
  <integer size="64">0xfffffff0077e51c8</integer>
  <key>CFBundleIdentifier</key>
  <string>com.apple.driver.AppleMobileFileIntegrity</string>
</dict>
```

这些字段的含义如下[1]：
- _PrelinkExecutableSourceAddr: kext 的起始地址，即 kext 的 Mach-O Header 地址；
- _PrelinkExecutableLoadAddr: kext 在内存中的加载地址，对于 prelink kext 这个值一般等于 _PrelinkExecutableSourceAddr；
- _PrelinkKmodInfo: kext 在 Mach layer 的对象模型。

下面我们大致看一下这些地址的内容，首先是 _PrelinkExecutableSourceAddr，这里是 kext 的加载起点，可以看到这是一个标准的 Mach-O Header 结构：

![](https://user-gold-cdn.xitu.io/2020/7/5/1731e86472655284?w=1966&h=878&f=png&s=308513)

其次是 `_PrelinkKmodInfo`，它是一个 `kmod_info_t` 结构体:
```c
typedef struct kmod_info {
    struct kmod_info  * next;
    int32_t             info_version;       // version of this structure
    uint32_t            id;
    char                name[KMOD_MAX_NAME];
    char                version[KMOD_MAX_NAME];
    int32_t             reference_count;    // # linkage refs to this
    kmod_reference_t  * reference_list;     // who this refs (links on)
    vm_address_t        address;            // starting address
    vm_size_t           size;               // total size
    vm_size_t           hdr_size;           // unwired hdr size
    kmod_start_func_t * start;
    kmod_stop_func_t  * stop;
} kmod_info_t;
```

![](https://user-gold-cdn.xitu.io/2020/7/5/1731e87b751b972d?w=1896&h=472&f=png&s=133266)

## 猜测模块加载方式
以 user mode 的经验而言，这里的 Mach-O Header 中可能会包含类似于 `LC_MAIN` 的结构来标识 Entry Point，或是在 `kmod_info` 中的 start 和 stop 函数中会包含注册的关键逻辑。

遗憾的是，在 amfi.kext 的 Mach-O Header 中并没有 Entry Point，且 `kmod_info` 中的 start 和 stop 函数均为空实现，这就说明对于这类 prelink 的 kext 肯定有其他的加载方式有待探索。

# AppleMobileFileIntegrity.kext 的注册
经过一番分析和资料查阅我发现有关 kext 的加载逻辑已经被逐步移动到 libkern 中。维护 kext 的关键逻辑位于 `libkern/c++/OSKext.cpp` 中，与此同时在 user mode 可以通过 I/O Kit 完成与 kext 的交互[1]。

基于 I/O Kit 的 kext 被作为 drivers 挂载在 IO 设备树中，可通过 Mach messages 实现对 kext 的操作，例如通过 OSKextLoadKextWithIdentifier 来加载一个 kext：

```c
kern_return_t
OSKextLoadKextWithIdentifier(const char * bundle_id)
{
    return OSKext::loadKextWithIdentifier(bundle_id);
}
```

这里的关键逻辑是在一个全局注册表 sKextsByID 中找到对应的 OSKext 对象并执行 load 操作，那么问题的关键就转变为 kext 是如何被加入到 sKextsByID 中的。

前面我们提到了 prelink kexts 通过 `PRELINK_INFO` 来记录信息，在内核的 boot 阶段初始化 I/O Kit 时，`_start` -> `_start_first_cpu` -> `arm_init` -> `machine_startup` -> `kernel_bootstrap` -> `kernel_bootstrap_thread` ->  `PE_init_iokit` -> `StartIOKit` -> `bootstrapRecordStartupExtensions` -> `KLDBootstrap::readStartupExtensions` -> `readPrelinkedExtensions` -> `OSKext::withPrelinkedInfoDict` -> `OSKext::initWithPrelinkedInfoDict` 来根据 `PRELINK_INFO` 中的 Info 逐个加载 prelinked kext。

## 从启动到注册
下面我们就从 OSKext::initWithPrelinkedInfoDict 方法入手来研究 kext 的加载方式：
```c++
bool
OSKext::initWithPrelinkedInfoDict(
	OSDictionary * anInfoDict,
	bool doCoalesedSlides) {
    // ...
    addressNum = OSDynamicCast(OSNumber, anInfoDict->getObject("_PrelinkKmodInfo"));
    if (addressNum->unsigned64BitValue() != 0) {
        kmod_info = (kmod_info_t *) ml_static_slide((intptr_t) (addressNum->unsigned64BitValue()));
        kmod_info->address = ml_static_slide(kmod_info->address);
    }
    
    // ...
    flags.prelinked = true;
    sPrelinkBoot = true;
    result = registerIdentifier();
    
    // ...
    return result;
}
```
这里主要是对 kext 对应的 Info.plist 的处理，其中包括初始化 `kmod_info`, 设置 kext 的 binary 以及设置 kext flags 等，这里最关键的一步是通过 `registerIdentifier` 将自己添加到全局注册表：

```c++
bool
OSKext::registerIdentifier(void)
{
    // ...
    /* If we don't have an existing kext with this identifier,
     * just record the new kext and we're done!
     */
    existingKext = OSDynamicCast(OSKext, sKextsByID->getObject(bundleID));
    if (!existingKext) {
    	sKextsByID->setObject(bundleID, this);
    	result = true;
    	goto finish;
    }
    
    // ...
    return true;
}
```

这里的首次注册逻辑非常简单，就是将 kext 以 bundleID 为 key 加入到全局注册表 sKextsByID，这里省略了二次注册同一个 kext 的版本决议逻辑。

# AppleMobileFileIntegrity.kext 的加载
说完了注册，下面来看一下 prelinked kext 的加载。笔者刚开始一直觉得 amfi.kext 是基于 libKern 的 kext_request 加载的，多处寻找代码和 bundleID 的交叉引用未果，费解之际发现 prelinked kext 加载也藏在启动流程之中，加载和注册的桥梁是全局注册表 sKextsByID。

## 加载器的注入
我们之前在注册流程中提到，有一个从 `StartIOKit` -> `bootstrapRecordStartupExtensions` 的调用，在 StartIOKit 中对应的代码为：

```c++
void (*record_startup_extensions_function)(void) = NULL;

void
StartIOKit( void * p1, void * p2, void * p3, void * p4 ) {
    // ...
    /* If the bootstrap segment set up a function to record startup
     * extensions, call it now.
     */
    if (record_startup_extensions_function) {
    	record_startup_extensions_function();
    }
    // ...
}
```

这里的 `record_startup_extensions_function` 是在 KLDBootstrap 的构造函数中注入的：

```c++
/*********************************************************************
* Set the function pointers for the entry points into the bootstrap
* segment upon C++ static constructor invocation.
*********************************************************************/
KLDBootstrap::KLDBootstrap(void)
{
    if (this != &sBootstrapObject) {
    	panic("Attempt to access bootstrap segment.");
    }
    record_startup_extensions_function = &bootstrapRecordStartupExtensions;
    load_security_extensions_function = &bootstrapLoadSecurityExtensions;
}
```

`StartIOKit` 调用的 `record_startup_extensions_function` 实现即为注册流程中的 `bootstrapRecordStartupExtensions`，此外这里还为 `load_security_extensions_function` 注入了 `bootstrapLoadSecurityExtensions` 作为实现。这里的 `bootstrapLoadSecurityExtensions` 就是 kext 的加载逻辑，与注册逻辑 `bootstrapRecordStartupExtensions` 相对应。

## 加载器的 Caller
那么是谁负责调用 `bootstrapLoadSecurityExtensions` 来加载这些 kext 的呢？通过搜索代码我们可以找到位于 MAC 中的逻辑：

```c++
/* Function pointer set up for loading security extensions.
 * It is set to an actual function after OSlibkernInit()
 * has been called, and is set back to 0 by OSKextRemoveKextBootstrap()
 * after bsd_init().
 */
void (*load_security_extensions_function)(void) = 0;

/*
 * Init after early Mach startup, but before BSD
 */
void
mac_policy_initmach(void)
{
    /*
     * For the purposes of modules that want to know if they were
     * loaded "early", set the mac_late flag once we've processed
     * modules either linked into the kernel, or loaded before the
     * kernel startup.
     */
    
    if (load_security_extensions_function) {
    	load_security_extensions_function();
    }
    mac_late = 1;
}
```

这里的 MAC 全称是 Mandatory Access Control，它是基于 Trusted BSD 实现的一个更细粒度的操作系统安全模型，用于提供对象级的安全控制。而 `mac_policy_initmach` 的 Caller 为 `kernel_bootstrap_thread`：

```c++
/*
 * Now running in a thread.  Kick off other services,
 * invoke user bootstrap, enter pageout loop.
 */
static void
kernel_bootstrap_thread(void)
{
    // ...
#ifdef  IOKIT
    kernel_bootstrap_log("PE_init_iokit");
    PE_init_iokit();
#endif

    // ...
#if CONFIG_MACF
    kernel_bootstrap_log("mac_policy_initmach");
    mac_policy_initmach();
    // ...
}
```

可以看到这里的注册 `PE_init_iokit` 和加载 `mac_policy_initmach` 是先后调用的，从而保证 `mac_policy_initmach` 时能取到已经注册的 Security Kexts。

## 加载逻辑
前面提到加载逻辑位于 `bootstrapLoadSecurityExtensions` 中：

```c++
static void
bootstrapLoadSecurityExtensions(void)
{
    sBootstrapObject.loadSecurityExtensions();
    return;
}

void
KLDBootstrap::loadSecurityExtensions(void)
{
    // ...
    // OSKext::copyKexts()
    extensionsDict = OSDynamicCast(OSDictionary, sKextsByID->copyCollection());
    // ...
    keyIterator = OSCollectionIterator::withCollection(extensionsDict);
    // ...
    while ((bundleID = OSDynamicCast(OSString, keyIterator->getNextObject()))) {
        const char * bundle_id = bundleID->getCStringNoCopy();
        
        /* Skip extensions whose bundle IDs don't start with "com.apple.".
         */
        if (!bundle_id ||
            (strncmp(bundle_id, "com.apple.", CONST_STRLEN("com.apple.")) != 0)) {
        	continue;
        }
        
        theKext = OSDynamicCast(OSKext, extensionsDict->getObject(bundleID));
        if (!theKext) {
    	    continue;
        }
        
        if (kOSBooleanTrue == theKext->getPropertyForHostArch(kAppleSecurityExtensionKey)) {
    	    OSKext::loadKextWithIdentifier(bundleID->getCStringNoCopy(),
        	    /* allowDefer */ false);
        }
    }
    // ...
}
```

这里通过遍历 sKextsByID 执行 loadKextWithIdentifier 方法，后续会执行 `OSKext::load` -> `OSKext::loadExecutable` (register `kmod_info`) and `OSKext::start` -> `OSRuntimeInitializeCPP`。

其中 `OSKext::load` 中包含了注册到 IOKit，`OSRuntimeInitializeCPP` 完成了 libkern 的一些 C++ 环境初始化。

# AppleMobileFileIntegrity.kext 注册到 IOKit
## 注册与启动服务
我们先来看 load 阶段，在 `OSKext::load` 的函数最后包含了这样一段逻辑：

```c++
/* If not excluding matching, send the personalities to the kernel.
 * This never affects the result of the load operation.
 * This is a bit of a hack, because we shouldn't be handling
 * personalities within the load function.
 */
OSReturn
OSKext::load(
	OSKextExcludeLevel   startOpt,
	OSKextExcludeLevel   startMatchingOpt,
	OSArray            * personalityNames) 
{
    // ...
    if (result == kOSReturnSuccess && startMatchingOpt == kOSKextExcludeNone) {
        result = sendPersonalitiesToCatalog(true, personalityNames);
    }
    // ...
}
```

所谓 Personalities 即 IOKitPersonalities，用于描述驱动的特征以便 IOKit 能正确的加载和匹配服务。

`OSKext::sendPersonalitiesToCatalog` 随后会调用到 `gIOCatalogue->addDrivers(personalitiesToSend, startMatching)`，这里的 gIOCatalogue 是一个全局的 IOCatalogue 对象，它是一个所有 IOKIt 驱动 personalities 的数据库，IOKit 通过它来匹配相关服务[2]。

`gIOCatalogue->addDrivers` 随后会调用到 `IOService::catalogNewDrivers` -> `IOService::startMatching` -> `IOService::doServiceMatch`：

```c++
void
IOService::doServiceMatch( IOOptionBits options )
{
    // ...
    while (keepGuessing) {
    	matches = gIOCatalogue->findDrivers( this, &catalogGeneration );
        // the matches list should always be created by findDrivers()
        if (matches) {
            if (0 == (__state[0] & kIOServiceFirstPublishState)) {
                getMetaClass()->addInstance(this);
                // ...
            }
            
            if (keepGuessing && matches->getCount() && (kIOReturnSuccess == getResources())) {
                if ((this == gIOResources) || (this == gIOUserResources)) {
                    if (resourceKeys) {
                        resourceKeys->release();
                    }
                    resourceKeys = copyPropertyKeys();
                }
                probeCandidates( matches );
            }
            // ...
        }
    }
    // ...
}
```
这里的 `getMetaClass()->addInstance(this)` 和 `probeCandidates( matches )` 是两个关键调用，我们先来看前者：

```c++
/* Class global data */
OSObject::MetaClass OSObject::gMetaClass;

const OSMetaClass *
OSObject::getMetaClass() const
{
    return &gMetaClass;
}
```

这里的 gMetaClass 是一个 Class 维度的全局对象，addInstance 将 kext 的 IOService 实例添加到这个 Class 维度的列表上来关联类对象关联的所有 IOService 实例：

```c++
void
OSMetaClass::addInstance(const OSObject * instance, bool super) const
{
    if (!super) {
        IOLockLock(sInstancesLock);
    }
    
    if (!reserved->instances) {
        reserved->instances = OSOrderedSet::withCapacity(16);
        if (superClassLink) {
            superClassLink->addInstance(reserved->instances, true);
        }
    }
    reserved->instances->setLastObject(instance);
    
    if (!super) {
        IOLockUnlock(sInstancesLock);
    }
}
```

这里的 gMetaClass->reserved->instances 将用于 Service Matching 时获取到 amfi 对应的 IOService 实例。

接下来看一下 `probeCandidates( matches )` 这个调用，它会调用到 `IOService::startCandidate` -> `IOService::start`，从而完成 amfi 的 IOService 启动。

## AMFI 的启动流程
在 amfi.kext 中我们可以找到 `IOService::start` 启动方法：

```c++
bool __cdecl AMFI::start_IOService(uint64_t *a1)
{
  uint64_t *v1; // x19

  v1 = a1;
  if ( !(*((unsigned int (**)(void))IORegistryEntry::gMetaClass + 88))() )
    ((void (*)(void))loc_FFFFFFF006075D18)();
  initializeAppleMobileFileIntegrity();
  if ( *(_DWORD *)cs_debug )
    IOLog("%s: built %s %s\n", "virtual bool AppleMobileFileIntegrity::start(IOService *)", "Sep  3 2019", "22:15:18");
  (*(void (__fastcall **)(uint64_t *, _QWORD))(*v1 + 672))(v1, 0LL);
  return 1;
}
```

这里的核心初始化方法是 `initializeAppleMobileFileIntegrity`，其中包含了与 codesign 相关的 MAC Policy Module 与 Handler 的注册，这些 Handler 以切面的形式对特定系统调用进行校验，例如 `mpo_vnode_check_signature` 使用 in-kernel signature cache 和 amfid 进行文件的代码签名校验。有关 `initializeAppleMobileFileIntegrity` 的具体逻辑以及与 amfid 的交互方式我们将在下一篇文章中详细介绍。

## 初始化 libkern C++ 环境
```c++
kern_return_t
OSRuntimeInitializeCPP(
	OSKext                   * theKext)
{
    // ...
    /* Tell the meta class system that we are starting the load
	 */
    metaHandle = OSMetaClass::preModLoad(kmodInfo->name);
    
    // ...
    /* Scan the header for all constructor sections, in any
	 * segment, and invoke the constructors within those sections.
	 */
    for (segment = firstsegfromheader(header);
        segment != NULL && load_success;
        segment = nextsegfromheader(header, segment)) {
    	/* Record the current segment in the event of a failure.
    	 */
    	failure_segment = segment;
    	load_success = OSRuntimeCallStructorsInSection(
    		theKext, kmodInfo, metaHandle, segment,
    		sectionNames[kOSSectionNameInitializer],
    		textStart, textEnd);
    } /* for (segment...) */
    
    // ...
    /* Now, regardless of success so far, do the post-init registration
     * and cleanup. If we had to call the unloadCPP function, static
     * destructors have removed classes from the stalled list so no
     * metaclasses will actually be registered.
     */
    result = OSMetaClass::postModLoad(metaHandle);
    // ...
}
```

### Pre 阶段
这里的加载主要包含 3 个阶段，其中 pre 阶段主要是为了准备 kext 的 Main Class 的加载上下文，这里的上下文通过一个全局变量保存，并通过一个锁保证串行队列：

```c++
/*
 * While loading a kext and running all its constructors to register
 * all OSMetaClass classes, the classes are queued up here. Only one
 * kext can be in flight at a time, guarded by sStalledClassesLock
 */
static struct StalledData {
    const char   * kextIdentifier;
    OSReturn       result;
    unsigned int   capacity;
    unsigned int   count;
    OSMetaClass ** classes;
} * sStalled;
IOLock * sStalledClassesLock = NULL;

void *
OSMetaClass::preModLoad(const char * kextIdentifier)
{
    IOLockLock(sStalledClassesLock);
    
    assert(sStalled == NULL);
    sStalled = (StalledData *)kalloc_tag(sizeof(*sStalled), VM_KERN_MEMORY_OSKEXT);
    if (sStalled) {
    	sStalled->classes = (OSMetaClass **)kalloc_tag(kKModCapacityIncrement * sizeof(OSMetaClass *), VM_KERN_MEMORY_OSKEXT);
    	if (!sStalled->classes) {
            kfree(sStalled, sizeof(*sStalled));
            return NULL;
    	}
    	OSMETA_ACCUMSIZE((kKModCapacityIncrement * sizeof(OSMetaClass *)) +
    	    sizeof(*sStalled));
    
    	sStalled->result   = kOSReturnSuccess;
    	sStalled->capacity = kKModCapacityIncrement;
    	sStalled->count    = 0;
    	sStalled->kextIdentifier = kextIdentifier;
    	bzero(sStalled->classes, kKModCapacityIncrement * sizeof(OSMetaClass *));
    }
    
    // keep sStalledClassesLock locked until postModLoad
    
    return sStalled;
}
```

### In 阶段
随后的代码通过 `OSRuntimeCallStructorsInSection` 扫描了 kext 中所有的 `__mod_init_func` sections 并调用这些初始化函数，这里我们可以打开 IDA 查看 `__mod_init_func` 包含了哪些初始化函数：

```
__mod_init_func:FFFFFFF006DF41A0 ; Segment type: Pure data
__mod_init_func:FFFFFFF006DF41A0   AREA __mod_init_func, DATA, ALIGN=3
__mod_init_func:FFFFFFF006DF41A0 ; ORG 0xFFFFFFF006DF41A0
__mod_init_func:FFFFFFF006DF41A0   DCQ InitFunc_0
__mod_init_func:FFFFFFF006DF41A8   DCQ InitFunc_1
__mod_init_func:FFFFFFF006DF41B0   DCQ InitFunc_2
__mod_init_func:FFFFFFF006DF41B0 ; __mod_init_func ends
```

可见在 amfi.kext 中共包含了 3 个初始化函数，其中 `InitFunc_1` 是一些全局变量的初始化函数，`InitFunc_0` 和 `InitFunc_2` 是 AMFI 的一些 Main Class 的初始化函数，我们这里重点看一下 `InitFunc_2`：

```
_QWORD *InitFunc_2()
{
    _QWORD *result; // x0
    result = (_QWORD *)OSMetaClass::OSMetaClass(&some_this, "AppleMobileFileIntegrity", some_inSuperClass, 136LL);
    *result = some_vtable;
    return result;
}
```

这里的 `OSMetaClass::OSMetaClass` 是类的核心构造方法，它实际上是将类加到 OSMetaClass 全局上下文 `sStalled->classes` 中以便 post 流程中使用，这里省略了当 classes 列表的 Grow 逻辑：

```c++
/*********************************************************************
* The core constructor for a MetaClass (defined with this name always
* but within the scope of its represented class).
*
* MetaClass constructors are invoked in OSRuntimeInitializeCPP(),
* in between calls to OSMetaClass::preModLoad(), which sets up for
* registration, and OSMetaClass::postModLoad(), which actually
* records all the class/kext relationships of the new MetaClasses.
*********************************************************************/

OSMetaClass::OSMetaClass(
	const char        * inClassName,
	const OSMetaClass * inSuperClass,
	unsigned int        inClassSize)
{
    // ...
    sStalled->classes[sStalled->count++] = this;
    // ...
}
```

### Post 阶段 
post 阶段主要是维护 kext 与 classes 的关系：

```c++
OSReturn
OSMetaClass::postModLoad(void * loadHandle)
{
    // ...
    // static OSDictionary * sAllClassesDict;
    sAllClassesDict = OSDictionary::withCapacity(kClassCapacityIncrement);
    sAllClassesDict->setOptions(OSCollection::kSort, OSCollection::kSort);
    myKextName = const_cast<OSSymbol *>(OSSymbol::withCStringNoCopy(
				    sStalled->kextIdentifier));
    myKext = OSKext::lookupKextWithIdentifier(myKextName);
    
    /* First pass checking classes aren't already loaded. If any already
     * exist, we don't register any, and so we don't technically have
     * to do any C++ teardown.
     *
     * Hack alert: me->className has been a C string until now.
     * We only release the OSSymbol if we store the kext.
     */
    IOLockLock(sAllClassesLock);
    for (unsigned int i = 0; i < sStalled->count; i++) {
        const OSMetaClass * me = sStalled->classes[i];
        
        unsigned int depth = 1;
        while ((me = me->superClassLink)) {
            depth++;
        }
        
        // static unsigned int sDeepestClass;
        if (depth > sDeepestClass) {
            sDeepestClass = depth;
        }
    }
    IOLockUnlock(sAllClassesLock);
    
    IOLockLock(sAllClassesLock);
    for (unsigned int i = 0; i < sStalled->count; i++) {
        const OSMetaClass * me = sStalled->classes[i];
        OSMetaClass * me = sStalled->classes[i];
        me->className = OSSymbol::withCStringNoCopy((const char *)me->className);
        sAllClassesDict->setObject(me->className, me);
        me->reserved->kext = myKext;
        myKext->addClass(me, sStalled->count);
    }
    IOLockLock(sAllClassesLock);
    
    sBootstrapState = kCompletedBootstrap;
    sStalled = NULL;
    return kOSReturnSuccess;
}
```

完成 post 流程后，kext 的所有 OSMetaClass 实例就被以 name2instance 的形式记录在全局注册表 sAllClassesDict 之中了，同时每个 OSMetaClass 实例 还维护了 instance2kext 的对应关系 (me->reserved->kext = myKext)，每个 kext 又维护了里属于他的所有 instance (myKext->addClass(me, sStalled->count))。这就保证了可以通过 class name 找到实例，又可以通过实例找到对应的 OSKext 对象，而通过 OSKext 对象也可以获得隶属于它的所有 OSMetaClass 实例。

# 获取 AppleMobileFileIntegrity.kext 服务
我们在 kernelcache 中搜索 "AppleMobileFileIntegrity" 字符串的交叉引用不难找到通过 IOService 访问 AMFI 服务的代码，例如 `com.apple.security.sandbox` 中的 `initAMFI`:

```c++
__int64 initAMFI()
{
  OSDictionary *matchDict_1; // x0
  OSDictionary *v1; // x19
  IOService *v2; // x0
  __int64 v4; // x0
  __int64 matchDict; // [xsp+8h] [xbp-18h]

  matchDict = 0LL;
  matchDict_1 = (OSDictionary *)IOService::nameMatching("AppleMobileFileIntegrity", 0LL);
  // ...
  v1 = matchDict_1;
  v2 = IOService::waitForMatchingService(matchDict_1, 0xFFFFFFFFFFFFFFFFLL);
  matchDict = OSMetaClassBase::safeMetaCast(v2, *(_QWORD *)qword_FFFFFFF006F9D038);
  // ...
}
```

这里先使用 IOService::nameMatching 构造了一个 OSDictionary:

```c++
{
    "IONameMatch": "AppleMobileFileIntegrity"
}
```

随后通过 `IOService::waitForMatchingService` 匹配服务，核心逻辑梳理如下：

```c++
IOService *
IOService::waitForMatchingService( OSDictionary * matching,
    uint64_t timeout) {
    // ...
    do {
    	result = (IOService *) copyExistingServices( matching,
    	    kIOServiceMatchedState, kIONotifyOnce );
    	// ...
}

OSObject *
IOService::copyExistingServices( OSDictionary * matching,
    IOOptionBits inState, IOOptionBits options ) {
    // ...
    IOServiceMatchContext ctx;
    ctx.table   = matching;
    ctx.state   = inState;
    ctx.count   = 0;
    ctx.done    = 0;
    ctx.options = options;
    ctx.result  = NULL;
    
    IOService::gMetaClass.applyToInstances(instanceMatch, &ctx);
    // ...
}

void
OSMetaClass::applyToInstances(OSMetaClassInstanceApplierFunction applier,
    void * context) const
{
    IOLockLock(sInstancesLock);
    if (reserved->instances) {
        applyToInstances(reserved->instances, applier, context);
    }
    IOLockUnlock(sInstancesLock);
}
```

可以看到最后是通过遍历 IOService::gMetaClass.reserved->instances 中的所有 IOService 实例实现匹配的，而 IOService::gMetaClass.reserved->instances 正好是我们在 `OSKext::load` -> `OSKext::sendPersonalitiesToCatalog` 阶段所注册的。 

# 总结
到这里，整个 Prelinked Kext 的注册、加载、启动和获取流程就讲完了。为了更好地研究代码签名机制，笔者首先分析了 amfid 的工作机制，随后分析了 AMFI.kext 与 amfid 的交互逻辑，再到 AMFI.kext 的加载。分析整个加载机制耗费了非常多的时间，这篇文章算是一个复盘。在接下来的文章中将重点分析 AMFI 注册的 MAC Policy Module 及其工作机制，这里面将涉及到更加复杂的逻辑。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>


# 参考资料
1. [Jonathan Levin: Mac OS X and iOS Internals: To the Apple's Core](https://www.amazon.com/Mac-OS-iOS-Internals-Apples/dp/1118057651)
2. [Apple: Darwin-XNU-6153.11.26](https://opensource.apple.com/source/xnu/xnu-6153.11.26/)