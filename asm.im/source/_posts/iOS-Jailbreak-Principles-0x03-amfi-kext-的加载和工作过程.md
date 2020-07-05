---
title: iOS Jailbreak Principles 0x03 - amfi.kext 的加载和工作过程
date: 2020-07-05 19:20:06
tags:
---

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

# AppleMobileFileIntegrity.kext 的加载
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

## OSKext 的注册
前面我们提到了 prelink kexts 通过 `PRELINK_INFO` 来记录信息，在内核的 boot 阶段初始化 I/O Kit 时，会调用到 KLDBootstrap::readStartupExtensions -> readPrelinkedExtensions -> OSKext::withPrelinkedInfoDict -> initWithPrelinkedInfoDict 来根据 `PRELINK_INFO` 中的 Info 逐个加载 prelinked kext。下面我们来分析 OSKext::initWithPrelinkedInfoDict 方法来研究 kext 的加载方式。


# 参考资料
1. [Jonathan Levin: Mac OS X and iOS Internals: To the Apple's Core](https://www.amazon.com/Mac-OS-iOS-Internals-Apples/dp/1118057651)