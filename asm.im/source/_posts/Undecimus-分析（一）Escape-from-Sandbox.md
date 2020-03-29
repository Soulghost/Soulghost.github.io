---
title: Undecimus 分析（一）Escape from Sandbox
date: 2019-12-15 21:00:00
tags: ['JailBreak', 'Undecimus', 'Sandbox Escape']
---

# 系列文章
1. [iOS Jailbreak Principles - Sock Port 漏洞解析（一）UAF 与 Heap Spraying](https://juejin.im/post/5dd10660e51d453fac0a598d)
2. [iOS Jailbreak Principles - Sock Port 漏洞解析（二）通过 Mach OOL Message 泄露 Port Address](https://juejin.im/post/5dd918d051882573180a2ba7)
3. [iOS Jailbreak Principles - Sock Port 漏洞解析（三）IOSurface Heap Spraying](https://juejin.im/post/5de37a236fb9a071b5615dea)
4. [iOS Jailbreak Principles - Sock Port 漏洞解析（四）The tfp0 !](https://juejin.im/post/5dec7f2f6fb9a0160c411516)

# 前言
在 Sock Port 系列文章中我们从 0 到 1 的介绍了通过 Socket UAF 拿到 tfp0 的全过程。从这篇文章开始我们将通过分析 [Undecimus](https://github.com/pwn20wndstuff/Undecimus) 介绍从 tfp0 到 jailbreak 的全过程。

单单通过 tfp0 能做的事情只是 kread, kwrite 等基础操作，要实现 rootfs read/write, kexec 等工作还需要非常复杂的步骤，本文将介绍通过 tfp0 逃出沙盒，实现 rootfs 读写的原理和过程。

# The Sandbox
在 iOS 中有两个重要的内核扩展，分别是 `AppleMobileFileIntegrity.kext` 和 `Sandbox.kext`。

## Apple Mobile File Integrity
根据 The iPhone Wiki 对 AMFI 的定义[1]:
> AppleMobileFileIntegrity(.kext), which can go by its full name com.apple.driver.AppleMobileFileIntegrity, is an iOS kernel extension which serves as the corner stone of iOS's code entitlements model. It is one of the Sandbox's (com.apple.security.sandbox) dependencies, along with com.apple.kext.AppleMatch (which, like on OS X, is responsible for parsing the Sandbox language rules).

即 `AMFI.kext` 是实现 `iOS Code Entitlements` 的基础组件，它和 `AppleMatch.kext`(用于解析 Sandbox DSL) 都是 `Sandbox.kext` 的依赖。

可能有人对 Entitlements 并不熟悉，它代表着 App 拥有的权限。在正向开发中，如果我们为 App 开启 Capability 就会生成对应的 XML Units 插入到 `App.entitlements`，某些 Capability 只有特定的证书才能生成合法签名。通过这种手段可以限制 Userland App 的权限，从而保证系统安全。

在运行时，内核扩展会注册 Mac Policy 并 hook 特定的 Mach Calls[1]:
> Affectionately known as AMFI, this kext can be found in the iOS 5.0 iPod 4,1 kernel around 0x805E499C (start) and 0x805E3EE8 (Initialization function). The latter function registers a MAC policy (using the kernel exported mac_policy_register), which is used to hook various system operations and enforce Apple's tight security policy.

根据 Wiki，AMFI 会 hook 需要 `task_for_pid-allow` 权限的 Mach Call[1]:
> This kext recognizes the task_for_pid-allow entitlement (among others) and is responsible for hooking this Mach call, which retrieves the Mach task port associated with a BSD process identifier. Given this port, one can usurp control of the task/PID, reading and writing its memory, debugging, etc. It is therefore enabled only if the binary is digitally signed with a proper entitlement file, specifying task_for_pid-allow.

即 `AMFI.kext` 会识别 entitlements 中的 `task_for_pid-allow`，并 Hook 相关 Mach Call，该 Mach Call 会通过 BSD 进程标识符查询特定进程的任务端口返回给调用者，使得调用者可以篡改进程的 task 或 PID, 甚至进行目标进程内存的读写和调试；而 `AMFI.kext` 会在调用前检查调用者的二进制是否拥有包含 `task_for_pid-allow` 的合法签名。

## Sandbox Kext
Sandbox 的实现与 `AMFI.kext` 类似，也是通过 Hook 一系列的 Mach Call 并检查特定的 Policy 来保证访问的合法性。根据 Dionysus Blazakis 的 Paper: The Apple Sandbox 中的描述[2]：
> Once the sandbox is initialized, function calls hooked by the TrustedBSD layer will pass
through Sandbox.kext for policy enforcement. Depending on the system call, the extension
will consult the list of rules for the current process. Some rules (such as the example given
above denying access to files under the /opt/sekret path) will require pattern matching
support. Sandbox.kext imports functions from AppleMatch.kext to perform regular expression matching on the system call argument and the policy rule that is being checked.
For example, does the file being read match the denied path /opt/sekret/.*? The other
small part of the system is the Mach messages used to carry tracing information (such as
which operations are being checked) back to userspace for logging.

上述引用主要包含了 3 个关键点：
1. 当 Sandbox 被初始化后，被 TrustedBSD layer 所 Hook 的 Mach Call 会通过 `Sandbox.kext` 执行权限检查；
2. `Sandbox.kext` 会通过 `AppleMatch.kext` 解析规则 DSL，并生成 checklist；
3. 通过 checklist 进行检查，例如被读取的 file path 是否在 denied path 列表中等。

# Policy 的内核表示
在进程的 proc 结构中有一个 p_ucred 成员用于存储进程的 Identifier (Process owner's identity. (PUCL))，它相当于进程的 Passport：
```c
struct proc {
    LIST_ENTRY(proc) p_list; /* List of all processes. */
    
    void * task; /* corresponding task (static)*/
    struct proc *p_pptr; /* Pointer to parent process.(LL) */
    pid_t p_ppid;	
    // ...
    /* substructures: */
    kauth_cred_t p_ucred; /* Process owner's identity. (PUCL) */
```

PUCL 是一个 ucred 对象：
```c
struct ucred {
    TAILQ_ENTRY(ucred) cr_link; /* never modify this without KAUTH_CRED_HASH_LOCK */
    u_long cr_ref; /* reference count */
    // ..
    struct label *cr_label; /* MAC label */
```

其中 `cr_label` 成员指向了存储 MAC Policies 的数据结构 `label`:
```c
struct label {
    int	l_flags;
    union {
    	void	*l_ptr;
    	long	 l_long;
    } l_perpolicy[MAC_MAX_SLOTS];
};
```

`l_perpolicy` 数组记录了 MAC Policy 列表，AMFI 和 Sandbox 的 Policy 都会插入到相应进程的 `l_perpolicy` 中。

根据 Quarkslab Blogs 中的文章 [Modern Jailbreaks' Post-Exploitation](https://blog.quarkslab.com/modern-jailbreaks-post-exploitation.html)，AMFI 和 Sandbox 分别插入到了 0 和 1 位置[3]：
> Each l_perpolicy "slot" is used by a particular MACF module, the first one being AMFI and the second one the sandbox. LiberiOS calls ShaiHulud2ProcessAtAddr to put 0 in its second label l_perpolicy[1]. Being the label used by the sandbox (processed in the function sb_evaluate), this move will neutralize it while keeping the label used by AMFI (Apple Mobile File Integrity) l_perpolicy[0] untouched (it's more precise and prevent useful entitlement loss).

即每个 `l_perpolicy` 插槽都被用于特定的 MACF 模块，第一个插槽被用于 AMFI，第二个被用于 Sandbox。LiberiOS 通过调用 `ShaiHulud2ProcessAtAddr` 在不修改第一个插槽的情况下将第二个插槽的指针置 0 来实现更加精准和稳定的沙盒逃逸。

# Escape Now
有了 tfp0 和上面的理论基础，实现沙盒逃逸的路径变得清晰了起来，我们只需要将当前进程的 `l_perpolicy[1]` 修改为 0，即可逃出沙盒。

首先读取到当前进程的 label，路径为 `proc->p_ucred->cr_label`，随后将索引为 1 的 Policy Slot 置 0：
```c
#define KSTRUCT_OFFSET_PROC_UCRED 0xf8
#define KSTRUCT_OFFSET_UCRED_CR_LABEL 0x78

kptr_t swap_sandbox_for_proc(kptr_t proc, kptr_t sandbox) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    _assert(KERN_POINTER_VALID(ucred));
    kptr_t const cr_label = ReadKernel64(ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
    _assert(KERN_POINTER_VALID(cr_label));
    kptr_t const sandbox_addr = cr_label + 0x8 + 0x8;
    kptr_t const current_sandbox = ReadKernel64(sandbox_addr);
    _assert(WriteKernel64(sandbox_addr, sandbox));
    ret = current_sandbox;
out:;
    return ret;
}
```

这里说明一下 `sandbox_addr` 的计算：
```c
kptr_t const sandbox_addr = cr_label + 0x8 + 0x8;
```
我们再回顾下 label 结构体：
```c
struct label {
    int	l_flags;
    union {
    	void	*l_ptr;
    	long	 l_long;
    } l_perpolicy[MAC_MAX_SLOTS];
};
```
虽然 `l_flags` 本身只有 4 字节，但 `l_perpolicy` 占据了 8n 字节，为了按照最大成员对齐，`l_flags` 也会占据 8B，因此 `cr_label + 8` 指向了 `l_perpolicy`，再偏移 8B 则指向 Sandbox 的 Policy Slot。

通过上述操作我们便能躲过 `Sandbox.kext` 对进程的沙盒相关检查，实现沙盒逃逸，接下来无论是通过 C 还是 OC 的 File API 都可以对 rootfs 进行读写。在 Undecimus Jailbreak 中以这种方式读取了 kernelcache 并确定 Kernel Slide 和关键偏移量。

我们可以通过简单实验验证沙盒逃逸成功，下面的代码读取了 kernelcache 和 Applications 目录：
```objc
NSArray *extractDir(NSString *dirpath) {
    NSError *error = nil;
    NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dirpath error:&error];
    if (error) {
        NSLog(@"failed to get application list");
        return nil;
    }
    return contents;
}

void sandbox_escape_test() {
    NSError *error = nil;
    BOOL success = [NSData dataWithContentsOfFile:@"/System/Library/Caches/com.apple.kernelcaches/kernelcache" options:NSDataReadingMappedAlways error:&error];
    if (!success) {
        NSLog(@"error occurred !!! %@", error);
    }
    
    // list applications dir
    error = nil;
    NSFileManager *mgr = [NSFileManager defaultManager];
    NSString *applicationRoot = @"/var/containers/Bundle/Application/";
    NSArray *uuids = [mgr contentsOfDirectoryAtPath:applicationRoot error:&error];
    if (error) {
        NSLog(@"failed to get application list");
        return;
    }
    for (NSString *uuid in uuids) {
        NSString *appPath = [applicationRoot stringByAppendingPathComponent:uuid];
        NSArray *contents = extractDir(appPath);
        for (NSString *content in contents) {
            if ([content hasSuffix:@".app"]) {
                NSLog(@"find %@ at %@ !!!", content, appPath);
            }
        }
    }
}
```

# 总结
本文简单介绍了通过 tfp0 实现 Sandbox Escape 的原理和过程，使得读者对 tfp0 能做的事情有一个简单认识。在接下来的文章中我们会介绍基于 tfp0 的 kexec 等利用。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>

# 参考资料
1. [AppleMobileFileIntegrity. The iPhone Wiki. ](https://www.theiphonewiki.com/wiki/AppleMobileFileIntegrity)
2. [The Apple Sandbox. Dionysus Blazakis. January 11, 2011.](https://dl.packetstormsecurity.net/papers/general/apple-sandbox.pdf)
3. [Modern Jailbreaks' Post-Exploitation. Marwan Anastas](https://blog.quarkslab.com/modern-jailbreaks-post-exploitation.html)
