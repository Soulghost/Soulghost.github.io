---
title: iOS Jailbreak Principles 0x02 - codesign and amfid bypass
date: 2020-06-14 18:28:18
tags:
---

# 系列文章
1. [iOS Jailbreak Principles - Undecimus 分析（一）Escape from Sandbox](https://juejin.im/post/5df5f6416fb9a016402d1cc0)
2. [iOS Jailbreak Principles - Undecimus 分析（二）通过 String XREF 定位内核数据](https://juejin.im/post/5e087dbd51882549757e5be2)
3. [iOS Jailbreak Principles - Undecimus 分析（三）通过 IOTrap 实现内核任意代码执行](https://juejin.im/post/5e1ac76d51882520c02c82c0)
4. [iOS Jailbreak Principles - Undecimus 分析（四）绕过 A12 的 PAC 实现 kexec](https://juejin.im/post/5e415da86fb9a07c9a194f3b)
5. [iOS Jailbreak Principles 0x01 - rootfs remount r/w 原理](https://juejin.im/post/5e8ad7ccf265da47b1778e17)

# 前言
通过之前的文章我们介绍了从内核漏洞到 tfp0，再到根文件系统可读写的原理。单纯一个可读写的 rootfs 能做的事情还是非常有限的，为了能做更多事情我们往往要控制系统的 binary 或是分发自己的 binary 到系统。

为了能将自己或他人编写的 binary 在 iOS 上跑起来，我们必须越过代码签名这道大山。iOS 仅仅包含了有限的 binary 和系统级 App，他们的签名被 hardcode 在一份静态的 TrustCache 中，对于我们自己部署的 binary，例如用于修改密码的 passwd，以及用于 SSH 服务的 bash 和 dropbear，默认情况下是无法启动的，会被 amfid 直接 kill 掉。

# Codesign Chain
在 iOS 中，当运行一个 binary 时，系统会以责任链模式从多个角度检查代码签名，自 iOS 12 以后，整个代码签名主要包含三个部分：
1. TrustCache: 一份 binary cdhash 的缓存，分为 static cache 和 dynamic cache 两部分，当 binary 的 cdhash 命中时直接放行；
2. CoreTrust: 内核基于 Apple 根证书对 binary 签名的合法性校验；
3. AMFI：即 MobileFileIntegrity，它会比对 binary 签名中存储的 cdhash 和 binary 实际 cdhash 是否相符。

## TrustCache
Trustcache 本质上是 cdhash 的线性表，当 binary 执行时，系统首先计算出 binary 的 cdhash，随后对 TrustCache 进行二分查找，如果命中则直接放行。在 iOS 的 image 中包含了一份静态的 trustcache 用于加速系统 binary 的执行。

除去静态 trustcache 外，系统还会维护一份动态的 trustcache，用于处理 Xcode 为设备安装调试必须的 binary 的签名问题[1]。**这其实是我们 bypass codesign 的一个简单方案**。

## CoreTrust
它主要保证了 binary 签名的合法性，即签名所使用的证书是由 Apple 根证书所签发的，这一机制使得非法签名和无签名的 binary 无法通过校验。

## AMFI
如果 binary 未命中又通过了 CoreTrust 检查后（这里不考虑 CoreTrust Cache），就会将消息送达 AMFI 进行真正的 codesign 检查，这里的核心是通过 MISValidateSignatureAndCopyInfo 方法对 binary 的实际 cdhash 和签名中的 cdhash 进行验证。

# 绕过思路
通过上面的讨论我们知道整个 codesign 责任链主要的三环：
```
TrustCache (static + dynamic cache lookup) → 
CoreTrust (deny fake signs, must sign with certs from apple) → 
AMFI (cdhash check)
```

## TrustCache Poisoning
最简单的方案就是篡改 dynamic TrustCache，我们首先通过 XREF 定位到 dynamic TrustCache 的全局变量，它是一个链表，链表的每一个结点都存储了一个或多个 binary 的 cdhash，且这些 cdhash 是以字典序升序排列的（用于支持二分查找）。

我们只需要找到 dynamic cache 的全局变量，为这个链表增加一个结点即可。这个在 rootlessJB 的 write-up[1] 以及各种开源 jailbreak 中有详细的论述和代码，主要的入手点在 `pmap_lookup_in_loaded_trust_caches`，本文不展开。

## CoreTrust Bypass
在 rootlessJB 的 write-up 中提到 binary 在 CoreTrust 的校验也包含了一个基于 generation count 的缓存，但为了构造出合法的缓存可能需要模拟 XNU 中构造 cs_blob 的过程随后再设置一个合法的 generation count。这种方式虽然跳过了 AMFI，但较为复杂，并且向后兼容能力较差。

## AMFI Bypass
AMFI 以 Mach Service 的形式提供对 codesign 的服务支持，既然是 C/S 架构，那么一个简单的方法就是伪造一个合法的响应，既然我们已经有了 tfp0，一个很直接的想法就是劫持 AMFI 的相关逻辑，并返回签名合法的消息。

本文将主要介绍 AMFI Bypass 的分析过程以及实施手段。

# How to Debug AMFI
在 iOS 11 以后，单纯给 debugserver 签上 `platform-application`, `task_for_pid-allow` 和 `com.apple.system-task-ports` 是依然无法 attach 到 system binary 的，因此默认情况下我们就无法调试 amfid。

为了能调试 system binary，我们必须在 spawn debugserver 时为它的 task 增加 `TF_PLATFORM` flag，其次为了断点能正常工作，我们需要为它的 proc 增加 `CS_DEBUGGED` flag：
```c
static bool patch_proc(uint64_t proc) {
    printf("[*] patch proc 0x%llx", proc);
    uint64_t our_task = rk64(proc + 0x10);
    printf("[*] find our task at 0x%llx\n", our_task);
    
    uint32_t our_flags = rk32(our_task + 0x3B8);
    wk32(our_task + 0x3B8, our_flags | 0x00000400);
    printf("[+] give us TF_PLATFORM\n");

    uint32_t our_csflags = rk32(proc + 0x298);
    our_csflags = our_csflags | CS_DEBUGGED | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW;
    our_csflags = our_csflags & ~(CS_HARD | CS_KILL | CS_RESTRICT);
    wk32(proc + 0x298, our_csflags);
    printf("[+] give us CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW\n");
    printf("[+] unrestrict our proc\n");
    return true;
}
```

这里需要用到 spawnAndPlatformize 的技术，这个技术包含在 QiLin ToolKit 中但没有开源，缺乏对 iOS 13 的支持，我们可以转而采用 jakeajames 开源在 rootlessJB 中的方法[3]：
```c
int launchAsPlatform(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    int rv = posix_spawn(&pd, binary, NULL, &attr, (char **)&args, env);
    
    platformize(pd);
    
    kill(pd, SIGCONT); //continue
    
    if (!rv) {
        int a;
        waitpid(pd, &a, 0);
    }
    
    return rv;
}
```

# AMFI 分析
笔者这里以 iOS 13.1.1 的 iPad Air 2 为样本分析，我们可以从 iOS 设备的 `/usr/libexec/amfid` 找到 amfid binary，将它进行反编译后，我们从 main 入手分析：

```c
void __fastcall __noreturn start(int a1, char **a2)
{
  char **argv; // x19
  int argc; // w20
  signed int v4; // w8
  signed int v5; // w22
  int hasDFlag; // w0
  __int64 v7; // x0
  void *v8; // x8
  int v9; // w1
  int v10; // w21
  int *v11; // x0
  char *v12; // x0
  const char *v13; // x1
  mach_port_t server_port; // [xsp+14h] [xbp-2Ch]
  struct dispatch_source_s *context; // [xsp+18h] [xbp-28h]
  dispatch_object_t v16; // 0:x0.8
  dispatch_object_t v17; // 0:x0.8

  argv = a2;
  argc = a1;
  v4 = 0;
  context = (struct dispatch_source_s *)-6148914691236517206LL;
  do
  {
    v5 = v4;
    hasDFlag = getopt(argc, argv, "d");
    v4 = 1;
  }
  while ( hasDFlag == 100 );
  if ( hasDFlag == -1 )
  {
    v7 = os_log_create("com.apple.MobileFileIntegrity", "amfid");
    v8 = &_os_log_default;
    if ( v7 )
      v8 = (void *)v7;
    amfi_logger = v8;
    if ( v5 )
      v9 = 33;
    else
      v9 = 1;
    if ( v5 )
      v10 = 255;
    else
      v10 = 63;
    openlog("amfid", v9, 24);
    setlogmask(v10);
    syslog(6, "starting");
    server_port = 0;
    if ( bootstrap_check_in(bootstrap_port, "com.apple.MobileFileIntegrity", &server_port) )
    {
      v11 = __error();
      v12 = strerror(*v11);
      syslog(3, "unable to checkin with launchd: %s", v12);
    }
    if ( server_port )
    {
      v16._do = dispatch_source_create(
                  (dispatch_source_type_t)&_dispatch_source_type_mach_recv,
                  server_port,
                  0LL,
                  (dispatch_queue_t)&_dispatch_main_q);
      context = v16._do;
      if ( v16._do )
      {
        dispatch_set_context(v16, &context);
        dispatch_source_set_event_handler_f(context, (dispatch_function_t)amfi_server_port_event_handler);
        v17._do = context;
        dispatch_resume(v17);
        dispatch_main();
      }
      v13 = "could not create mig source";
    }
    else
    {
      v13 = "could not get mach port";
    }
    syslog(3, v13);
    exit(1);
  }
  fprintf(__stderrp, "unrecognized argument '%c'\n", (unsigned int)optopt);
  exit(1);
}
```

这是一个 LaunchDaemon 的标准操作，通过 `bootstrap_port` 获取自己的 service port 并监听，重点看这一句：
```c
dispatch_source_set_event_handler_f(context, (dispatch_function_t)amfi_server_port_event_handler);
```

这里我们得到了 server port 的 hander，我们跳转到 handler 进行分析：
```c
__int64 __fastcall amfi_server_port_event_handler(_QWORD *a1)
{
  _QWORD *v1; // x20
  __int64 v2; // x19
  __int64 v3; // x0

  v1 = a1;
  syslog(7, "%s: enter", "mig_source_handler");
  v2 = os_transaction_create("amfid mig server");
  v3 = dispatch_mig_server(*v1, 4184LL, amfi_mig_server_handler);
  if ( (_DWORD)v3 )
    syslog(3, "%s: dispatch_mig_server returned %d", "mig_source_handler", v3);
  syslog(7, "%s: exit", "mig_source_handler");
  return _os_release(v2);
```

可以看到这里包含了一个 mig server 的 handler，我们继续向下分析：
```c
signed __int64 __fastcall amfi_mig_server_handler(_DWORD *a1, __int64 a2)
{
  int v2; // w8
  int v3; // w8
  unsigned int some_index; // w8
  void (__cdecl *v5)(_DWORD *, __int64); // x8
  signed __int64 result; // x0

  *(_DWORD *)a2 = *a1 & 0x1F;
  v2 = a1[2];
  *(_DWORD *)(a2 + 4) = 36;
  *(_DWORD *)(a2 + 8) = v2;
  v3 = a1[5] + 100;
  *(_DWORD *)(a2 + 16) = 0;
  *(_DWORD *)(a2 + 20) = v3;
  *(_DWORD *)(a2 + 12) = 0;
  some_index = a1[5] - 1000;
  if ( some_index <= 4
    && (v5 = (void (__cdecl *)(_DWORD *, __int64))*(&off_100004090 + 5 * (signed int)some_index + 5)) != 0LL )
  {
    v5(a1, a2);
    result = 1LL;
  }
  else
  {
    result = 0LL;
    *(NDR_record_t *)(a2 + 24) = NDR_record;
    *(_DWORD *)(a2 + 32) = -303;
  }
  return result;
}
```

这里包含了一个 dispatch table，且 off_100004090 是跳转表的头部：
```c
some_index = a1[5] - 1000;
if ( some_index <= 4
&& (v5 = (void (__cdecl *)(_DWORD *, __int64))*(&off_100004090 + 5 * (signed int)some_index + 5)) != 0LL )
{
v5(a1, a2);
result = 1LL;
}
```

我们看一下 off_100004090 的内容：
```
__const:0000000100004090 off_100004090   DCQ mig_server_handler_inner_1
__const:0000000100004090                                         ; DATA XREF: mig_server_handler_inner_1+1C↑o
__const:0000000100004090                                         ; amfi_mig_server_handler+38↑o
// ...
__const:00000001000040B8                 DCQ mig_server_handler_inner_2
// ...
__const:00000001000040E0                 DCQ mig_server_handler_inner_3
```

我们可以看到这里包含了 3 个函数指针，基于不同的 index 会选择不同的 handler 去处理 xpc message。

这里我们可以采取动态调试的方法去寻找实际被调用的 handler：
![](https://user-gold-cdn.xitu.io/2020/6/14/172b248730f69363?w=2880&h=1082&f=png&s=1852047)

这里我们可以看到实际用到的 handler 位于 0x00000001000032c8，即上面讨论中的 `mig_server_handler_inner_2`。

接下来顺着 `mig_server_handler_inner_2` 分析，它是一个 wrapper，关键部分如下：
```c
__n128 __fastcall mig_server_handler_inner_2(NDR_record_t *ndr, __int64 a2) {
    // ...
    ret = amfi_verify_codesign(
        a1 = ndr[1].int_rep,     // via w0
        a2 = &ndr[5],            // via x1 = binpath
        a3 = ndr[8].int_rep,     // via x2
        a4 = ndr[9].int_rep,     // via w3
        a5 = ndr[10].mig_vers,   // via w4
        a6 = ndr[10].int_rep,    // via w5
        a7 = arg1 + 0x24,        // via x6
        a8 = arg1 + 0x28,        // via x7, switch keypoint
        a9 = arg1 + 0x2c,        // via x10
        a10 = arg1 + 0x30,       // via x9
        a11 = arg1 + 0x34,       // via x11
        a12 = arg1 + 0x38,       // via x12
        a13 = arg1 + 0x44,       // via x20, return cdhash
        a14 = &sp_cdhash_bytes,  // via x8
        a15 = &ndr[13].int_rep   // via x8-prev
    );
// ...
}
```
继续跟进 `amfi_verify_codesign`，这里给出关键代码：
```c
uint64_t __fastcall amfi_verify_codesign(__int64 a1, __int64 a2, __int64 a3, char a4, __int64 a5, __int64 a6, _DWORD *a7, _DWORD *a8, _DWORD *a9, _DWORD *res_back_48, _DWORD *a11, _DWORD *a12, __int64 a13, __int64 cdhash_bytes, unsigned int *a15)
{
  _DWORD *res_back_40; // x19
  char v16; // w20
  __int64 bin_path; // x23
  uint64_t return_val; // x0
  uint64_t v19; // x25
  uint64_t binary_path; // x21
  __int64 cfdict; // x0
  uint64_t dict; // x22
  __int64 true_value; // x26
  uint64_t longnum_v; // x25
  __int64 error; // x0
  __int64 v26; // x25
  __int64 v27; // x0
  __int64 v28; // x24
  __int64 v29; // x23
  __int64 cdhash; // x23
  __int64 res_dict; // x25
  uint64_t singer_type; // x0
  __int64 cs_res_dict; // [xsp+50h] [xbp-170h]
  __int64 ndr_5_plus_reversed; // [xsp+58h] [xbp-168h]
  __int128 valuePtr; // [xsp+60h] [xbp-160h]
  __int128 v36; // [xsp+70h] [xbp-150h]
  __int128 v37; // [xsp+80h] [xbp-140h]
  __int128 v38; // [xsp+90h] [xbp-130h]
  __int128 v39; // [xsp+A0h] [xbp-120h]
  __int128 v40; // [xsp+B0h] [xbp-110h]
  __int128 v41; // [xsp+C0h] [xbp-100h]
  __int128 v42; // [xsp+D0h] [xbp-F0h]
  __int128 v43; // [xsp+E0h] [xbp-E0h]
  __int128 v44; // [xsp+F0h] [xbp-D0h]
  __int128 v45; // [xsp+100h] [xbp-C0h]
  __int128 v46; // [xsp+110h] [xbp-B0h]
  __int128 v47; // [xsp+120h] [xbp-A0h]
  __int128 v48; // [xsp+130h] [xbp-90h]
  __int128 v49; // [xsp+140h] [xbp-80h]
  __int128 v50; // [xsp+150h] [xbp-70h]
  __int64 v51; // [xsp+168h] [xbp-58h]

  res_back_40 = a8;
  v16 = a4;
  bin_path = a2;
  ndr_5_plus_reversed = a3;
  *a7 = 0;
  *a8 = 0;
  *res_back_48 = 0;
  *a11 = 0;
  *a12 = 0;
  *a9 = 0;
  *(_OWORD *)cdhash_bytes = 0uLL;               // x24 = cdhash_bytes out
  *(_DWORD *)(cdhash_bytes + 16) = 0;
  if ( !memcmp(a15, &unk_100003BB8, 0x20uLL) )
  {
    v19 = kCFAllocatorDefault;
    t
    if ( return_val )
    {
      binary_path = return_val;
      cfdict = CFDictionaryCreateMutable(v19, 0LL, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
      if ( cfdict )
      {
        dict = cfdict;
        true_value = kCFBooleanTrue;
        CFDictionarySetValue(cfdict, kMISValidationOptionValidateSignatureOnly, kCFBooleanTrue);
        CFDictionarySetValue(dict, kMISValidationOptionRespectUppTrustAndAuthorization, true_value);
        longnum_v = CFNumberCreate(v19, 0xBuLL, &ndr_5_plus_reversed);
        CFDictionarySetValue(dict, kMISValidationOptionUniversalFileOffset, longnum_v);
        CFRelease(longnum_v);
        cs_res_dict = 0LL;
        error = MISValidateSignatureAndCopyInfo(binary_path, dict, (uint64_t)&cs_res_dict);
        if ( (_DWORD)error )
        {
          // error
        }
        else if ( cs_res_dict
               && (v29 = CFGetTypeID(), v29 == CFDictionaryGetTypeID())
               && (cdhash = CFDictionaryGetValue(cs_res_dict, kMISValidationInfoCdHash)) != 0
               && (res_dict = CFGetTypeID(), res_dict == CFDataGetTypeID()) )
        {
          CFDataGetBytes(cdhash, 0LL, 20LL, cdhash_bytes);
          singer_type = CFDictionaryGetValue(cs_res_dict, kMISValidationInfoSignerType);
          if ( singer_type )
          {
            *(_QWORD *)&valuePtr = 0LL;
            if ( CFNumberGetValue(singer_type, 0xEuLL, &valuePtr) )
            {
              if ( (_QWORD)valuePtr == 5LL )
                *res_back_48 = 5;
            }
            else if ( (unsigned int)os_log_type_enabled(amfi_logger, 16LL) )
            {
              amfi_log_error_some(binary_path, &cs_res_dict);
            }
          }
          *res_back_40 = 1;
        }
        else
        {
          if ( (unsigned int)os_log_type_enabled(amfi_logger, 17LL) )
            amfi_log_error_some2(binary_path, dict, &cs_res_dict);
            *res_back_40 = 0;
        }
        if ( cs_res_dict )
          CFRelease(cs_res_dict);
        if ( v16 & 1 )
          *res_back_40 = 0;
        CFRelease(dict);
      }
      return_val = CFRelease(binary_path);
    }
  }
  else
  {
    // error
  }
  return return_val;
}
```

这里的几个关键部分如下：
1. 通过 `return_val = CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault, bin_path);` 我们可以知道 a2 是 binary path，它通过 ndr[5] 传入，被存储在 x23 中；
2. 签名校验的关键逻辑在 libmis.dylib 的 `MISValidateSignatureAndCopyInfo` 中，函数必须返回 0 和合法的 dict 才能继续后面的校验；
3. 通过 `CFDataGetBytes(cdhash, 0LL, 20LL, cdhash_bytes);` 完成了 binary cdhash 的拷贝，其中 cdhash_bytes 的地址存储在 x24 中；
4. `res_back_40` 在出错时均写了 0，成功时写了 1，因此他应该代表校验的结果，它通过 a8 传入，通过分析 Caller 可知 a8 的地址被存储在 x19 中。

基于上面的分析，我们的主要任务是伪造出 `res_back_40`，但经过实验发现单纯伪造 result 的 true/false 是不够的，我们还需要将 binary 实际的 cdhash 写入到 x24 对应的地址中才能完美的模拟 `amfi_verify_codesign` 从而通过签名校验。

# AMFI 绕过
有了上面的分析我们知道，关键是要在 `amfi_verify_codesign` 中伪造三个东西：
1. 计算 binary 的真实 cdhash 并写到 x24 对应的 Caller Stack 地址，这个可以通过 x23 先拿到 binary path，调用 MIS 方法完成计算后写回；
2. 劫持 MISValidateSignatureAndCopyInfo 使其返回 0；
3. 将 `res_back_40` 置为 1。

这些在 jakeajames 的 jelbrekLib 中已经有非常成熟的开源方案[4]，核心思路是获取 amfid 的 task port，为它设置一个 exception port，并将其 MISValidateSignatureAndCopyInfo 符号的地址写成非法值，当 AMFI 执行签名校验时，我们会收到 mach exception message，随后执行上述绕过操作，直接跳转到 `amfi_verify_codesign` 的 Epilogue 即可，这里给出几份代码实现的地址：
1. https://github.com/jakeajames/jelbrekLib/blob/master/amfid.m#L188
2. https://github.com/coolstar/Chimera13/blob/master/Chimera13/post-exploit/utils/amfidtakeover.swift#L164

# 总结
本文先简要分析了 iOS 12 以后的 codesign 机制，随后从 AMFI 入手分析了 AMFI 绕过方案的原理和实施过程。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>


# 参考资料
1. [jakeajames: rootlessJB write-up]( https://github.com/jakeajames/rootlessJB3/blob/master/writeup.pdf)
2. [Jonathan Levin: Make Debugging Great Again](http://newosxbook.com/articles/MDGA.html)
3. [jakeajames: rootlessJB_EL - launchAsPlatform](https://github.com/jakeajames/rootlessJB_EL/blob/334ef9dfa9a04d0b9ca8ef4d2786c649b5971d51/empty_list/jelbrek/jelbrek.m#L245)
4. [jakeajames: jelbrekLib - amfid.m](https://github.com/jakeajames/jelbrekLib/blob/master/amfid.m#L188)
5. [CoolStar: Chimera13 - amfidtakeover.swift](https://github.com/coolstar/Chimera13/blob/master/Chimera13/post-exploit/utils/amfidtakeover.swift#L164)