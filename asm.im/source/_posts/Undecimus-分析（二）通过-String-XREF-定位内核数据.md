---
title: Undecimus 分析（二）通过 String XREF 定位内核数据
date: 2019-12-29 21:00:00
tags: ['JailBreak', 'Undecimus', 'XREF']
---

# 前言
在内核中有许多关键变量和校验，为获得这些变量和绕过校验就要求我们在内存中定位这些地址。本文将介绍 Undecimus 中基于 String XREF 定位关键内存地址的方法，通过该方法不仅可以准确定位内核中的特定元素，也能为自行设计二进制分析工具带来很好的启发。

# 定位 Kernel Task
为了获取内核信息，我们需要定位到 Kernel Task 的地址，再通过 tfp0 的 kread 读取内容。要定位 Kernel Task，关键是找到获取 Kernel Task 的代码，然后尝试从内存中定位这段代码，再分析指令解出变量的文件偏移即可。

## 查找使用 Kernel Task 的函数
在 [xnu-4903.221.2](https://github.com/apple/darwin-xnu/tree/xnu-4903.221.2) 中可以找到访问 Kernel Task 的如下代码：
```c
int
proc_apply_resource_actions(void * bsdinfo, __unused int type, int action)
{
    proc_t p = (proc_t)bsdinfo;

    switch(action) {
        case PROC_POLICY_RSRCACT_THROTTLE:
        	/* no need to do anything */
        	break;
        
        case PROC_POLICY_RSRCACT_SUSPEND:
        	task_suspend(p->task);
        	break;
        
        case PROC_POLICY_RSRCACT_TERMINATE:
        	psignal(p, SIGKILL);
        	break;
        
        case PROC_POLICY_RSRCACT_NOTIFY_KQ:
        	/* not implemented */
        	break;
        
        case PROC_POLICY_RSRCACT_NOTIFY_EXC:
        	panic("shouldn't be applying exception notification to process!");
        	break;
	}
	return(0);
}
```

这里有一段字符串 "shouldn't be applying exception notification to process!" 可用于辅助定位，它在编译后会被存储在 `__TEXT,__cstring` 段，通过在内存中搜索 `__TEXT,__cstring` 段即可找到字符串地址，我们称之为 `location_str`。

## 定位到函数中的 String XREF
由于 ARM 的取址常常需要 2 条指令完成，为了定位使用 `location_str` 的代码，我们需要对代码段进行静态分析。当发现寄存器中的值等于 `location_str` 时即发现了一个交叉引用(XREF)，通过这种手段我们便能在内存中定位到语句 `panic("shouldn't be applying exception notification to process!")` 对应的指令地址。

## 回溯找到 Kernel Task XREF
最快定位到 Kernel Task 的方法是回溯到 `task_suspend(p->task)`，在 `task_suspend` 第一次访问 `p->task` 时一定会对 task 寻址，我们可以从寻址指令中解出 task 的文件偏移，再加上内核在内存中的基地址即可得到 Kernel Task 的地址。
```c
kern_return_t
task_suspend(task_t task)
{
    kern_return_t kr;
    mach_port_t port, send, old_notify;
    mach_port_name_t name;
    
    if (task == TASK_NULL || task == kernel_task)
    	return (KERN_INVALID_ARGUMENT);
    
    task_lock(task);
    // ...
```

从上面的分析可以看出问题的关键在于 XREF 的定位，下面我们将分析一种 String Based XREF 定位算法来解决上述问题。

# 在内存中加载 Kernelcache
根据 iPhone Wiki 给出的 Kernelcache 定义[1]：
> The kernelcache is basically the kernel itself as well as all of its extensions (AppleImage3NORAccess, IOAESAccelerator, IOPKEAccelerator, etc.) into one file, then packed/encrypted in an IMG3 (iPhone OS 2.0 and above) or 8900 (iPhone OS 1.0 through 1.1.4) container.

即 kernelcache 就是将 kernel 和它的扩展打包在一个文件中并以 IMG3 格式存储(iOS 2 以上)。

在 [上一篇文章](https://juejin.im/post/5df5f6416fb9a016402d1cc0) 中我们介绍了基于 tfp0 的沙盒逃逸方法，通过沙盒逃逸我们可以从 `/System/Library/Caches/com.apple.kernelcaches/kernelcache` 读取 kernelcache，它既是当前系统加载的镜像。

读者可打开 Undecimus 的 `jailbreak.m` 文件，搜索 "Initializing patchfinder" 定位到 kernelcache 的加载代码，加载方法和普通的 `Mach-O` 文件类似，也是先读取 `Mach Header` 和 `Load Commands`，然后逐段记录偏移量，具体代码在 `init_kernel` 函数中。

这里不再赘述加载过程，只指出几个关键的全局变量：
1. `cstring_base` 和 `cstring_size` 是 `__TEXT,__cstring` 段的虚拟地址和长度；
2. `xnucore_base` 和 `xnucore_size` 是 `__TEXT,__TEXT_EXEC` 段，即代码段的虚拟地址和长度；
3. `kerndumpbase` 是所有段中最小的虚拟地址，即 kernelcache 加载的虚拟基地址，在普通的 `Mach-O` 文件中这个值一般是 `__PAGEZERO` 段的虚拟地址 0x100000000，在内核中似乎是 `__TEXT` 段的虚拟地址 0xFFFFFFF007004000；
4. `kernel` 是 kernelcache 在用户空间的完整映射，即一份完整加载的内核镜像。

# Find String Based XREF
在 Undecimus 中包含一个 `find_strref` 函数用于定位字符串的 XREF：
```c
addr_t
find_strref(const char *string, int n, enum string_bases string_base, bool full_match, bool ppl_base)
{
    uint8_t *str;
    addr_t base;
    addr_t size;
    enum text_bases text_base = ppl_base?text_ppl_base:text_xnucore_base;

    switch (string_base) {
        case string_base_const:
            base = const_base;
            size = const_size;
            break;
        case string_base_data:
            base = data_base;
            size = data_size;
            break;
        case string_base_oslstring:
            base = oslstring_base;
            size = oslstring_size;
            break;
        case string_base_pstring:
            base = pstring_base;
            size = pstring_size;
            text_base = text_prelink_base;
            break;
        case string_base_cstring:
        default:
            base = cstring_base;
            size = cstring_size;
            break;
    }
    addr_t off = 0;
    while ((str = boyermoore_horspool_memmem(kernel + base + off, size - off, (uint8_t *)string, strlen(string)))) {
        // Only match the beginning of strings
        // first_string || \0this_string
        if ((str == kernel + base || *(str-1) == '\0') && (!full_match || strcmp((char *)str, string) == 0))
            break;
        // find after str
        off = str - (kernel + base) + 1;
    }
    if (!str) {
        return 0;
    }
    // find xref
    return find_reference(str - kernel + kerndumpbase, n, text_base);
}
```

它要求传入字符串 string，引用的序号 n，基准段 string_base，是否完全匹配 `full_match`，以及是否位于 `__PPLTEXT` 段，对于寻找 Kernel Task 的场景，我们的入参如下：
```c
addr_t str = find_strref("\"shouldn't be applying exception notification", 2, string_base_cstring, false, false);
```

即以 `__TEXT,__cstring` 为基准，不要求完全匹配，找到第 2 个交叉引用所在的地址。

## 定位字符串地址
字符串地址的定位逻辑在 `boyermoore_horspool_memmem` 函数中：
```c
static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}
```
我们首先根据调用分析入参：
```c
addr_t base = cstring_base;
addr_t off = 0;
while ((str = boyermoore_horspool_memmem(kernel + base + off, size - off, (uint8_t *)string, strlen(string)))) {
    // Only match the beginning of strings
    // first_string || \0this_string
    if ((str == kernel + base || *(str-1) == '\0') && (!full_match || strcmp((char *)str, string) == 0))
        break;
    // find after str
    off = str - (kernel + base) + 1;
}
```
1. haystack = kernel + base + off，即 `__TEXT,__cstring` 段的起始地址；
2. hlen = size - off，即 `__TEXT,__cstring` 段的长度；
3. needle = string 即待查找字符串指针；
4. nlen = strlen(string) 即待查找字符串的长度。

在函数的开头首先维护了一个 `bad_char_skip` 数组来记录当匹配失败时，应当跳过多少个字符来避免无意义的匹配。整个算法采用了倒序扫描的方式，不断从 `haystack[needle_len - 1]` 向前扫描并检查 `haystack[i] == needle[i]`，当匹配到 `haystack[0]` 时如果依然满足条件，说明找到了字符串的地址，否则根据匹配失败的字符查 `bad_char_skip` 表将 haystack 指针后移继续匹配。

**需要注意的是，在匹配成功后得到的字符串地址是相对于用户空间的 kernelcache 映射 `kernel` 的，并非是字符串在内核中的实际地址。**

## 搜索对字符串所在地址的寻址操作
在获取到字符串在用户空间的地址 `str` 后，首先需要计算它在 kernelcache 中的虚拟地址：
```c
addr_t str_vmaddr = str - kernel + kerndumpbase;
```

内核代码中对 str 的引用一定涉及到对 `str_vmaddr` 的寻址，主要的寻址方式有以下几种：
```arm
; 1
adrp xn, str@PAGE
add xn, xn, str@PAGEOFF

; 2
ldr xn, [xm, #imm]

; 3
ldr xn, =#imm

; 4
adr xn, #imm

; 5
bl #addr
```

在 `find_strref` 的尾部调用了 `return find_reference(str_vmaddr, n, text_base)`，`find_reference` 对 `__TEXT_EXEC,__text` 进行了静态分析，对寻址相关的指令模拟了寄存器运算，主要逻辑在 `xref64` 函数中，当发现寄存器中的值等于 `str_vmaddr` 时即找到了一条对 str 的交叉引用。

这里的代码主要是对机器码的解码和运算操作，篇幅较长不再贴出，读者有兴趣可以自行阅读。

# 通过 String XREF 定位变量地址
上文中我们已经得到了目标函数 `proc_apply_resource_actions` 中对 str 的引用地址，随后需要向上回溯定位 `task_suspend` 函数的调用指令：
```c
addr_t find_kernel_task(void) {
    /**
             adrp x8,     str@PAGE
     str --> add  x8, x8, str@PAGEOFF
             bl   _panic
     */
    addr_t str = find_strref("\"shouldn't be applying exception notification", 2, string_base_cstring, false, false);
    if (!str) return 0;
    str -= kerndumpbase;

    // find bl _task_suspend
    addr_t call = step64_back(kernel, str, 0x10, INSN_CALL);
    if (!call) return 0;

    addr_t task_suspend = follow_call64(kernel, call);
    if (!task_suspend) return 0;

    addr_t adrp = step64(kernel, task_suspend, 20*4, INSN_ADRP);
    if (!adrp) return 0;

    addr_t kern_task = calc64(kernel, adrp, adrp + 0x8, 8);
    if (!kern_task) return 0;

    return kern_task + kerndumpbase;
}
```
整个过程主要分 3 步：
1. 回溯找到 `bl _task_suspend` 的调用点，解出 `task_suspend` 函数的地址；
2. 从 `task_suspend` 函数向后搜寻第一条 adrp 指令，即是对 Kernel Task 的寻址；
3. 从寻址指令中解出 Kernel Task 地址。

我们再回过头来看 `proc_apply_resource_actions` 函数片段：
```c
switch(action) {
	case PROC_POLICY_RSRCACT_THROTTLE:
		/* no need to do anything */
		break;

	case PROC_POLICY_RSRCACT_SUSPEND:
		task_suspend(p->task);
		break;

	case PROC_POLICY_RSRCACT_TERMINATE:
		psignal(p, SIGKILL);
		break;

	case PROC_POLICY_RSRCACT_NOTIFY_KQ:
		/* not implemented */
		break;
	
	case PROC_POLICY_RSRCACT_NOTIFY_EXC:
		panic("shouldn't be applying exception notification to process!");
		break;
}
```

编译时不一定会按照 case 的顺序生成机器码，因此我们需要根据 str XREF 找到 kernelcache 中的实际表示，一个简单地办法是在 `find_strref("\"shouldn't be applying exception notification", 2, string_base_cstring, false, false)` 后打一个断点来获取 str XREF 的文件偏移，再利用二进制分析工具反汇编 kernelcache 中的这个部分。

通过断点调试可知 str XREF 位于 0x0000000000f9f084，这应该是一条 add 指令：
```c
/**
         adrp x8,     str@PAGE
 str --> add  x8, x8, str@PAGEOFF
         bl   _panic
 */
```

在 `Mach-O` 查看器中打开可以发现，0x0000000000f9f084 确实是一条 add 指令：
![](https://user-gold-cdn.xitu.io/2019/12/29/16f519149c6a5e33?w=818&h=272&f=png&s=57926)

要定位 `task_suspend(p->task)` 有两种方式，其一是 `p->task` 是一个基于偏移量的结构体成员寻址有明显特征，第二个是看函数调用前的参数准备。在 0xf9f074 处有一个 +16 的偏移量寻址，显然这是对 `p->task` 地址的计算，因此 0xf9f078 处即是 `task_suspend(p->task)` 的调用。

所以从 add 指令处向前回溯 3 条指令即可，找到这条 CALL 指令后，即可从中解出 `task_suspend`的地址：
```c
// find bl _task_suspend
addr_t call = step64_back(kernel, str, 0x10, INSN_CALL);
if (!call) return 0;

addr_t task_suspend = follow_call64(kernel, call);
if (!task_suspend) return 0;
```

随后我们从 `task_suspend` 函数的起始地址开始向后搜寻第一个 adrp 指令即可找到对 Kernel Task 的 adrp 语句，静态分析 adrp & add 即可计算出 Kernel Task 的地址：
```c
addr_t adrp = step64(kernel, task_suspend, 20*4, INSN_ADRP);
if (!adrp) return 0;

addr_t kern_task = calc64(kernel, adrp, adrp + 0x8, 8);
if (!kern_task) return 0;
```

注意这里我们得到的依然是 fileoff，需要加上 `kerndumpbase` 得到虚拟地址：
```c
return kern_task + kerndumpbase;
```

**需要注意的是，如果要在内核中读取 Kernel Task，这个地址需要加上 kernel_slide 才可以。计算 kernel_slide 的代码紧跟在 tfp0 之后，读者有兴趣可以自行阅读。**

# 总结
本文详细分析了 Undecimus 中基于 string 的交叉引用在内存中定位代码和变量的技术，通过该技术可以实现内核中变量地址的定位，随后可通过读写实现绕过检测和注入等操作。该技术不仅是完成 Jailbreak 的关键技术，也能给读者带来二进制静态分析的一些启发。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>


# 参考资料
1. [The iPhone Wiki: Kernelcache](https://www.theiphonewiki.com/wiki/Kernelcache)
2. [Apple: Darwin-XNU](https://github.com/apple/darwin-xnu/tree/xnu-4903.221.2)
3. [Github/pwn20wndstuff: Undecimus](https://github.com/pwn20wndstuff/Undecimus)
