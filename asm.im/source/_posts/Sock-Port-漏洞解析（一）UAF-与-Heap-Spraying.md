---
title: Sock Port 漏洞解析（一）UAF 与 Heap Spraying
date: 2019-11-17 19:00:00
tags: ['SockPort', 'UAF', 'Heap Spraying']
---

# 前言
在之前的汇编教程系列文章中，我们在用户态下探讨了诸多原理。从今天开始，我们将详细分析历代 iOS Jailbreak Exploits，并由此深入 XNU 内核，并学习更多二进制安全攻防的知识。

虽然国外大佬提供的 Exploit PoC 都有较为详细的 write-up，但这些 write-up 常常以之前出现的 PoC 为基础，并不详细展开某些具体原理，这就导致初学者很难完全读懂。笔者的 Jailbreak Priciples 系列文章会将所有相关的 PoC 和 write-up 进行整合，并以读者是内核小白（其实笔者也是）为假设展开分析，目标是打造人人能读懂的 XNU 漏洞分析系列文章。

# 越狱的本质
iOS 仅为用户提供了一个受限的 Unix 环境，常规情况下我们只能在用户态借助于合法的系统调用来与内核交互。相反的，用于电脑的 macOS 则有着很高的自由度。它们都基于 Darwin-XNU，但 Apple 在 iPhoneOS 上施加了诸多限制，越狱即解除这些限制使我们可以获得 iPhoneOS 的 root 权限，进而在一定程度上为所欲为。

Apple 采用了 Sandbox, Signature Checkpoints 等手段对系统进行保护，使得突破这些限制变得极为困难。

# 越狱的分类
目前越狱主要分为两类，一类是以硬件漏洞为基础的 BootROM Exploit，另一类则是基于软件漏洞的 Userland Exploit。

## BootROM Exploit
这类漏洞类似于单片机中的 IC 解密，从硬件层面发现 iPhone 本身的漏洞，使得整个系统的 [Secure Boot Chain](https://www.theiphonewiki.com/wiki/Bootchain) 变得不可靠，这类漏洞的杀伤力极强，只能通过更新硬件解决。最近出现的 [checkm8](https://github.com/axi0mX/ipwndfu) 及基于它开发的 [checkra1n](https://checkra.in/) 就实现了 iPhone 5s ~ iPhone X 系列机型的硬件调试与越狱；

## Userland Exploit
这类漏洞往往是对开源的 [Darwin-XNU](https://github.com/apple/darwin-xnu) 进行代码审计发现的，基于这些漏洞往往能使我们在用户态将任意可执行代码送入内核执行，我们即将介绍的 Sock Port Exploit 即是对 XNU 中 socket options 的一个 UAF 漏洞的利用。

# 将用户态数据送入内核
通过上文的分析我们知道，Userland Exploit 的一个重要基础是能将任意数据写入内核的堆区，使之成为有效地 Kernel 数据结构，进而从用户态实施对内核的非法控制。遗憾的是，我们无法直接操作内核的内存数据，这是因为用户态的应用程序没有办法获取 kernel_task，也就无法直接通过 `vm_read` 和 `vm_write` 等函数操作内核的堆栈。

既然无法直接操作内存，我们就需要考虑间接操作内存的方式，事实上我们有非常多的方式能够间接读写内核的数据，最常见方式有 Socket, Mach Message 和 IOSurface 等，这里我们先介绍最好理解的 Socket 方式，随后对 Sock Port 的漏洞时分析会介绍其利用这三种方式打的组合拳。

## 基于 Socket 的间接内核内存读写
由于 Socket 的实现是操作系统层面的，在用户态通过 socket 函数创建 sock 时内核会执行一些内存分配操作，例如下面的用户态代码：
```c
int sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
```

在内核态会根据传入的参数创建 `struct socket` 结构体：
```c
/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
struct socket {
	int	so_zone;		/* zone we were allocated from */
	short	so_type;		/* generic type, see socket.h */
	u_short	so_error;		/* error affecting connection */
	u_int32_t so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* internal state flags SS_*, below */
	void	*so_pcb;		/* protocol control block */
	// ...
}
```

这里我们能通过传入 socket 的参数间接、受限的控制内核中的内存，但由于系统只会返回 sock 的句柄（handle）给我们，我们无法直接读取内核的内存内容。

要读取内核的内存，我们可以借助于内核提供的 socket options 相关函数，他们能够修改 socket 的一些配置，例如下面的代码修改了 IPV6 下的 Maximum Transmission Unit：
```c
// set mtu
int minmtu = -1;
setsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &minmtu, sizeof(*minmtu));

// read mtu
getsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &minmtu, sizeof(*minmtu));
```

在内核态，系统会读取 `struct socket` 的 so_pcb，并执行来自用户态的读写操作，由此我们透过 options 相关函数读写了内核中 socket 结构体的部分内容。

## 利用 Socket 读写内核的任意内容
上述方式有一个明显的限制，那就是我们只能在内核受控的范围内读写内存，单单通过这种方式是玩不出幺蛾子的。设想如果我们能尝试把一个伪造的 Socket 结构体分配到内核的其他区段，是不是就能通过 `setsockopt` 和 `getsockopt` 来读写任意内存了呢？

Sock Port 是一个利用 Socket 函数集实现内核内存任意读写的漏洞，它主要基于 iOS 10.0 - 12.2 的内核代码中 socket disconnect 时的一个漏洞，观察如下的内核代码：
```c
if (!(so->so_flags & SOF_PCBCLEARING)) {
	struct ip_moptions *imo;
	struct ip6_moptions *im6o;

	inp->inp_vflag = 0;
	if (inp->in6p_options != NULL) {
		m_freem(inp->in6p_options);
		inp->in6p_options = NULL; // <- good
	}
	ip6_freepcbopts(inp->in6p_outputopts); // <- bad
	ROUTE_RELEASE(&inp->in6p_route);
	/* free IPv4 related resources in case of mapped addr */
	if (inp->inp_options != NULL) {
		(void) m_free(inp->inp_options); 
		inp->inp_options = NULL; // <- good
	}
	// ...
}
```

可以看到在清理 options 时只对 `in6p_outputopts` 进行了释放，而没有清理 `in6p_outputopts` 指针的地址，这就造成了一个 `in6p_outputopts` 悬垂指针。

幸运的是，通过某种设置后，我们能够在 socket disconnect 后继续通过 `setsockopt` 和 `getsockopt` 间接读写这个悬垂指针。随着系统重新分配这块内存，我们依然能够通过悬垂指针对其进行访问，因此问题转化为了如何间接控制系统对该区域的 Reallocation。

这类透过悬垂指针操作已释放区域的漏洞被称为 UAF（Use After Free），而间接控制系统 Reallocation 的常见方式有 [堆喷射(Heap Spraying)](https://en.wikipedia.org/wiki/Heap_spraying) 和 [堆风水(Heap feng-shui)](https://en.wikipedia.org/wiki/Heap_feng_shui)，整个 Sock Port 的漏洞利用较为复杂，我们将在接下来的几篇文章中逐步讲解，这里只需要对这些概念有个初步的认识即可。

# Use After Free
透过上述例子我们对 UAF 有了一个初步的认识，现在我们参考 Webopedia 给出明确的定义：

> Use After Free specifically refers to the attempt to access memory after it has been freed, which can cause a program to crash or, in the case of a Use-After-Free flaw, can potentially result in the execution of arbitrary code or even enable full remote code execution capabilities.

即尝试访问已释放的内存，这会导致程序崩溃，或是潜在的任意代码执行，甚至获取完全的远程控制能力。

UAF 的关键之一是获取被释放区域的内存地址，一般透过悬垂指针实现，而悬垂指针是由于指针指向的内存区域被释放，但指针未被清零导致的，这类问题在缺乏二进制安全知识的开发者写出的代码中屡见不鲜。

对于跨进程的情况下，只透过悬垂指针是无法读写执行内存的，需要配合一些能间接读取悬垂指针的 IPC 函数，例如上文中提到的 `setsockopt` 和 `getsockopt`，此外为了有效地控制 Reallocation 往往需要结合间接操作堆的相关技术。

# Heap Spraying
下面我们参考 Computer Hope 给出 Heap Spraying 的定义：
> Heap spraying is a technique used to aid the exploitation of vulnerabilities in computer systems. It is called "spraying the heap" because it involves writing a series of bytes at various places in the heap. The heap is a large pool of memory that is allocated for use by programs. The basic idea is similar to spray painting a wall to make it all the same color. Like a wall, the heap is "sprayed" so that its "color" (the bytes it contains) is uniformly distributed over its entire memory "surface."

即在用户态透过系统调用等方式在内核堆的不同区域分配大量内存，如果将内核的堆比作墙壁，堆喷射就是通过大量分配内存的方式将同样颜色的油漆（同样的字节）泼洒到堆上，这会导致其颜色（同样的字节）均匀的分布在整个内存平面上，即那些先前被释放的区域几乎都被 Reallocation 成了同样的内容。

简言之就是，比如我们 alloc 了 1 个 8B 的区域，随后将其释放，接下来再执行 alloc 时迟早会对先前的区域进行复用，如果恰好被我们 alloc 时占用，则达到了内容控制的目的。透过这种技术我们可以间接控制堆上的 Reallocation 内容。

显然如果我们将上述 Socket UAF 与 Heap Spraying 组合，就有机会为 Socket Options 分配伪造的内容，随后我们通过 `setsockopt` 和 `getsockopt` 执行读写和验证，就能实现对内核堆内存的完全控制。

# 一个纯用户态的 UAF & Heap Spraying 例子
综合上述理论探讨，我们对堆内存的读写有了初步的认识，事实上事情没有我们想象的那么简单，整个 Sock Port 的利用是基于许多漏洞组合而来的，并非三言两语和一朝一夕能够完全搞懂，因此本文先不展开具体漏洞的内容，而是在用户态模拟一个 UAF 和 Heap Spraying 的场景让大家先从工程上初步认识这两个概念。

## 假设的漏洞场景
设想小明是一个初级页面仔，他要开发一个任务执行系统，该系统根据任务的优先级顺序执行任务，任务的优先级取决于用户的 VIP 等级，该 VIP 等级被记录在 task 的 options 中：
```c
struct secret_options {
    bool isVIP;
    int vipLevel;
};

struct secret_task {
    int tid;
    bool valid;
    struct secret_options *options;
};
```

小明参考了 Mach Message 的设计理念，在系统内部维护 Task 的内存结构，只对外暴露 Task 的句柄（tid），用户可以透过 `create_secret_task` 创建任务，任务的默认是没有 VIP 等级的：
```c
std::map<task_t, struct secret_task *> taskTable;

task_t create_secret_task() {
    struct secret_task *task = (struct secret_task *)calloc(1, sizeof(struct secret_task));
    task->tid = arc4random();
    while (taskTable.find(task->tid = arc4random()) != taskTable.end());
    taskTable[task->tid] = task;
    struct secret_options *options = (struct secret_options *)calloc(1, sizeof(struct secret_options));
    task->options = options;
    options->isVIP = false;
    options->vipLevel = 0;
    return task->tid;
}
```

在系统之外，用户能做的只是创建任务、获取 VIP 信息以及获取任务优先级：
```c
typedef int task_t;
#define SecretTaskOptIsVIP 0
#define SecretTaskOptVipLevel 1
#define SecretTaskVipLevelMAX 9

int get_task_priority(task_t task_id) {
    struct secret_task *task = get_task(task_id);
    if (!task) {
        return (~0U);
    }
    return task->options->isVIP ? (SecretTaskVipLevelMAX - task->options->vipLevel) : (~0U);
}

bool secret_get_options(task_t task_id, int optkey, void *ret) {
    struct secret_task *task = get_task(task_id);
    if (!task) {
        return false;
    }
    switch (optkey) {
        case SecretTaskOptIsVIP:
            *(reinterpret_cast<bool *>(ret)) = task->options->isVIP;
            break;
        case SecretTaskOptVipLevel:
            *(reinterpret_cast<int *>(ret)) = task->options->vipLevel;
            break;
        default:
            break;
    }
    return true;
}
```

在理想情况下，不考虑逆向工程的方式，我们只能拿到 Task 的句柄，无法获取 Task 地址，因此无法任意修改 VIP 信息。

小明同时为用户提供了注销任务的 API，他只对任务的 options 进行了释放，同时将任务标记为 invalid，缺乏经验的他忘记清理 options 指针，为系统引入了一个 UAF Exploit：
```c
bool free_task(task_t task_id) {
    struct secret_task *task = get_task(task_id);
    if (!task) {
        return false;
    }
    free(task->options);
    task->valid = false;
    return true;
}
```

## 假设的攻击场景
常规情况下，我们只能透过公共的 API 访问系统：
```c
// create task
task_t task = create_secret_task();

// read options
int vipLevel;
secret_get_options(task, SecretTaskOptVipLevel, &vipLevel);

// get priority
int priority = get_task_priority(leaked_task);

// release task
free_task(task);
```

由于 Task 默认是非 VIP 的，我们只能拿到最低优先级 INTMAX。这里我们通过 `task->options` 的 UAF 可以伪造 task 的 VIP 等级，方法如下：
1. 创建一个 Task，并通过 free_task 函数将其释放，这会构造一个 `task->options` 的悬垂指针；
2. 不断分配与 `task->options` 指向的 `struct secret_options` 相同大小的内存区域，直到 `task->options` 悬垂指针指向的区域被 Reallocation 成我们新申请的内存，验证方式可以伪造特定数据，随后通过 `secret_get_options` 读取验证；
3. 此时 `struct secret_options` 已经指向了我们新申请的区域，可以通过修改该区域实现对 Task Options 的修改。

```c
struct faked_secret_options {
    bool isVIP;
    int vipLevel;
};
struct faked_secret_options *sprayPayload = nullptr;
task_t leaked_task = -1;

for (int i = 0; i < 100; i++) {
    // create task
    task_t task = create_secret_task();
    // free to make dangling options
    free_task(task);
    
    // alloc to spraying
    struct faked_secret_options *fakedOptions = (struct faked_secret_options *)calloc(1, sizeof(struct faked_secret_options));
    fakedOptions->isVIP = true;
    // to verify
    fakedOptions->vipLevel = 0x123456;
    
    // check by vipLevel
    int vipLevel;
    secret_get_options(task, SecretTaskOptVipLevel, &vipLevel);
    if (vipLevel == 0x123456) {
        printf("spray succeeded at %d!!!\n", i);
        sprayPayload = fakedOptions;
        leaked_task = task;
        break;
    }
}

// modify
if (sprayPayload) {
    sprayPayload->vipLevel = 9;
}
```

由于是纯用户态、同一线程内的同步操作，这种方式的成功率极高。当然这种方式只能让大家对 UAF 与 Heap Spraying 有一个大致认识，**实际上这类漏洞利用都是跨进程的，需要非常复杂的操作，往往需要借助于 Mach Message 和 IOSurface，且 Payload 构造十分复杂**。

# 下节预告
在下一个章节中我们将开始着手分析 Sock Port 的源码，了解来自 [Ian Beer](https://en.wikipedia.org/wiki/Ian_Beer) 大佬的 kalloc 系列函数以及利用 IOSurface 进行 Heap Spraying 的方式和原理。其中 kalloc 系列函数需要对 Mach Message 有深入的认识，因此在下一篇文章中我们也会从 XNU 源码角度分析 mach port 的设计。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>

# 参考资料
1. Andy Slye. What Is Jailbreaking? How a Jailbreak Works - https://www.youtube.com/watch?v=tYKfXNiA1wc
2. Webopedia. Use After Free - https://www.webopedia.com/TERM/U/use-after-free.html
3. Computer Hope. Heap spraying - https://www.computerhope.com/jargon/h/heap-spraying.htm
4. GitHub. jakeajames/sock_port - https://github.com/jakeajames/sock_port/tree/sock_port_2