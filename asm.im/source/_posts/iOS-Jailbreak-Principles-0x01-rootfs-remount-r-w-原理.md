---
title: iOS Jailbreak Principles 0x01 - rootfs remount r/w 原理
date: 2020-04-06 20:27:22
tags: ['JailBreak', 'Undecimus', 'Chimera', 'rootfs', 'APFS', 'remount']
---

# 系列文章
1. [iOS Jailbreak Principles - Sock Port 漏洞解析（一）UAF 与 Heap Spraying](https://juejin.im/post/5dd10660e51d453fac0a598d)
2. [iOS Jailbreak Principles - Sock Port 漏洞解析（二）通过 Mach OOL Message 泄露 Port Address](https://juejin.im/post/5dd918d051882573180a2ba7)
3. [iOS Jailbreak Principles - Sock Port 漏洞解析（三）IOSurface Heap Spraying](https://juejin.im/post/5de37a236fb9a071b5615dea)
4. [iOS Jailbreak Principles - Sock Port 漏洞解析（四）The tfp0 !](https://juejin.im/post/5dec7f2f6fb9a0160c411516)
5. [iOS Jailbreak Principles - Undecimus 分析（一）Escape from Sandbox](https://juejin.im/post/5df5f6416fb9a016402d1cc0)
6. [iOS Jailbreak Principles - Undecimus 分析（二）通过 String XREF 定位内核数据](https://juejin.im/post/5e087dbd51882549757e5be2)
7. [iOS Jailbreak Principles - Undecimus 分析（三）通过 IOTrap 实现内核任意代码执行](https://juejin.im/post/5e1ac76d51882520c02c82c0)
8. [iOS Jailbreak Principles - Undecimus 分析（四）绕过 A12 的 PAC 实现 kexec](https://juejin.im/post/5e415da86fb9a07c9a194f3b)

# 前言
在之前的文章中我们介绍了 iOS 12 获取 tfp0 以及基于 tfp0 实现 kexec 的原理。从这篇文章开始我们开始分析 tfp0 和 kexec 之后的 jailbreak 环境布置原理，主要包括 rootfs 的读写与持久化、ssh 等远程服务的启动、非法签名代码的执行以及 Hook 系统等。这一篇我们主要介绍 rootfs 的读写与持久化原理。

# 什么是 rootfs
在 Unix-like 的操作系统中每个文件系统都需要通过挂载点（mount point）来进行加载。其中 rootfs 指的是在启动时挂载到根目录 `/` 的文件系统。[1]

在 iOS 中 rootfs 是从 `/dev/disk0s1s1` 或 `system-snapshot` 挂载的文件系统，其中包含了操作系统（/System/Library/Caches/com.apple.kernelcaches/kernelcache）、基础 App（/Applications/）等信息，**且在现代 iOS 操作系统中默认是只读的**。

而用户信息则通过其他的文件系统挂载到 `/private/var` 等目录，我们可以在已越狱的 iOS 设备上通过 `df -h` 查看挂载信息：
```
iPad-2:~ root# df -h
Filesystem       Size   Used  Avail Capacity iused      ifree %iused  Mounted on
/dev/disk0s1s1   60Gi  4.6Gi  2.0Gi    71%  177766  624821794    0%   /
devfs            56Ki   56Ki    0Bi   100%     194          0  100%   /dev
/dev/disk0s1s2   60Gi   53Gi  2.0Gi    97%  194854  624804706    0%   /private/var
/dev/disk0s1s3   60Gi  6.8Mi  2.0Gi     1%     185  624999375    0%   /private/var/MobileSoftwareUpdate
/dev/disk4       30Mi   14Mi   16Mi    47%     337 4294966942    0%   /Developer
```

# rootfs 为什么是只读的
## vnode & mount 对象
在说明 rootfs 为什么是只读的之前，我们要先简单介绍下 iOS 的文件系统。在 Unix-like 操作系统中，每个文件（包括目录）都会在系统中分配唯一的 vnode，在 vnode 中包含了文件的各种信息[2]：
```c
struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;         /* vnodes for mount point */
    // ...
    mount_t v_mount;                        /* ptr to vfs we are in */
    // ...
};
```


vnode 的 `v_mount` 成员记录了当前文件挂载到的文件系统及其属性，其中 `mnt_flag` 中的标志位可以设置 rootfs 标识和只读属性：
```c
struct mount {
    TAILQ_ENTRY(mount)      mnt_list;                   /* mount list */
    int32_t                 mnt_count;                  /* reference on the mount */
    // ...
    uint32_t                mnt_flag;                   /* flags */
    // ,,,
};
```

## mount flags
对于 rootfs，其 `node->v_mount->mnt_flag` 的 `MNT_ROOTFS` 和 `MNT_RDONLY` 被置位。这两个标志位代表了以下缓解措施：
1. 当一个 Sandbox App 试图访问某个文件系统时，如果系统发现其 vnode 包含 `MNT_ROOTFS` 属性会直接失败；
2. 一个包含 `MNT_RDONLY` 的文件系统是只读的。

解决方案也十分简单，我们只需要获取到 rootfs 的 vnode，通过 kread 读取 `mnt_flag`，将 `MNT_ROOTFS` 和 `MNT_RDONLY` 位置 0 后写回，再重新挂载文件系统以刷新状态即可。

## APFS Snapshots
在 iOS 11.3 以后，苹果采取了更加极端的措施，他们不再把 `/dev/disk0s1s1` 挂载到 `/`，而是随着系统固件升级向设备发布 rootfs 的 APFS Snapshot，在每次启动时优先挂载 Snapshot 到 `/`。这就意味着即使我们通过上面的 flags patch 修改了 rootfs，在 reboot 后系统依然会从 APFS Snapshot 加载文件系统，从而导致我们写入 rootfs 的内容并没有被挂载，一切都回归到了从前[3]。

# 实现 rootfs r/w 和持久化
通过上面的讨论我们知道，实现 rootfs r/w 的关键点有两个：
1. 找到 rootfs 的 vnode；
2. 修改 rootfs 的 vnode 数据实现 r/w；
3. 绕过 APFS Snapshot 加载机制使其挂载真正的文件系统 `/dev/disk0s1s1` 到 `/`。

## 注意事项
1. 笔者的讨论和实验基于 iOS 13.1.1 (17A854)，参考代码来自于 [unc0ver](https://github.com/pwn20wndstuff/Undecimus) 和 [Chimera13](https://github.com/coolstar/Chimera13)；
2. remount 涉及到多个系统调用，需要在提权（setuid(0)）后才能执行，有关提权的代码可自行参考 Chimera13 中的 getRoot，不在本文讨论范围内。

## 0x01 找到 rootfs vnode
要找到 rootfs 的 vnode 有两个思路：
1. 通过 XREF 方案在内核中定位 `rootvnode` 全局变量；
2. 找到一个系统进程，通过 proc 对象的 `p_textvp` 找到其 vnode，再通过 vnode 链表回溯到 rootfs vnode。

这里我们采用第二种方案，我们首先来看 proc 对象上的 vnode 信息数据：
```c
struct  proc {
    LIST_ENTRY(proc) p_list;                /* List of all processes. */
    
    void *          task;                   /* corresponding task (static)*/
    struct  proc *  p_pptr;                 /* Pointer to parent process.(LL) */
    pid_t           p_ppid;   
    // ...
    struct  vnode *p_textvp;        /* Vnode of executable. */
    // ...
};
```

因此我们通过 `proc->p_textvp` 即可获得可执行文件对应的 vnode，接下来我们来看 vnode 中实现回溯的关键数据：
```c
struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;    
    // ...  
    vnode_t v_parent;                       /* pointer to parent vnode */
    // ...
    const char *v_name;                     /* name component of the vnode */
    // ...
};
```

这里我们可以通过 `vnode->v_name` 确定 vnode 结点的名称（文件/目录名），通过 `v_parent` 进行回溯，当找到名称为 `System` 的 vnode 时说明我们已经回溯到了根目录，即当前 vnode 即为 rootfs vnode（rootvnode）。

比如这里我们选择系统进程 launchd 作为起点，首先我们来看 launchd 所在的目录：
```
iPad-2:~ root# which launchd
/sbin/launchd
```

那么理论上回溯 2 次即可到达 `/`，因此我们只需要通过 tfp0 来做 proc iteration，找到 launchd 的 proc 对象，再进行两次回溯即可找到 rootvnode：
```c
uint64_t findRootVnode(uint64_t launchd_proc) {
    uint64_t textvp = rk64(launchd_proc + 0x238); // proc_text_vp
    uint64_t nameptr = rk64(textvp + 0xb8); // vnode.name
    uint8_t name[20] = {0};
    kread(nameptr, &name, 20);
    printf("[+] found vnode: %s\n", name);
    
    uint64_t sbin = rk64(textvp + 0xc0); // vnode.parent
    nameptr = rk64(sbin + 0xb8); // vnode.name
    kread(nameptr, &name, 20);
    printf("[+] found vnode (should be sbin): %s\n", name);
    
    uint64_t rootvnode = rk64(sbin + 0xc0); // vnode.parent
    nameptr = rk64(rootvnode + 0xb8); // vnode.name
    kread(nameptr, &name, 20);
    printf("[+] found vnode (should be System): %s\n", name);
    return rootvnode;
}
```

对应的输出如下，可见符合理论假设，我们成功找到了 rootvnode：
```
[+] found vnode: launchd
[+] found vnode (should be sbin): sbin
[+] found vnode (should be System): System
```

## 0x02 移除 rootfs 的 APFS Snapshot
在前面的讨论中提到，iOS 系统在启动时如果发现存在 rootfs 的 snapshot，则会优先加载它而不是 `/dev/disk0s1s1`，因此只有移除 rootfs 的 snapshot 才能保证启动时真实 rootfs 的挂载。

Apple 限制了对 `fs_snaphost_delete` 的使用，但没有限制 `fs_snapshot_rename`，因此我们可以通过对 rootfs 的 boot snapshot 重命名来实现。通过 rename 而不是 delete 方式的另一个好处是我们可以通过 rename back 来恢复 rootfs。

需要注意的是，我们在执行上述操作时需要对真实的系统盘 `/dev/disk0s1s1` 做修改，但 rootfs 已经被系统挂载，因此这里我们需要将其挂载到另外的位置，比如 
Chimera13 中使用的 `var/rootfsmnt`。整个流程大致如下：

![](https://user-gold-cdn.xitu.io/2020/4/6/1714f2e577a71c3f?w=554&h=1370&f=png&s=107224)

这里面有几个注意点列举如下：
### 问题一：iOS 不允许 device 被多次挂载
我们需要找到 rootvnode 的 specinfo，清理其 si_flags 中记录的已挂载信息。否则当我们尝试挂载 `/dev/disk0s1s1` 时会触发 kernel panic。（这里有一个疑问是，系统并未真正的挂载 `/dev/disk0s1s1`，而是挂载了其 snapshot，是否依然会置位 `/dev/disk0s1s1` 的 `SI_MOUNTEDON` 所以这里需要清理）。
```c
struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;         /* vnodes for mount point */
    // ...
    union {
    	// ...
	    struct specinfo *vu_specinfo;   /* device (VCHR, VBLK) */
	// ...
};

/*
 * Flags for specinfo
 */
#define SI_MOUNTEDON    0x0001  /* block special device is mounted on */
#define SI_ALIASED      0x0002  /* multiple active vnodes refer to this device */

struct specinfo {
    struct  vnode **si_hashchain;
    struct  vnode *si_specnext;
    long    si_flags;
    // ...
};
```

我们先找到 rootvnode，然后找到 mount 中存储的 device 信息，最后清理 `/dev/disk0s1s1` 的 flag 清除已挂载信息，来为后续 remount 铺路：
```c
int mountRealRootFS(uint64_t rootvnode) {
    uint64_t vmount = rk64(rootvnode + 0xd8); // vnode.mount
    uint64_t dev = rk64(vmount + 0x980); // vmount.devvp
    uint64_t nameptr = rk64(dev + 0xb8); // vnode.name
    char name[20] = {0};
    kread(nameptr, &name, 20);
    printf("[+] found vnode: %s\n", name);
    
    uint64_t specinfo = rk64(dev + 0x78); // vnode.specinfo
    uint32_t flags = rk32(specinfo + 0x10); // specinfo.flags
    printf("[+] found dev flags %d\n", flags);
    
    // set specinfo.flags = 0
    wk32(specinfo + 0x10, 0);
    // ...
};
```

### 问题二：仅仅提权是不够的
在 iOS 11.3 及以后，除了 kernel 以外的进程无法 mount apfs 文件系统，因此我们还需要劫持 kernel 的 ucred，这里在 iOS 13 有个奇怪的点是不需要再做 Shenanigans Patch：
```c
// steal kern's ucred
uint64_t kern_ucred = rk64(kern_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
uint64_t my_ucred = rk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
wk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), kern_ucred);

// actions
// ...

// restore
wk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), my_ucred);
```

### 问题三：需要在 rename 前 unset snapshot flags
在 rename snapshot 以前，需要 patch `/dev/disk0s1s1` 的 `boot-snapshot` 的 `vnode->v_data->flags`：
```c
bool unsetSnapShotFlag(uint64_t newmnt) {
    uint64_t dev = rk64(newmnt + 0x980); // vnode.devvp
    uint64_t nameptr = rk64(dev + 0xb8); // vnode.name
    char name[20] = {0};
    kread(nameptr, &name, 20);
    printf("[+] found vnode: %s\n", name);
    
    uint64_t specinfo = rk64(dev + 0x78); // vnode.specinfo
    uint32_t flags = rk32(specinfo + 0x10); // specinfo.flags
    printf("[+] found dev flags %d\n", flags);
    
    uint64_t vnodelist = rk64(newmnt + 0x40); // vmount.vnodelist
    
    uint64_t pc_strlen = Find_strlen();
    while (vnodelist != 0) {
        printf("[+] recurse vnode list 0x%llx\n", vnodelist);
        
        uint64_t nameptr = rk64(vnodelist + 0xb8); // vnode.name
        char nameBuf[255] = {0};
        int nameLen = (int)Kernel_Execute(pc_strlen, nameptr, 0, 0, 0, 0, 0, 0);
        kread(nameptr, &nameBuf, nameLen);
        printf("[+] found vnode %s\n", name);
        NSString *name = [NSString stringWithFormat:@"%s", nameBuf];
        if ([name hasPrefix:@"com.apple.os.update-"]) {
            uint64_t vdata = rk64(vnodelist + 0xe0); // vnode.data
            uint32_t flag = rk32(vdata + 0x31); // vnode.data.flag
            printf("[+] found apfs flag: %d\n", flag);
            
            if ((flag & 0x40) != 0) {
                flag = flag & ~0x40;
                printf("[+] need unset snapshot flag to %d\n", flag);
                wk32(vdata + 0x31, flag); // vnode.data.flag
                return true;
            }
        }
        usleep(1000);
        vnodelist = rk64(vnodelist + 0x20); // vnode.next
    }
    return false;
}
```
这应该和 APFS 的某种特性有关，但笔者暂时没有找到相关的资料，希望大佬们指点。待后续了解到更多 APFS 相关的内容后再行补充。

### 问题四：boot-snapshot 的名称是随机的
boot-snapshot 的名称格式为 `com.apple.os.update-<boot-manifest-hash>`，其中 `boot-manifest-hash` 需要通过 IOKit 的 API 查询获得，这个 hash 在重启时不会变化，猜测是在固件更新时生成并创建 snapshot 和记录的。

因此在获取 boot-snapshot 的名称时需要先查询 hash，再拼接前缀：
```c
NSString* find_boot_snapshot() {
    io_registry_entry_t chosen = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
    CFDataRef data = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    if (!data) {
        return nil;
    }
    IOObjectRelease(chosen);
    
    CFIndex length = CFDataGetLength(data) * 2 + 1;
    char *manifestHash = calloc(length, sizeof(char));
    const uint8_t *hash = CFDataGetBytePtr(data);
    int i = 0;
    for (i = 0; i < CFDataGetLength(data); i++) {
        sprintf(manifestHash + i * 2, "%02X", hash[i]);
    }
    manifestHash[i * 2] = 0;
    
    NSString *systemSnapshot = [NSString stringWithFormat:@"com.apple.os.update-%s", manifestHash];
    printf("[+] find System Snapshot: <%s>\n", systemSnapshot.UTF8String);
    return systemSnapshot;
}
```

## 0x03 remount rootfs as r/w
经过 0x02 之后，系统会挂载 `/dev/disk0s1s1` 到 `/`，因此我们只需要修改 mount flags 然后 remount 刷新状态即可得到一个持久化的 r/w rootfs：
```c
uint64_t vmount = rk64(rootvnode + 0xd8); // vnode.mount
uint32_t vflag = rk32(vmount + 0x70); // vmount.vflag
vflag = vflag & ~(MNT_NOSUID | MNT_RDONLY);
wk32(vmount + 0x70, vflag & ~MNT_ROOTFS);

char * dev_path = strdup("/dev/disk0s1s1");
int ret = mount("apfs", "/", MNT_UPDATE, &dev_path);
free(dev_path);
wk32(vmount + 0x70, vflag);
printf("[+] not rename required remount with status %d\n", ret);
return ret == 0;
```

## 0x04 完整的处理流程
我们可以通过 `fs_snapshot_list` 去查询 rootfs `/` 已有的 snapshot，**在没有经过上述处理之前，通过这个函数并不能查询到 boot-snapshot，不知道苹果在这里是否做了特殊处理？**。在经过上述处理后，我们将 boot-snapshot 重命名为 orig-fs，且通过 `fs_snapshot_list` 函数是可以查询到的，通过这种差异我们可以判断文件系统是否已经做过 snapshot rename 处理，如果已经处理过我们只需要执行 0x03 中的 patch flags & remount 操作即可。

# 总结
到这里我们已经完成了对 iOS 13.1.1 rootfs remount 的分析，整个过程并不是十分复杂，但每个细节的背后都对应着大量知识。站在巨人的肩膀上分析固然容易，但如果信息变得逐渐封闭，需要靠自己去探索 bypass 方案时难度就会陡然上升。希望每一个学习和研究 Jailbreak 的人都能有这种危机感，抱着打破砂锅问到底的态度，去深入钻研其中的道理。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>

# 参考资料
1. [freebsd.org: Mounting and Unmounting File Systems. ](https://www.freebsd.org/doc/handbook/dirstructure.html)
2. [FreeBSD Manual Pages: BSD Kernel Developer's Manual VNODE(9)](https://www.freebsd.org/cgi/man.cgi?query=vnode)
3. [GeoSn0w: Jailbreaks Demystified - Remounting the File System
](https://geosn0w.github.io/Jailbreaks-Demystified/)
4. [Xiaolong Bai: The last line of defense:
understanding and
attacking Apple File
System on iOS](https://i.blackhat.com/eu-18/Thu-Dec-6/eu-18-Bai-The-Last-Line-Of-Defense-Understanding-And-Attacking-Apple-File-System-On-IOS.pdf#)
5. [Pwn20wnd & sbingner: Undecimus](https://github.com/pwn20wndstuff/Undecimus)
6. [Coolstar: Chimera13](https://github.com/coolstar/Chimera13/)
7. [jakeajames: jelbrekLib](https://github.com/jakeajames/jelbrekLib)