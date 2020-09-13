## shmapperd, shmapperctl, libshmapper, libshmap

`shmapperd` is a shared-memory D-Bus [mapper][1] [implementation][2]. `mapper`
client applications can link against `libshmapper` and do lookups in-process,
saving 4 context switches and queuing up behind other events in the mapper
daemon.

[1]: https://github.com/openbmc/docs/blob/master/architecture/object-mapper.md
[2]: https://github.com/openbmc/phosphor-objmgr

## libshmap

`libshmap` provides applications with a toolkit (heap allocator, locking
primitives and common data-structures) for process-shared-memory that is backed
by a transparently movable and resizable shared-memory pool. It lifts two
requirements that are often levelled at process-shared-memory applications:

1. That applications only work over `fork()` to guarantee address space
   layouts, and
2. That the pool be set to a pre-defined size (as it cannot be moved)

The result is that it's now possible to treat process-shared-memory in much the
same way as regular heap memory.

`libshmap` leverages [`sparse`][3] annotations to provide compile-time
assurance that private and shared pointers are correctly handled. This
exploitation of `sparse` address spaces reduces the sharp edges associated with
process-shared-memory designs.

[3]: https://sparse.docs.kernel.org/en/latest/

Use of `libshmap` is demonstrated in the fuzzing binaries (e.g.
[fuzz/vec.c](fuzz/vec.c)). Its header is [shmap.h](shmap.h).

Currently `libshmap` provides the following process-shared-memory
data-structures:

* Vector: [vec.c](vec.c)
* Map: [map.c](map.c)
* Set: [set.c](set.c)

And the following process-shared-memory locking primitives, in
[shmap.c](shmap.c):

* Mutexes
* Conditions
* Reader-writer locks

The data-structures are implemented on top of the heap memory provided by the
slab-allocator in [alloc.c](alloc.c). The shared memory allocator
implementation:

1. Uses fine-grained locking to exploit concurrency
2. Coalesces adjacent free regions to minimise fragmentation

The shared-memory backing the slab-allocator is provided by [pool.c](pool.c),
which handles the dynamic remapping under memory pressure.

The shared-memory pool uses a reader-writer concurrency model for its metadata:

1. All accesses into the pool require the read-lock (both reads and writes).
2. All changes to the pool metadata (size) require the write-lock

The outcome is that no invalid shared pointers (validly pointing beyond the
shared mapping) can be read by an application holding a read-lock on the pool.

The `libshmap` API and implementation is still in its early phase of
development. If you have suggestions or complaints, do get in touch!
