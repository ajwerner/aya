#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} RESULTS SEC(".maps");

#define BUF_LEN 1<<10
#define QUEUE_MAX_LEN 1000

typedef enum type_id {
    PROGRAM_TYPE_FOO = 1,
    PROGRAM_TYPE_BAR = 2,
    PROGRAM_TYPE_STR = 3,
} type_id_t; 

typedef struct queue_entry {
    void *ptr;
    type_id_t type;
    __u32 len;
} queue_entry_t;

typedef struct queue {
    unsigned int tail;
    unsigned int head;
    queue_entry_t entries[QUEUE_MAX_LEN];
} queue_t;

queue_entry_t *pop(queue_t *queue) {
    if (queue->head == queue->tail) {
        return NULL;
    }
    if (queue->head >= QUEUE_MAX_LEN) {
        return NULL;
    }
    queue_entry_t *entry = &queue->entries[queue->head];
    queue->head++;
    return entry;
}

typedef __u32 piece_id_t;

piece_id_t enqueue(queue_t *queue, type_id_t type, void *ptr, __u32 len) {
    if (ptr == NULL) {
        return 0;
    }
    __u64 idx = queue->tail;
    if (idx < QUEUE_MAX_LEN-2) {
        queue_entry_t *entry = &queue->entries[idx];
        *entry = (queue_entry_t) {.type = type, .ptr = ptr, .len = len};
        queue->tail++;   
    }
    return queue->tail;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, queue_t);
    __uint(max_entries, 1);
} QUEUE SEC(".maps");

#define PTR(x) __u64

typedef struct Bar {
    unsigned long long int c;
    unsigned long long int d;
} Bar_t;

typedef struct Str {
    unsigned long long int len;
    unsigned long long int ptr;
} Str_t;

typedef struct Foo {
    unsigned long long a;
    unsigned long long b;
    Str_t str;
    PTR(Foo_t) foo;
    PTR(Bar_t) bar;
} Foo_t;

typedef struct output_buffer {
    char *buffer;
    unsigned int offset;
} output_buffer_t;

static void write_output_buffer_piece_header(output_buffer_t *b, __u32 len) {
    if (b->offset+sizeof(__u32) >= BUF_LEN) {
        return;
    }
    __u32 *header = (__u32 *)(&b->buffer[b->offset]);
    b->offset += sizeof(__u32);
}

static void enqueue_str_children(queue_t *queue, Str_t *str) {
    enqueue(queue, PROGRAM_TYPE_STR, (void *)(str->ptr), (__u32)(str->len));
}

static void enqueue_foo_children(queue_t *queue, Foo_t *foo) {
    enqueue(queue, PROGRAM_TYPE_BAR, (void *)(foo->bar), 0);
    enqueue(queue, PROGRAM_TYPE_FOO, (void *)(foo->foo), 0);
    enqueue_str_children(queue, &foo->str);
}


static long loop_queue(__u32 idx, output_buffer_t *ctx) {
    output_buffer_t *context = (output_buffer_t *)ctx;
    const __u32 zero = 0;
    queue_t *queue = bpf_map_lookup_elem(&QUEUE, &zero);
    if (!queue) {
        return 1;
    }
    queue_entry_t *entry = pop(queue);
    if (!entry) {
        return 1;
    }
    switch (entry->type) {
        case PROGRAM_TYPE_FOO:
            write_output_buffer_piece_header(context, sizeof(Foo_t));
            if (context->offset+sizeof(Foo_t) >= BUF_LEN) {
                return 1;
            }
            if (bpf_probe_read_user(&context->buffer[context->offset], sizeof(Foo_t), entry->ptr)) {
                return 1;
            }
            if (queue->tail + 2 >= QUEUE_MAX_LEN) {
                return 1;
            }

            Foo_t *foo = (Foo_t *)(&context->buffer[context->offset]);
            if (context->offset+sizeof(Foo_t) >= BUF_LEN) {
                return 1;
            }
            context->offset += sizeof(Foo_t);
            enqueue_foo_children(queue, foo);
            break;
        case PROGRAM_TYPE_BAR:
            write_output_buffer_piece_header(context, sizeof(Bar_t));
            if (context->offset+sizeof(Bar_t) >= BUF_LEN) {
                return 1;
            }
            if (bpf_probe_read_user(context->buffer+context->offset, sizeof(Bar_t), entry->ptr)) {
                return 1;
            }
            context->offset += sizeof(Bar_t);
            break;
        case PROGRAM_TYPE_STR:
            if (entry->len > BUF_LEN) {
                return 1;
            }
            context->offset *= 2;
            bpf_printk("offset: %d\n", context->offset);
            if (bpf_probe_read_user(context->buffer+context->offset, 1024, entry->ptr)) {
                return 1;
            }
            context->offset += entry->len;
            break;
        default:
            return 1;
    }

    return 0;
}


SEC("uprobe/test_ring_buf_serialize")
int BPF_KPROBE(test_ring_buf_serialize, void *foo_ptr) {
    const __u32 zero = 0;
    queue_t *queue = bpf_map_lookup_elem(&QUEUE, &zero);
    if (!queue) {
        return 0;
    }
    queue->head = 0;
    queue->tail = 0;
    void *buf = bpf_ringbuf_reserve(&RESULTS, BUF_LEN, 0);
    if (!buf) {
        return 0;
    }
    output_buffer_t context = {
        .buffer = buf,
        .offset = 0,
    };
    enqueue(queue, PROGRAM_TYPE_FOO, foo_ptr, 0);

    bpf_loop(100, loop_queue, &context, 0);
    bpf_ringbuf_submit(buf, 0);
    return 0;
}
