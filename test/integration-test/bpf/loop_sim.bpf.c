#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-function"

#include <vmlinux.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, uint64_t);
} percpu_array_8b SEC(".maps");


#define MY_ARRAY_SIZE 48

typedef uint64_t my_array_t[MY_ARRAY_SIZE];

static const uint32_t zero = 0;

__attribute__((noinline))
bool d_func(int a) {
    return (a % 2) > 0;
}

__attribute__((noinline))
bool c_func(int a) {
    return d_func(a);
}


__attribute__((noinline))
bool b_func(int a) {
    return c_func(a);
}

__attribute__((noinline))
bool a_func(int a) {
    return b_func(a);
}

__attribute__((noinline))
bool target_function(struct pt_regs* ctx) {
    if (!ctx) {
        return false;
    }
    uint64_t *ptr = (uint64_t *)bpf_map_lookup_elem(&percpu_array_8b, &zero);
    if (!ptr) {
        return false;
    }
    *ptr += 1;
    if ((*ptr % 10) == 0) {
        bpf_printk("target_function: %llu %llx\n", *ptr, ctx->ip);
    }
    /*
    my_array_t arr;
    for (int i = 0; i < MY_ARRAY_SIZE; i++) {
        arr[i] = i;
    }
    int idx = *ptr % MY_ARRAY_SIZE;
    for (int i = 0; i < MY_ARRAY_SIZE; i++) {
        bpf_printk("target_function: %llu %llx\n", *ptr, &arr[i]);
    }
    return true;
    */
   return true;
}

#define LOOP_L3_COUNT 100

__attribute__((noinline))
bool loop_l3(struct pt_regs* ctx) {
    for (unsigned long long int i = 0; i < LOOP_L3_COUNT; i++) {
        if (!target_function(ctx)) {
            return false;
        }
    }
    return true;
}

bool bad_loop_function(struct pt_regs* ctx) { 
    bool result;
    asm volatile ( 
        "r7 = %[ctx]\n"              /* load ctx into r7 for function argument */
        "r1 = 0\n"
        "loop_start%=:\n"
        "r8 = r1\n"
        "if r8 == %[loop_count] goto return_true%=\n"  /* if i >= count, jump to loop_end */
        "r1 = r7\n"                    /* load ctx into r1 for function argument */
        "call %[next_call]\n"          /* call next_fn */
        "r1 = r8\n"
        "r1 += 1\n"                    /* i++ */
        "r0 &= 1\n"
        "if r0 != 0 goto loop_start%=\n"   /* if result == 0, return false */
        "return_true%=:\n"             /* return true */
        "r0 = 1\n"
        "return%=:\n"
        "%[result] = r0\n"
        : [result]"=r"(result) 
        : [loop_count]"i"(1000), [loop_count_less_1]"i"(1000-1), [next_call]"i"(target_function), [ctx]"r"(ctx) 
        : "r0", "r1", "r2", "r3", "r4", "r5", "r7", "r8" 
    ); 
    return result; 
}

#define DEFINE_LOOP_FUNCTION_2(name, count, next_fn) \
bool name(struct pt_regs* ctx) { \
    bool result; \
    asm volatile ( \
        "r7 = %[ctx]\n"              /* load ctx into r7 for function argument */ \
        "r1 = 0\n"                   /* i = 0 (using r8 as it's callee-saved) */ \
        "loop_start%=:\n" \
        "r8 = r1\n" \
        "r1 = r7\n"                    /* load ctx into r1 for function argument */ \
        "call %[next_call]\n"          /* call next_fn */ \
        "r1 = r8\n" \
        "r1 += 1\n" \
        "if r0 == 0 goto return%=\n"   /* if result == 0, return false */ \
        "r1 += 1\n"                    /* i++ */ \
        "if r1 == %[loop_count] goto return_true%=\n"  /* if i >= count, jump to loop_end */ \
        "goto loop_start%=\n"          /* jump back to loop_start */ \
        "return_true%=:\n"             /* return true */ \
        "r0 = 1\n"                     /* set result = true */ \
        "return%=:\n" \
        "%[result] = r0\n" \
        \
        : [result]"=r"(result) \
        : [loop_count]"i"(count), [next_call]"i"(next_fn), [ctx]"r"(ctx) \
        : "r0", "r1", "r2", "r3", "r4", "r5", "r7", "r8" \
    ); \
    return result; \
}

#define DEFINE_LOOP_FUNCTION(name, count, next_fn) \
bool name(struct pt_regs* ctx) { \
    bool result; \
    asm volatile ( \
        "r7 = %[ctx]\n"              /* load ctx into r7 for function argument */ \
        "r8 = 0\n"                   /* i = 0 (using r8 as it's callee-saved) */ \
        "loop_start%=:\n" \
        "r1 = r7\n"                    /* load ctx into r1 for function argument */ \
        "call %[next_call]\n"          /* call next_fn */ \
        "if r0 == 0 goto return%=\n"   /* if result == 0, return false */ \
        "r8 += 1\n"                    /* i++ */ \
        "if r8 == %[loop_count] goto return_true%=\n"  /* if i >= count, jump to loop_end */ \
        "goto loop_start%=\n"          /* jump back to loop_start */ \
        "return_true%=:\n"             /* return true */ \
        "r0 = 1\n"                     /* set result = true */ \
        "return%=:\n" \
        "%[result] = r0\n" \
        \
        : [result]"=r"(result) \
        : [loop_count]"i"(count), [next_call]"i"(next_fn), [ctx]"r"(ctx) \
        : "r0", "r1", "r2", "r3", "r4", "r5", "r7", "r8" \
    ); \
    return result; \
}

// Replace the existing loop_l2 and loop_l1 functions with macro calls
__attribute__((noinline))
DEFINE_LOOP_FUNCTION_2(loop_l2, 100, loop_l3)

inline
DEFINE_LOOP_FUNCTION(loop_l1, 100, loop_l2)

SEC("uprobe") int loop_sim(struct pt_regs* ctx) {
    return loop_l1(ctx);
}
