//go:build ignore

#include "vmlinux.h"

// #include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CHUNK_LIMIT 50
#define MAX_MSG_SIZE 401

struct event {
    u32 pid;
    u16 len;
    char buf[MAX_MSG_SIZE];
};

struct active_ssl_buf {
    const char* buf;
    u16 bufLen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct event);
    __uint(max_entries, 1);
} socket_data_event_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1);
} events SEC(".maps");


SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u16 bufLen = 0;
    u32 pid = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    bufLen = (u16)PT_REGS_PARM3(ctx);
    bpf_printk("enter: %d len: %d",pid,bufLen);
    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    if(buf == NULL){
        bpf_printk("buf is NULL ret :%d\n", -1);
        return 0;
    }
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.buf = buf;
    active_ssl_buf_t.bufLen = bufLen;
    bpf_map_update_elem(&active_ssl_read_args_map, &current_pid_tgid,
                        &active_ssl_buf_t, BPF_ANY);
    return 0;
}


SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    struct active_ssl_buf* active_ssl_buf_t =
        bpf_map_lookup_elem(&active_ssl_read_args_map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        const char* buf;
        u32 id = 0;
        struct event *e = bpf_map_lookup_elem(&socket_data_event_buffer_heap, &id);
        if(!e){
            bpf_printk("bpf_ringbuf_reserve is NULL return.");
            return 0;
        }
        e->pid = pid;
        e->len = active_ssl_buf_t->bufLen;
        u32 bufSize = (e->len < MAX_MSG_SIZE)?e->len:MAX_MSG_SIZE;
        bpf_probe_read(&buf, sizeof(const char*), &active_ssl_buf_t->buf);
        if(!buf){
            bpf_printk("buf is NULL return.");
            return 0;
        }
        bpf_probe_read_user(e->buf, bufSize, buf);
        bpf_printk("payload3: %s\n",e->buf);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    }
    bpf_map_delete_elem(&active_ssl_read_args_map, &current_pid_tgid);
    return 0;
}


SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
    u16 bufLen = 0;
    u32 pid = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    bufLen = (u16)PT_REGS_PARM3(ctx);
    bpf_printk("enter: %d len: %d",pid,bufLen);
    void *buf = PT_REGS_PARM2(ctx);
    if(buf == NULL){
        bpf_printk("buf is NULL ret :%d\n", -1);
        return 0;
    }
    u32 id = 0;
    struct event *e = bpf_map_lookup_elem(&socket_data_event_buffer_heap, &id);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve is NULL return.");
        return 0;
    }
    e->pid = pid;
    e->len = bufLen;
    u32 bufSize = (bufLen < MAX_MSG_SIZE)?bufLen:MAX_MSG_SIZE;
    bpf_probe_read_user(e->buf,bufSize,buf);
    bpf_printk("payload: %s\n",e->buf);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    bpf_printk("end. sizeof: %d",sizeof(*e));
    return 0;
}


SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u16 bufLen = 0;
    u32 pid = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    bufLen = (u16)PT_REGS_PARM3(ctx);
    bpf_printk("enter: %d len: %d",pid,bufLen);
    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    if(buf == NULL){
        bpf_printk("buf is NULL ret :%d\n", -1);
        return 0;
    }
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.buf = buf;
    active_ssl_buf_t.bufLen = bufLen;
    bpf_map_update_elem(&active_ssl_read_args_map, &current_pid_tgid,
                        &active_ssl_buf_t, BPF_ANY);
    return 0;
}


SEC("uretprobe/SSL_read_ex")
int probe_ret_SSL_read_ex(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    struct active_ssl_buf* active_ssl_buf_t =
        bpf_map_lookup_elem(&active_ssl_read_args_map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        const char* buf;
        u32 id = 0;
        struct event *e = bpf_map_lookup_elem(&socket_data_event_buffer_heap, &id);
        if(!e){
            bpf_printk("bpf_ringbuf_reserve is NULL return.");
            return 0;
        }
        e->pid = pid;
        e->len = active_ssl_buf_t->bufLen;
        u32 bufSize = (e->len < MAX_MSG_SIZE)?e->len:MAX_MSG_SIZE;
        bpf_probe_read(&buf, sizeof(const char*), &active_ssl_buf_t->buf);
        if(!buf){
            bpf_printk("buf is NULL return.");
            return 0;
        }
        bpf_probe_read_user(e->buf, bufSize, buf);
        bpf_printk("payload3: %s\n",e->buf);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    }
    bpf_map_delete_elem(&active_ssl_read_args_map, &current_pid_tgid);
    return 0;
}


SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx) {
    u16 bufLen = 0;
    u32 pid = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    // if(e.pid != 46187){
    //     return 0;
    // }
    // e.fd = (u16)PT_REGS_PARM1(ctx);
    bufLen = (u16)PT_REGS_PARM3(ctx);
    bpf_printk("enter: %d len: %d",pid,bufLen);
    void *buf = PT_REGS_PARM2(ctx);
    if(buf == NULL){
        bpf_printk("buf is NULL ret :%d\n", -1);
        return 0;
    }
    u32 id = 0;
    struct event *e = bpf_map_lookup_elem(&socket_data_event_buffer_heap, &id);
    // struct event *e;
    // e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve is NULL return.");
        return 0;
    }
    e->pid = pid;
    e->len = bufLen;
    u32 bufSize = (bufLen < MAX_MSG_SIZE)?bufLen:MAX_MSG_SIZE;
    bpf_probe_read_user(e->buf,bufSize,buf);
    // bpf_printk("payload: %s\n",e->buf);
    // bpf_ringbuf_submit(e,0);
    // bpf_ringbuf_output(&events,e,sizeof(*e), 0);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    bpf_printk("end. sizeof: %d",sizeof(*e));
    // int bytes_sent = 0;
    // unsigned int i = 0;
// #pragma unroll
// for(i = 0; i < CHUNK_LIMIT; ++i){
//     if(e->len < bytes_sent){
//         return 0;
//     }
//     int bytes_remaining = e->len - bytes_sent;
//     if(bytes_remaining < 0 ){
//         bpf_printk("bytes_remaining size is zero or negative, breaking loop.");
//         break;
//     }
//     u16 current_size = (bytes_remaining > MAX_MSG_SIZE && ( i != CHUNK_LIMIT - 1)) ?MAX_MSG_SIZE:bytes_remaining;
//     if (current_size <= 0)
//     {
//         bpf_printk("Current size is zero or negative, breaking loop.");
//         break;
//     }
//     // e->len = current_size;
//     bpf_probe_read(&e->buf,current_size,buf+bytes_sent);
//     bpf_ringbuf_submit(e, 0);
//     bytes_sent += current_size;
//     if (bufLen == bytes_sent)
//     {
//         return 0;
//     }
// }
    return 0;
}


// SEC("kprobe/do_sys_openat2")
// int kprobe__do_sys_openat2(struct pt_regs *ctx) {
//     struct event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }

//     e->pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_probe_read(&e->filename, sizeof(e->filename), (void *)PT_REGS_PARM2(ctx));

//     bpf_ringbuf_submit(e, 0);

//     return 0;
// }

char _license[] SEC("license") = "GPL";
