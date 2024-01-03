//go:build ignore

#include "vmlinux.h"

// #include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define CHUNK_LIMIT 50
#define MAX_MSG_SIZE 256

struct event {
    u32 pid;
    // u16 fd;
    u16 len;
    char buf[MAX_MSG_SIZE];
};

/* BPF perfbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");


SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write(struct pt_regs *ctx) {
    struct event e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    // if(e.pid != 46187){
    //     return 0;
    // }
    bpf_printk("enter: %d",e.pid);
    // e.fd = (u16)PT_REGS_PARM1(ctx);
    e.len = (u16)PT_REGS_PARM3(ctx);
    void *buf = PT_REGS_PARM2(ctx);
    if(buf == NULL){
        bpf_printk("buf is NULL ret :%d\n", -1);
        return 0;
    }
    bpf_probe_read_user(&e.buf,sizeof(e.buf),buf);
    bpf_printk("test len: %d",e.len);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}


// SEC("uprobe/recvmsg")
// int uprobe_recvmsg(struct pt_regs *ctx) {
//     struct msghdr sd ;
//     struct event e = {};
//     e.pid = bpf_get_current_pid_tgid() >> 32;
//     if(e.pid != 46187){
//         return 0;
//     }
//     bpf_printk("enter: %d",222);
//     e.fd = (u16)PT_REGS_PARM1(ctx);
//     e.len = (u16)PT_REGS_PARM3(ctx);
//     void *buf = PT_REGS_PARM2(ctx);
//     if(buf == NULL){
//         bpf_printk("buf is NULL ret :%d\n", -1);
//         return 0;
//     }
//     bpf_probe_read_user(&e.buf,sizeof(e.buf),buf);
//     bpf_printk("test fd: %d len: %d",e.fd,e.len);
//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
//     return 0;
// }

// sendto

// struct event {
//     u32 pid;
//     u16 fd;
//     u16 len;
//     char buf[256];
// };

// SEC("uprobe/sendto")
// int uprobe_sendto(struct pt_regs *ctx) {
//     bpf_printk("enter: %d",222);
//     struct event e = {};
//     e.pid = bpf_get_current_pid_tgid() >> 32;
//     e.fd = (u16)PT_REGS_PARM1(ctx);
//     e.len = (u16)PT_REGS_PARM3(ctx);
//     void *buf = PT_REGS_PARM2(ctx);
//     if(buf == NULL){
//         bpf_printk("buf is NULL ret :%d\n", -1);
//         return 0;
//     }
//     bpf_probe_read_user(&e.buf,sizeof(e.buf),buf);
//     // if(e.count > 256){
//     //     bpf_probe_read_user(&e.buf,sizeof(e.buf),buf);
//     // }else{
//     //     bpf_probe_read_user(&e.buf,e.count,buf);
//     // }    
//     bpf_printk("test fd: %d count: %d ",e.fd,e.len);
//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

//     return 0;
// }

//write

// struct event {
//     u32 pid;
//     u16 fd;
//     u32 len;
//     char buf[256];
// };

// SEC("uprobe/write")
// int uprobe_write(struct pt_regs *ctx) {
//     bpf_printk("enter: %d",222);
//     struct event e = {};
//     e.pid = bpf_get_current_pid_tgid() >> 32;
//     e.fd = (u16)PT_REGS_PARM1(ctx);
//     e.len = (u32)PT_REGS_PARM3(ctx);
//     void *buf = PT_REGS_PARM2(ctx);
//     if(buf == NULL){
//         bpf_printk("buf is NULL ret :%d\n", -1);
//         return 0;
//     }
//     bpf_probe_read_user(&e.buf,sizeof(e.buf),buf);
//     bpf_printk("test fd: %d",e.fd);
//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
//     return 0;
// }


// accept4

// struct event {
//     u32 pid;
//     u16 fd;
//     u16 port;
//     u32 ipv4;
//     // char buf[256];
//     // char comm[16];
// };


// SEC("uprobe/accept4")
// int uprobe_accept4(struct pt_regs *ctx) {
//     bpf_printk("enter: %d",222);
//     struct event e = {};
//     e.pid = bpf_get_current_pid_tgid() >> 32;
//     e.fd = (u16)PT_REGS_PARM1(ctx);
//     struct sockaddr *addr = (struct sockaddr*)PT_REGS_PARM2(ctx);
//     if(addr == NULL){
//         bpf_printk("client_addr is NULL ret :%d\n", -1);
//         return 0;
//     }
//     // sa_family_t family = 0;
//     // bpf_probe_read(&family,sizeof(family),&addr->sa_family);
//     // if(family == 2){
//     //     bpf_printk("family :%d\n", family);
//     // }else{
//     //     bpf_printk("family2 :%d\n", family);
//     // }
//     bpf_probe_read(&e.port,sizeof(e.port),&(((struct sockaddr_in*)addr)->sin_port));
//     e.port = bpf_ntohs(e.port);
//     bpf_probe_read(&e.ipv4,sizeof(e.ipv4),&(((struct sockaddr_in*)addr)->sin_addr));
//     bpf_printk("ipv4: %ld",e.ipv4);
//     // bpf_printk("test fd: %d count: %d ",e.fd,e.port);
//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

//     return 0;
// }

// connect 
// struct event {
//     u32 pid;
//     u16 fd;
//     u16 port;
//     u32 ipv4;
//     // char buf[256];
//     // char comm[16];
// };

// SEC("uprobe/connect")
// int uprobe_connect(struct pt_regs *ctx) {
//     bpf_printk("enter: %d",222);
//     struct event e = {};
//     e.pid = bpf_get_current_pid_tgid() >> 32;
//     e.fd = (u16)PT_REGS_PARM1(ctx);
//     // e.count = (u32)PT_REGS_PARM3(ctx);
//     sa_family_t family = 0;
//     struct sockaddr *addr = (struct sockaddr*)PT_REGS_PARM2(ctx);
//     if(addr == NULL){
//         bpf_printk("client_addr is NULL ret :%d\n", -1);
//         return 0;
//     }
//     bpf_printk("addr: %x ",addr);
//     bpf_probe_read(&family,sizeof(family),&addr->sa_family);
//     if(family == 2){
//         bpf_printk("family :%d\n", family);
//     }else{
//         bpf_printk("family2 :%d\n", family);
//     }
//     bpf_probe_read(&e.port,sizeof(e.port),&(((struct sockaddr_in*)addr)->sin_port));
//     e.port = bpf_ntohs(e.port);
//     bpf_probe_read(&e.ipv4,sizeof(e.ipv4),&(((struct sockaddr_in*)addr)->sin_addr));
//     // e.ipv4 = bpf_ntohl(e.ipv4);
//     // bpf_printk("ipv4 :%ld\n", e.ipv4);
//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

//     return 0;
// }


char _license[] SEC("license") = "GPL";
