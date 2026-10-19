#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			__u64 regs[31];
			__u64 sp;
			__u64 pc;
			__u64 pstate;
		};
	};
	__u64 orig_x0;
	__s32 syscallno;
	__u32 unused2;
	__u64 orig_addr_limit;
	__u64 pmr_save;
	__u64 stackframe[2];
	__u64 lockdep_hardirqs;
	__u64 exit_rcu;
};
#endif

/* Kernel structs read through CO-RE: only the fields the programs read, matched by
   name against the kernel's BTF when the programs are loaded, which takes the
   offsets from there. Their layout here does not matter, so they are never
   copied whole, only field by field:
   - the record of a tracepoint (trace_event_raw_*, syscall_trace_*) is the
     program's context, read straight from it: args->pid. CO-RE patches the
     offset of the load. An array field (an address) is copied with
     BPF_CORE_READ_INTO: a copy needs the field's address in a register, and the
     verifier does not let a program load through a moved context pointer.
   - a struct behind any other kernel pointer (a kprobe argument) is read with
     BPF_CORE_READ*, a bpf_probe_read_kernel at the patched offset: the
     verifier does not let a program load from such a pointer.
   The traced application's memory has no BTF; it is read with bpf_read. */
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct in6_addr {
	__u8 s6_addr[16];
};

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

union nf_inet_addr {
	__be32 ip6[4];
};

union nf_conntrack_man_proto {
	__be16 all;
};

struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	__u16 l3num;
};

struct nf_conntrack_tuple {
	struct nf_conntrack_man src;
	struct {
		union nf_inet_addr u3;
		union {
			__be16 all;
		} u;
		__u8 protonum;
	} dst;
};

struct nf_conntrack_tuple_hash {
	struct nf_conntrack_tuple tuple;
};

struct nf_conn {
	struct nf_conntrack_tuple_hash tuplehash[2];
};

struct path {
	void *mnt;
};

struct trace_event_raw_task_newtask {
	int pid;
	unsigned long clone_flags;
};

/* not trace_event_raw_sched_process_template: sched_process_exit has its own
   class (with group_dead), where pid is at another offset */
struct trace_event_raw_sched_process_exit {
	int pid;
};

struct trace_event_raw_mark_victim {
	int pid;
};

struct trace_event_raw_tcp_retransmit_skb {
	__u16 sport;
	__u16 dport;
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct trace_event_raw_inet_sock_set_state {
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 protocol;
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

/* The records of the syscalls/sys_enter_* and sys_exit_* tracepoints
   (kernel/trace/trace.h). The fields are loaded straight from the context: CO-RE
   patches the offset of the load, which costs no instruction. */
struct syscall_trace_enter {
	unsigned long args[6];
};

struct syscall_trace_exit {
	long ret;
};

/* The socket behind a file descriptor of the current task (socket_of_fd):
   task->files->fdt->fd[fd] is a struct file, a socket's private_data its
   struct socket, whose sk is the struct sock (sock_common first). */
struct fdtable {
	unsigned int max_fds;
	struct file **fd;
};

struct files_struct {
	struct fdtable *fdt;
};

struct task_struct {
	struct files_struct *files;
};

struct inode {
	unsigned short i_mode;
};

struct file {
	struct inode *f_inode;
	void *private_data;
};

struct sock;

struct socket {
	short type;
	struct sock *sk;
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */