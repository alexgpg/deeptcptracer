#!/usr/bin/python
#
# deeptcptracer   Trace TCP connections.
#                 For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: deeptcptracer [-h] [-t] [-p PID] [-N NETNS]
#
# Inspired by tcptracer and tcpretrans from iovisor/bcc.
#
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
from bcc import BPF

import argparse as ap
import ctypes
import datetime
import errno
import sys
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

parser = ap.ArgumentParser(description="Trace TCP connections",
                           formatter_class=ap.RawDescriptionHelpFormatter)
parser.add_argument("-t", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid", default=0, type=int,
                    help="trace this PID only")
parser.add_argument("-N", "--netns", default=0, type=int,
                    help="trace this Network Namespace only")
parser.add_argument("-K", "--kstack", action="store_true",
                    help="Print kernel stack")
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

// Maybe include?
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

#define EVT_SRC_TCP_SET_STATE_FUNC 1
#define EVT_SRC_TCP_RETRANSMIT_SKB 2
#define EVT_SRC_TCP_FIN            3
#define EVT_SRC_TCP_RESET          4
#define EVT_SRC_TCP_SEND_FIN       5
#define EVT_SRC_TCP_ACK            6
#define EVT_SRC_TCP_ACCEPT         7
#define EVT_SRC_TCP_ERR_REPORT     8

struct tcp_ipv4_event_t {
    u64 ts_ns;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8 ip;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
    u8 new_tcp_state;
    u8 prev_tcp_state;
    u8 evt_src;
    u64 stack_id;
    int sk_err; // From struct sock.sk_err
};

BPF_PERF_OUTPUT(tcp_ipv4_event);

struct tcp_ipv6_event_t {
    u64 ts_ns;
    u32 type;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};
BPF_PERF_OUTPUT(tcp_ipv6_event);

##DEFINE_KSTACK##

#ifdef KSTACK
BPF_STACK_TRACE(stack_traces, 128);
#endif

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};

struct ipv6_tuple_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};

struct pid_comm_t {
    u64 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(tuplepid_ipv4, struct ipv4_tuple_t, struct pid_comm_t);
BPF_HASH(tuplepid_ipv6, struct ipv6_tuple_t, struct pid_comm_t);

BPF_HASH(connectsock, u64, struct sock *);

// TODO: Clean after close
BPF_HASH(sktopidmap, struct sock *, u64);
BPF_HASH(sktopidmap2, struct sock *, struct pid_comm_t);

static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
{
  u32 net_ns_inum = 0;
  u32 saddr = skp->__sk_common.skc_rcv_saddr;
  u32 daddr = skp->__sk_common.skc_daddr;
  struct inet_sock *sockp = (struct inet_sock *)skp;
  u16 sport = sockp->inet_sport;
  u16 dport = skp->__sk_common.skc_dport;
#ifdef CONFIG_NET_NS
  possible_net_t skc_net = skp->__sk_common.skc_net;
  bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif

  ##FILTER_NETNS##

  tuple->saddr = saddr;
  tuple->daddr = daddr;
  tuple->sport = sport;
  tuple->dport = dport;
  tuple->netns = net_ns_inum;

  // if addresses or ports are 0, ignore
  if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
      return 0;
  }

  return 1;
}

static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp)
{
  u32 net_ns_inum = 0;
  unsigned __int128 saddr = 0, daddr = 0;
  struct inet_sock *sockp = (struct inet_sock *)skp;
  u16 sport = sockp->inet_sport;
  u16 dport = skp->__sk_common.skc_dport;
#ifdef CONFIG_NET_NS
  possible_net_t skc_net = skp->__sk_common.skc_net;
  bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif
  bpf_probe_read(&saddr, sizeof(saddr),
                 skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
  bpf_probe_read(&daddr, sizeof(daddr),
                 skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

  ##FILTER_NETNS##

  tuple->saddr = saddr;
  tuple->daddr = daddr;
  tuple->sport = sport;
  tuple->dport = dport;
  tuple->netns = net_ns_inum;

  // if addresses or ports are 0, ignore
  if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
      return 0;
  }

  return 1;
}

static bool check_family(struct sock *sk, u16 expected_family) {
  u64 zero = 0;
  u16 family = sk->__sk_common.skc_family;
  return family == expected_family;
}

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
{
  u64 pid = bpf_get_current_pid_tgid();

  ##FILTER_PID##

  // stash the sock ptr for lookup on return
  connectsock.update(&pid, &sk);

  // NEW
  struct pid_comm_t pp = { };
  pp.pid = pid;
  bpf_get_current_comm(&pp.comm, sizeof(pp.comm));
  sktopidmap.update(&sk, &pid);
  // TODO: Rename to sktoprocmap
  sktopidmap2.update(&sk, &pp);

  // TODO: Clean hashes after connection close.
  return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
  int ret = PT_REGS_RC(ctx);
  u64 pid = bpf_get_current_pid_tgid();

  struct sock **skpp;
  skpp = connectsock.lookup(&pid);
  if (skpp == 0) {
      return 0;       // missed entry
  }

  connectsock.delete(&pid);

  if (ret != 0) {
      // failed to send SYNC packet, may not have populated
      // socket __sk_common.{skc_rcv_saddr, ...}
      return 0;
  }

  // pull in details
  struct sock *skp = *skpp;
  struct ipv4_tuple_t t = { };
  if (!read_ipv4_tuple(&t, skp)) {
      return 0;
  }

  struct pid_comm_t p = { };
  p.pid = pid;
  bpf_get_current_comm(&p.comm, sizeof(p.comm));

  tuplepid_ipv4.update(&t, &p);

  return 0;
}

int trace_tcp_ack_entry(struct pt_regs *ctx, struct sock *sk, const struct sk_buff *skb, int flag) {
  // TODO: Filter namespace
  if (check_family(sk, AF_INET)) {
    u32 nwin;
    u16 win_no;
    if (skb->head) {
      struct tcphdr *hdr = (struct tcphdr *)(skb->head + skb->transport_header);
      if (hdr) {
        win_no = hdr->window;
        nwin = ntohs(win_no);
      }
    }

    if (nwin > 0) {
      return 0;
    }

    struct tcp_ipv4_event_t evt4 = { };
    evt4.evt_src = EVT_SRC_TCP_ACK;

    struct ipv4_tuple_t t = { };
    read_ipv4_tuple(&t, sk);

    evt4.ts_ns = bpf_ktime_get_ns();

    evt4.saddr = t.saddr;
    evt4.daddr = t.daddr;
    evt4.sport = ntohs(t.sport);
    evt4.dport = ntohs(t.dport);

    u64 pid = 0;
    struct pid_comm_t *pcomm;
    pcomm = sktopidmap2.lookup(&sk);
    if (pcomm) {
      pid = pcomm->pid;
      int i;
      for (i = 0; i < TASK_COMM_LEN; i++) {
        evt4.comm[i] = pcomm->comm[i];
      }
    }

    ##FILTER_PID##

    evt4.pid = pid;
    evt4.sk_err = sk->sk_err;

    evt4.new_tcp_state = sk->__sk_common.skc_state;
    evt4.prev_tcp_state = sk-> __sk_common.skc_state;

#ifdef KSTACK
    evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

    tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  } else {
    // TODO: Add IPv6 support. Now it isn't supported.
  }

  return 0;
}

int trace_tcp_reset_entry(struct pt_regs *ctx, struct sock *sk) {
  // TODO: Filter namespace
  if (check_family(sk, AF_INET)) {
      struct tcp_ipv4_event_t evt4 = { };
      evt4.evt_src = EVT_SRC_TCP_RESET;
      evt4.ts_ns = bpf_ktime_get_ns();

      struct ipv4_tuple_t t = { };
      read_ipv4_tuple(&t, sk);

      evt4.saddr = t.saddr;
      evt4.daddr = t.daddr;
      evt4.sport = ntohs(t.sport);
      evt4.dport = ntohs(t.dport);

      evt4.prev_tcp_state = sk->sk_state;
      evt4.new_tcp_state = sk->sk_state;

      // Get PID and COMM
      // More robust way. Cause bpf_get_current_pid_tgid and bpf_get_current_comm
      // returns sometimes returns 0 and swapper/1
      u64 pid = 0;
      struct pid_comm_t *pcomm;
      pcomm = sktopidmap2.lookup(&sk);
      if (pcomm) {
        pid = pcomm->pid;
        int i;
        for (i = 0; i < TASK_COMM_LEN; i++) {
          evt4.comm[i] = pcomm->comm[i];
        }
      } else {
        // Try from bpf_get_current_pid_tgid and bpf_get_current_comm?
        pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));
      }

      ##FILTER_PID##

      evt4.pid = pid >> 32;
      evt4.sk_err = sk->sk_err;

#ifdef KSTACK
      evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

      tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  } else {
    // TODO: Add IPv6 support. Now it isn't supported.
  }
  return 0;
}

int trace_tcp_fin_entry(struct pt_regs *ctx, struct sock *sk) {
  if (check_family(sk, AF_INET)) {
    struct tcp_ipv4_event_t evt4 = { };
    evt4.evt_src = EVT_SRC_TCP_FIN;
    evt4.ts_ns = bpf_ktime_get_ns();

    struct ipv4_tuple_t t = { };
    read_ipv4_tuple(&t, sk);

    evt4.saddr = t.saddr;
    evt4.daddr = t.daddr;
    evt4.sport = ntohs(t.sport);
    evt4.dport = ntohs(t.dport);

    evt4.prev_tcp_state = sk->sk_state;
    evt4.new_tcp_state = sk->sk_state;

    // Get PID and COMM
    // More robust way. Cause bpf_get_current_pid_tgid and bpf_get_current_comm
    // returns sometimes returns 0 and swapper/1
    u64 pid = 0;
    struct pid_comm_t *pcomm;
    pcomm = sktopidmap2.lookup(&sk);
    if (pcomm) {
      pid = pcomm->pid;
      int i;
      for (i = 0; i < TASK_COMM_LEN; i++) {
        evt4.comm[i] = pcomm->comm[i];
      }
    } else {
      // Try from bpf_get_current_pid_tgid and bpf_get_current_comm?
      pid = bpf_get_current_pid_tgid();
      bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));
    }

    ##FILTER_PID##

    evt4.pid = pid >> 32;
    evt4.sk_err = sk->sk_err;

#ifdef KSTACK
    evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

    tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  } else {
    // TODO: Add IPv6 support. Now it isn't supported.
  }
  return 0;
}

int trace_tcp_send_fin_entry(struct pt_regs *ctx, struct sock *sk) {
  u64 pid = bpf_get_current_pid_tgid();

  ##FILTER_PID##

  if (check_family(sk, AF_INET)) {
    struct tcp_ipv4_event_t evt4 = { };
    evt4.evt_src = EVT_SRC_TCP_SEND_FIN;
    evt4.pid = pid >> 32;
    bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));
    evt4.sk_err = sk->sk_err;

    struct ipv4_tuple_t t = { };
    read_ipv4_tuple(&t, sk);

    evt4.ts_ns = bpf_ktime_get_ns();

    evt4.saddr = t.saddr;
    evt4.daddr = t.daddr;
    evt4.sport = ntohs(t.sport);
    evt4.dport = ntohs(t.dport);

    evt4.prev_tcp_state = sk->sk_state;
    evt4.new_tcp_state = sk->sk_state;

#ifdef KSTACK
    evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

    tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  } else {
    // TODO: Add IPv6 support. Now it isn't supported.
  }
  return 0;

}

int trace_retransmit(struct pt_regs *ctx, struct sock *sk)
{
  if (check_family(sk, AF_INET)) {
    struct tcp_ipv4_event_t evt4 = { };
    evt4.evt_src = EVT_SRC_TCP_RETRANSMIT_SKB;

    // Note :bpf_get_current_pid_tgid doesn't return coorect PID
    // 0      swapper/1  isnstead. So we can try get pid and comm from
    // previus saved hash filled by connect? or accept.
    u64 pid = 0;
    struct pid_comm_t *pcomm;
    pcomm = sktopidmap2.lookup(&sk);
    if (pcomm == 0) {
      // Don't skeep events
      // But pid 0 and comm is empty
    } else {
      pid = pcomm->pid;
      int i;
      for (i = 0; i < TASK_COMM_LEN; i++) {
        evt4.comm[i] = pcomm->comm[i];
      }
    }

    ##FILTER_PID##

    evt4.pid = pid >> 32;
    evt4.sk_err = sk->sk_err;

    struct ipv4_tuple_t t = { };
    read_ipv4_tuple(&t, sk);

    evt4.saddr = t.saddr;
    evt4.daddr = t.daddr;
    evt4.sport = ntohs(t.sport);
    evt4.dport = ntohs(t.dport);

    evt4.prev_tcp_state = sk->sk_state;
    evt4.new_tcp_state = sk->sk_state;

#ifdef KSTACK
    evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

    tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  } else {
    // TODO: Add IPv6 support. Now it isn't supported.
  }
  return 0;
}

int trace_tcp_set_state_entry(struct pt_regs *ctx, struct sock *skp, int state)
{
  // TODO: Check ip version
  struct tcp_ipv4_event_t evt4 = { };
  evt4.evt_src = EVT_SRC_TCP_SET_STATE_FUNC;

  struct ipv4_tuple_t t = { };
  // Cause src port may zero before actually connected
  read_ipv4_tuple(&t, skp);

  u64 pid = 0;
  //if (state == TCP_SYN_SENT) {
  //  struct sock **skpp;
  u64 *pidptr;
  // From connect?
  pidptr = sktopidmap.lookup(&skp);
  struct pid_comm_t *pcomm;
  pcomm = sktopidmap2.lookup(&skp);
  if (pcomm == 0) {
    return 0;
  } else {
    pid = pcomm->pid;
    int i;
    for (i = 0; i < TASK_COMM_LEN; i++) {
      evt4.comm[i] = pcomm->comm[i];
    }
  }

  if (pidptr == 0) {
    return 0;
    // TODO: GET PID FROM? Fill connectsock from accept

    /**
    struct pid_comm_t *pcomm;
    pcomm = tuplepid_ipv4.lookup(&t);
    if (pcomm == 0) {
      pid = 0;
    } else {
      pid = pcomm->pid;
      int i;
      for (i = 0; i < TASK_COMM_LEN; i++) {
        evt4.comm[i] = pcomm->comm[i];
      }
    }
    **/
  } else {
    //pid = *pidptr;
  }
  //  if (skpp == 0) {
  //    return 0;       // missed entry
  //  }
  //  connectsock.delete(&pid);
  //}

  evt4.ts_ns = bpf_ktime_get_ns();
  evt4.pid = pid >> 32;
  evt4.sk_err = skp->sk_err;
  evt4.saddr = t.saddr;
  evt4.daddr = t.daddr;
  evt4.sport = ntohs(t.sport);
  evt4.dport = ntohs(t.dport);
  //evt4.netns = t.netns;

  // Get prev state
  evt4.prev_tcp_state = skp->sk_state;

  // Get new state
  evt4.new_tcp_state = state;

#ifdef KSTACK
  evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

  tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  return 0;
}

int trace_close_entry(struct pt_regs *ctx, struct sock *skp)
{
  u64 pid = bpf_get_current_pid_tgid();

  ##FILTER_PID##

  u8 oldstate = skp->sk_state;
  // Don't generate close events for connections that were never
  // established in the first place.
  if (oldstate == TCP_SYN_SENT ||
      oldstate == TCP_SYN_RECV ||
      oldstate == TCP_NEW_SYN_RECV)
      return 0;

  u8 ipver = 0;
  if (check_family(skp, AF_INET)) {
      ipver = 4;
      struct ipv4_tuple_t t = { };
      if (!read_ipv4_tuple(&t, skp)) {
          return 0;
      }

      struct tcp_ipv4_event_t evt4 = { };
      evt4.ts_ns = bpf_ktime_get_ns();
      evt4.pid = pid >> 32;
      evt4.ip = ipver;
      evt4.saddr = t.saddr;
      evt4.daddr = t.daddr;
      evt4.sport = ntohs(t.sport);
      evt4.dport = ntohs(t.dport);
      evt4.netns = t.netns;
      bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

      tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  } else if (check_family(skp, AF_INET6)) {
      ipver = 6;
      struct ipv6_tuple_t t = { };
      if (!read_ipv6_tuple(&t, skp)) {
          return 0;
      }

      struct tcp_ipv6_event_t evt6 = { };
      evt6.ts_ns = bpf_ktime_get_ns();
      evt6.pid = pid >> 32;
      evt6.ip = ipver;
      evt6.saddr = t.saddr;
      evt6.daddr = t.daddr;
      evt6.sport = ntohs(t.sport);
      evt6.dport = ntohs(t.dport);
      evt6.netns = t.netns;
      bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

      tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
  }
  // else drop

  return 0;
};


int trace_accept_return(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
  u64 pid = bpf_get_current_pid_tgid();

  if (sk == NULL) {
    return 0;
  }

  struct tcp_ipv4_event_t evt4 = { };
  evt4.evt_src = EVT_SRC_TCP_ACCEPT;
  evt4.pid = pid >> 32;
  bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

  struct ipv4_tuple_t t = { };
  read_ipv4_tuple(&t, sk);

  u16 lport = 0, dport = 0;
  bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
  bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);

  evt4.saddr = t.saddr;
  evt4.daddr = t.daddr;
  evt4.sport = lport;
  evt4.dport = ntohs(dport);

  u8 state = 0;
  bpf_probe_read(&state, sizeof(u8), (const void*)&sk->__sk_common.skc_state);
  evt4.prev_tcp_state = state;
  evt4.new_tcp_state = state;

  // stash the sock ptr for lookup on return
  connectsock.update(&pid, &sk);
  // NEW
  // What if cmd changed on the fly?
  struct pid_comm_t pp = { };
  pp.pid = pid;
  bpf_get_current_comm(&pp.comm, sizeof(pp.comm));
  bpf_probe_read(&evt4.sk_err, sizeof(sk->sk_err), &sk->sk_err);
  sktopidmap.update(&sk, &pid);
  sktopidmap2.update(&sk, &pp);

  struct pid_comm_t p = { };
  p.pid = pid;
  bpf_get_current_comm(&p.comm, sizeof(p.comm));
  //tuplepid_ipv4.update(&t, &p);

#ifdef KSTACK
  evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

  tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  return 0;
}

// TODO: Add IPv6 support.
int sock_def_error_report_entry(struct pt_regs *ctx, struct sock *sk) {
  if (!sk->sk_err) {
    return 0;
  }

  struct tcp_ipv4_event_t evt4 = { };

  // TODO: Move the code block to separate function.
  // Get PID and COMM
  // More robust way. Cause bpf_get_current_pid_tgid and bpf_get_current_comm
  // returns sometimes returns 0 and swapper/1
  u64 pid = 0;
  struct pid_comm_t *pcomm;
  pcomm = sktopidmap2.lookup(&sk);
  if (pcomm) {
    pid = pcomm->pid;
    int i;
    for (i = 0; i < TASK_COMM_LEN; i++) {
      evt4.comm[i] = pcomm->comm[i];
    }
  } else {
    // Try from bpf_get_current_pid_tgid and bpf_get_current_comm?
    pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));
  }

  ##FILTER_PID##

  evt4.evt_src = EVT_SRC_TCP_ERR_REPORT;
  evt4.pid = pid >> 32;
  evt4.sk_err = sk->sk_err;
  evt4.prev_tcp_state = sk->sk_state;
  evt4.new_tcp_state = sk->sk_state;

  struct ipv4_tuple_t t = { };
  read_ipv4_tuple(&t, sk);

  evt4.saddr = t.saddr;
  evt4.daddr = t.daddr;
  evt4.sport = ntohs(t.sport);
  evt4.dport = ntohs(t.dport);
  evt4.netns = t.netns;

#ifdef KSTACK
  evt4.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
#endif

  tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
  return 0;
}

"""

TASK_COMM_LEN = 16   # linux/sched.h


class TCPIPV4Evt(ctypes.Structure):
    _fields_ = [
            ("ts_ns", ctypes.c_ulonglong),
            ("pid", ctypes.c_uint),
            ("comm", ctypes.c_char * TASK_COMM_LEN),
            ("ip", ctypes.c_ubyte),
            ("saddr", ctypes.c_uint),
            ("daddr", ctypes.c_uint),
            ("sport", ctypes.c_ushort),
            ("dport", ctypes.c_ushort),
            ("netns", ctypes.c_uint),
            ("new_tcp_state", ctypes.c_ubyte),
            ("prev_tcp_state", ctypes.c_ubyte),
            ("evt_src", ctypes.c_ubyte),
            ("stack_id", ctypes.c_ulonglong),
            ("sk_err", ctypes.c_int)
    ]


# From https://elixir.free-electrons.com/linux/v4.12/source/include/net/tcp_states.h#L16
TCP_ESTABLISHED  = 1
TCP_SYN_SENT     = 2
TCP_SYN_RECV     = 3
TCP_FIN_WAIT1    = 4
TCP_FIN_WAIT2    = 5
TCP_TIME_WAIT    = 6
TCP_CLOSE        = 7
TCP_CLOSE_WAIT   = 8
TCP_LAST_ACK     = 9
TCP_LISTEN       = 10
TCP_CLOSING      = 11 # Now a valid state
TCP_NEW_SYN_RECV = 12


tcp_states_names = {
  TCP_ESTABLISHED  : "ESTABLISHED",
  TCP_SYN_SENT     : "SYN_SENT",
  TCP_SYN_RECV     : "SYN_RECV",
  TCP_FIN_WAIT1    : "FIN_WAIT1",
  TCP_FIN_WAIT2    : "FIN_WAIT2",
  TCP_TIME_WAIT    : "TIME_WAIT",
  TCP_CLOSE        : "CLOSE",
  TCP_CLOSE_WAIT   : "CLOSE_WAIT",
  TCP_LAST_ACK     : "LAST_ACK",
  TCP_LISTEN       : "LISTEN",
  TCP_CLOSING      : "CLOSING",
  TCP_NEW_SYN_RECV : "NEW_SYN_RECV"
}

# TODO: send reset tcp_send_active_reset
# TODO: close with reason?
EVT_SRC_TCP_SET_STATE_FUNC = 1;
EVT_SRC_TCP_RETRANSMIT_SKB = 2;
EVT_SRC_TCP_FIN            = 3;
EVT_SRC_TCP_RESET          = 4;
EVT_SRC_TCP_SEND_FIN       = 5;
EVT_SRC_TCP_ACK            = 6;
EVT_SRC_TCP_ACCEPT         = 7;
EVT_SRC_TCP_ERR_REPORT     = 8;

# TODO: add desctiption: EVT_SRC_TCP_RESET : {tcp_reset(), "RST received"}
evt_src_str = {
  EVT_SRC_TCP_SET_STATE_FUNC : "tcp_set_state()",        # TCP state changed
  EVT_SRC_TCP_RETRANSMIT_SKB : "tcp_retransmit_skb()",
  EVT_SRC_TCP_FIN            : "tcp_fin()",
  EVT_SRC_TCP_RESET          : "tcp_reset()",            # RST received
  EVT_SRC_TCP_SEND_FIN       : "tcp_send_fin()",         # Send FIN
  EVT_SRC_TCP_ACK            : "tcp_ack()/win==0",       # Receive zero window from remote point
  EVT_SRC_TCP_ACCEPT         : "tcp_accept()/return",
  EVT_SRC_TCP_ERR_REPORT     : "sock_def_error_report()" # Kernel notify apps about sock error
}

def print_ipv4_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(TCPIPV4Evt)).contents

    if args.timestamp:
      ts = datetime.datetime.today()
      ms = int(ts.microsecond / 1000.0)
      print("%-8s.%-3d  " % (ts.strftime('%H:%M:%S'), ms), end="")

    evt_source  = evt_src_str.get(event.evt_src, "ERROR!");

    print("%-23s " % (evt_source), end="")

    state_str = tcp_states_names.get(event.new_tcp_state, "ERROR!")
    prev_state_str = tcp_states_names.get(event.prev_tcp_state, "ERROR!")

    state_trans_str = ""
    if event.new_tcp_state != event.prev_tcp_state :
      state_trans_str = prev_state_str + " -> " + state_str
    else:
      state_trans_str = state_str;

    evt_source  = evt_src_str.get(event.evt_src, "ERROR!");

    sk_err_str = ""
    if event.sk_err != 0:
      sk_err_str = errno.errorcode[event.sk_err]

    #       PID COMM  SOURCE DESTINATION  STATE SOCK_ERR
    print("%-6d %-16s %-21s %-21s %-24s %-6s" %
          (event.pid, event.comm.decode('utf-8'),
           "%s:%-6d" % (inet_ntop(AF_INET, pack("I", event.saddr)), event.sport),
           "%s:%-6d" % (inet_ntop(AF_INET, pack("I", event.daddr)), event.dport),
           state_trans_str, sk_err_str), end="")
    if args.netns:
        print(" %-8d" % event.netns, end="")

    print()

    if args.kstack:
      # Print kernel stack
      if event.stack_id != 0:
        for addr in stack_traces.walk(event.stack_id):
          sym = b.ksym(addr)
          print("\t%s" % sym)
        print()
    sys.stdout.flush()

pid_filter = ""
netns_filter = ""

if args.pid:
    pid_filter = 'if (pid >> 32 != %d) { return 0; }' % args.pid
if args.netns:
    netns_filter = 'if (net_ns_inum != %d) { return 0; }' % args.netns

bpf_text = bpf_text.replace('##FILTER_PID##', pid_filter)
bpf_text = bpf_text.replace('##FILTER_NETNS##', netns_filter)
bpf_text = bpf_text.replace('##DEFINE_KSTACK##', "#define KSTACK")

# Initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_entry")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state_entry")
b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")
b.attach_kprobe(event="tcp_fin", fn_name="trace_tcp_fin_entry")
b.attach_kprobe(event="tcp_reset", fn_name="trace_tcp_reset_entry")
b.attach_kprobe(event="tcp_send_fin", fn_name="trace_tcp_send_fin_entry")
b.attach_kprobe(event="tcp_ack", fn_name="trace_tcp_ack_entry")
b.attach_kprobe(event="sock_def_error_report", fn_name="sock_def_error_report_entry")

if args.kstack:
  stack_traces = b.get_table("stack_traces")

# TODO: Add IPv6 tcp_v6_send_reset
# TODO: tcp_close
# TODO: tcp_send_active_reset
# TODO: tcp_v6_connect
print("Tracing TCP events. Ctrl-C to end.")

if args.timestamp:
  print("%-14s" % ("TIME"), end="")

print("%-23s %-6s %-16s %-21s %-21s %-24s %-7s" %
     ("EVENT_SOURCE", "PID", "COMM", "SOURCE", "DESTINATION", "TCP_STATE", "SOCK_ERR"))

def inet_ntoa(addr):
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq


b["tcp_ipv4_event"].open_perf_buffer(print_ipv4_event)
while True:
    b.kprobe_poll()

# TODO
# sk->sk_err = ECONNABORTED;??? tcp_disconnect(? tcp_close?
