Deep TCP tracer
===============

Tool for tracing some TCP events in Linux kernel (like state change or retransmissions).

Inspired by [tcptracer](https://github.com/iovisor/bcc/blob/master/tools/tcptracer.py)
and [tcpretrans](https://github.com/iovisor/bcc/blob/master/tools/tcpretrans.py)
from [BCC - BPF Compiler Collection](https://github.com/iovisor/bcc).

Example of an output

~~~
Tracing TCP events. Ctrl-C to end.
EVENT_SOURCE            PID    COMM             SOURCE                DESTINATION           TCP_STATE                SK_ERR
tcp_set_state()         16065  wget             10.0.2.15:0           87.250.250.242:443    CLOSE -> SYN_SENT
tcp_set_state()         16065  wget             10.0.2.15:60590       87.250.250.242:443    SYN_SENT -> ESTABLISHED
tcp_set_state()         16065  wget             10.0.2.15:60590       87.250.250.242:443    ESTABLISHED -> FIN_WAIT1
tcp_send_fin()          16065  wget             10.0.2.15:60590       87.250.250.242:443    FIN_WAIT1
tcp_set_state()         16065  wget             10.0.2.15:60590       87.250.250.242:443    FIN_WAIT1 -> FIN_WAIT2
tcp_set_state()         16065  wget             10.0.2.15:60590       87.250.250.242:443    FIN_WAIT2 -> CLOSE
~~~

## Requirements

Linux kernel 4.1 or newer.

## Quick start

For Ubuntu Xenial 16.04 LTS

Install BCC([details and other systems](https://github.com/iovisor/bcc/blob/master/INSTALL.md))

```
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
echo "deb https://repo.iovisor.org/apt/xenial xenial main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```

Clone the repo

```
git clone https://github.com/alexgpg/deeptcptracer.git
cd deeptcptracer/
```

Run

```
sudo ./deeptcptracer.py
```

## Options

**-p PID** Show events only for process with the process ID equals PID.

  ```
  sudo ./deeptcptracer.py -p 42
  ```

**-t** Print timestamp for events.

  ```
  sudo ./deeptcptracer.py -t
  ```

**-K, --kstack** Print kernel stack. Need a Linix kernel 4.6+!

  ```
  sudo ./deeptcptracer.py -K
  ```

  or

  ```
  sudo ./deeptcptracer.py --kstack
  ```

## Supported events

 * Change TCP state - [tcp_set_state()](https://elixir.bootlin.com/linux/latest/ident/tcp_set_state)

 * Get error on socker - [sock_def_error_report()](https://elixir.bootlin.com/linux/latest/ident/sock_def_error_report)

 * Receive RST flag - [tcp_reset()](https://elixir.bootlin.com/linux/latest/ident/tcp_reset)

 * Receive FIN flag - [tcp_fin()](https://elixir.bootlin.com/linux/latest/ident/tcp_fin)

 * Retransmission - [tcp_retransmit_skb()](https://elixir.bootlin.com/linux/latest/ident/tcp_retransmit_skb)

 * Send FIN flag - [tcp_send_fin()](https://elixir.bootlin.com/linux/latest/ident/tcp_send_fin)

 * Receive zero window - [tcp_ack()/win==0](https://elixir.bootlin.com/linux/latest/ident/tcp_ack)

## Supported filters

TODO

## TODO

 * Zero window sent event

 * IPv6 support

 * N/A for pid==0, cmd==0

 * Filters: src/dst IP, src/dst port

 * Full namespaces suppport
