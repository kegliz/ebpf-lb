## eBPF Load balancer

This repo was created to reimplement and extend Liz Rice's eBPF-based load balancer [example](https://www.youtube.com/watch?v=L3_AOFSNKK8) using Go user-space code. A big applause to Liz for her great work and for sharing it with the community. I've also enjoyed her book ["Learning eBPF"](https://learning.oreilly.com/library/view/learning-ebpf/9781098135119/) and I highly recommend it to anyone interested in eBPF.

For user-space code I decided to use cilium's Go eBPF [library](https://ebpf-go.dev/). The eBPF program is written in C, and [bpf2go](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go) is used to compile it and generate Go bindings. The user-space code is responsible for loading the eBPF program into the kernel, setting up the load balancer, and handling events from a [ringbuffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html). These events are then printed to the console.

Do not use this in production. This is a learning project and it's not optimized for performance or security.

Setup guides:
- [Installations steps for Mac with Apple Silicon chip](#installations-steps-for-mac-with-apple-silicon-chip)
- [Installations steps for x86_64 Ubuntu 22.04](#installations-steps-for-x86_64-ubuntu-2204)


## Installations steps for Mac with Apple Silicon chip
### Initial setup
I used VMware Fusion to run Ubuntu 22.04 with OpenSSH on my M1 Mac. After setting up ssh I used a simple terminal to ssh into it and install the following:
- [Go](https://go.dev/wiki/Ubuntu) 
- [Docker](https://docs.docker.com/engine/install/ubuntu/)
- clang and llvm
```bash
sudo apt update && sudo apt upgrade
sudo apt install clang llvm
```
- libbpf headers and linux kernel headers

*Note: gcc-multilib is not currently available for ARM architectures on Ubuntu 22.04. Instead, I'm linking `/usr/include/$(shell uname -m)-linux-gnu` into the include path. See [this thread for more info](https://patchwork.ozlabs.org/project/netdev/patch/20200311123421.3634-1-tklauser@distanz.ch/).* 
```bash
sudo apt install libbpf-dev
sudo ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm
```
- for using Makefile (and column)
```bash
sudo apt install build-essential bsdmainutils
```
- bpftool and ip (optional)
```bash
sudo apt install linux-tools-common linux-tools-generic iproute2
```

### Clone the repo and initialize it
```bash
git clone https://github.com/kegliz/ebpf-lb.git
cd lb
go get github.com/cilium/ebpf/cmd/bpf2go 
```

### Build the eBPF program
```bash
make build
```

### Create backend and client containers

for backends:
```bash
docker run -d --rm --name backend-A -h backend-A --env TERM=xterm-color nginxdemos/hello:plain-text
docker run -d --rm --name backend-B -h backend-B --env TERM=xterm-color nginxdemos/hello:plain-text
```

In a different terminal exec into one of the backends and install tcpdump if you want to see incoming traffic there.
```bash
docker exec -it backend-A /bin/sh 
apk add tcpdump
tcpdump -i eth0
```

Open a different terminal for the client and start its container:
```bash
docker run --rm -it -h client --name client --env TERM=xterm-color ubuntu:jammy
apt update && sudo apt upgrade 
apt install curl
```

If these are the first docker containers you are running, there is a high chance that the IP addresses of the containers are as follows:
- backend-A: 172.17.0.2
- backend-B: 172.17.0.3
- client: 172.17.0.4

If not, then use the following commands to obtain the IP addresses and correct the program code accordingly
```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' backend-A
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' backend-B
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' client
```

Make sure the backends are running and available from the client so check it from the client container:
```bash
curl 172.17.0.2
curl 172.17.0.3
```

### Start the load balancer

Running it as privileged gives it permissions to load eBPF programs: 

```bash
docker run --rm -it -v ~/work/ebpf-lb:/lb --privileged -h lb --name lb --env TERM=xterm-color ubuntu:jammy
cd lb
./ebpf-lb
```

### Test the load balancer
From the client container run the following command multiple times to see the load balancer in action:
```bash
curl 172.17.0.5
```
The answer should come from either backend-A or backend-B as the load balancer distributes the requests between them.
You can also check the traffic on the backends with tcpdump. On the host, you can use the following command to see the debug output of the eBPF program:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Installations steps for x86_64 Ubuntu 22.04
TODO

