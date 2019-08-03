# Dynamic monitoring of IoT Network using eBPF

Usage:
- [M] Launch monitor_ebpf.py on device as root (ip, port)
- [C] (Optional) Launch collector_server to collect the stats (ip, port)
- [A] administrator.py:
    - RUN [R] (-s [C]) (-t time)
    - START [R]
    - (running) GET [M] (-s [C])
    - (running) STOP [M]
    - PERIOD [M] -s [C] (-i interval) (-t time)
    - (running) THRESH [M] -s [C] (-r rate) (t-time)