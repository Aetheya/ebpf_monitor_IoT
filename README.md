# Dynamic monitoring of IoT Network using eBPF

Usage:
- [R] Launch raspi_ebpf.py on device as root (ip, port)
- [C] (Optional) Launch collector_server to collect the stats (ip, port)
- [A] administrator.py:
    - RUN [R] (-s [C] []) (-t time)
    - START [R]
    - (running) GET [R] (-s [C])
    - (running) STOP [R]
    - PERIOD [R] -s [C] (-i interval) (-t time)
    - (running) THRESH [R] -s [C] (-r rate) (t-time)