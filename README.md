# Dynamic monitoring of IoT Network using eBPF

Usage:
- [R] Launch raspi_ebpf.py on device as root
- [C] (Optional) Launch collector_server to collect the stats
- [A] administrator.py:
    - RUN [R_ip] [R_port] -s [C]: Ack
    - START [R_ip] [R_port]
    - GET [R_ip] [R_port] -s [C]: Ack
    - STOP [R_ip] [R_port]
    - PERIOD [R_ip] [R_port] -s [C]