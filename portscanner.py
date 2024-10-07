import nmap
import socket

nmScan = nmap.PortScanner()
t_host = str(input('Enter the host to be scanned: '))
t_ip = socket.gethostbyname(t_host)

port_start = str(input('Enter the starting port to be scanned: '))
port_end = str(input('Enter the ending port to be scanned: '))
t_port = port_start + '-' + port_end

print(f'Scanning {t_ip} on port {t_port}...')
nmScan.scan(t_ip, t_port)

for host in nmScan.all_hosts():
    print(f'Host : {host} ({nmScan[host].hostname()})')
    print(f'State : {nmScan[host].state()}')
    
    for proto in nmScan[host].all_protocols():
        print('----------')
        print(f'Protocol : {proto}')

        lport = nmScan[host][proto].keys()
        sorted(lport)
        for port in lport:
            print(f'port : {port}\tstate : {nmScan[host][proto][port]['state']}')