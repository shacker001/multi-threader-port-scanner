from django.shortcuts import render
from django.http import HttpResponse
import socket
import threading
from queue import Queue
from datetime import datetime
from ipaddress import ip_network
import subprocess
import xml.etree.ElementTree as ET

def index(request):
    return render(request, 'port_scanner/index.html')

def help(request):
    return render(request, 'port_scanner/help.html')

def port_scan(request):
    if request.method == 'POST':
        target_range = request.POST.get('target_range', '')
        start_port = int(request.POST.get('start_port', 0))
        end_port = int(request.POST.get('end_port', 0))

        ips = [str(ip) for ip in ip_network(target_range).hosts()]
        discovered_ports = []
        ports_discovered = []
        t1 = datetime.now()

        def portscan(ip, port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((ip, port))
                    service_name = socket.getservbyport(port)
                    discovered_ports.append({"ip": ip, "port": port, "service": service_name})
                    ports_discovered.append(port)
                except (ConnectionRefusedError, AttributeError, OSError):
                    pass

        def threader():
            while True:
                worker = q.get()
                for ip in ips:
                    portscan(ip, worker)
                q.task_done()

        q = Queue()

        for x in range(min(200, end_port - start_port + 1)):
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()

        for worker in range(start_port, end_port):
            q.put(worker)

        q.join()

        t2 = datetime.now()
        total = t2 - t1
        nmap_command = f"nmap -p {','.join(map(str, ports_discovered))} -sV -sC -T4 -Pn {target_range}"
        context = {
            'target_range': target_range,
            'discovered_ports': discovered_ports,
            'total': total,
            'nmap_command': nmap_command,
        }
        return render(request, 'port_scanner/results.html', context)
    else:
        return HttpResponse("Method not allowed")

def run_nmap_scan(request):
    if request.method == 'POST':
        target_range = request.POST.get('target_range', '')
        discovered_ports = request.POST.get('discovered_ports', '')
        nmap_command = f"nmap -p {discovered_ports} -sV -sC -T4 -Pn -oX scan_results.xml {target_range}"
        subprocess.run(nmap_command, shell=True)

        # Parse Nmap output files and extract relevant information
        nmap_results = parse_nmap_xml('scan_results.xml')

        context = {
            'nmap_results': nmap_results,
        }
        return render(request, 'port_scanner/nmap_results.html', context)
    else:
        return HttpResponse("Method not allowed.")

def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        nmap_results = []

        for host in root.findall('host'):
            ip = host.find('address').attrib['addr']
            open_ports = []
            services = []

            for port in host.findall('ports/port'):
                port_number = port.attrib['portid']
                state = port.find('state').attrib['state']
                if state == 'open':
                    open_ports.append(port_number)
                    service = port.find('service')
                    service_name = service.attrib.get('name', 'Unknown')
                    service_product = service.attrib.get('product', 'Unknown')
                    service_version = service.attrib.get('version', 'Unknown')
                    services.append({'port': port_number, 'name': service_name, 'product': service_product, 'version': service_version})

            if open_ports:
                nmap_results.append({'ip': ip, 'open_ports': open_ports, 'services': services})

        return nmap_results
    except Exception as e:
        print(f"Error parsing Nmap results: {e}")
        return []
