import nmap

def scan_network(target, scan_type='-sS'):
    """
    Функция для сканирования сети с использованием nmap.
    
    :param target: Цель для сканирования (например, "192.168.1.0/24" или "scanme.nmap.org").
    :param scan_type: Тип сканирования (например, '-sS' для SYN-сканирования).
    :return: Результаты сканирования.
    """
    nm = nmap.PortScanner()
    
    print(f"Сканируем цель: {target} с опцией {scan_type}...")
    
    try:
        nm.scan(hosts=target, arguments=scan_type)
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    print(f"Port: {port}, State: {nm[host][proto][port]['state']}")
    except Exception as e:
        print(f"Ошибка при сканировании: {e}")


if __name__ == "__main__":
    
    target = input("Введите цель для сканирования (например, 192.168.1.1 или scanme.nmap.org): ")
    scan_type = input("Введите тип сканирования (по умолчанию '-sS'): ") or '-sS'
    
    scan_network(target, scan_type)
