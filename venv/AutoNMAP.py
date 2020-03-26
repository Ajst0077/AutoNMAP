import sys
import os
import nmap
import socket


def main():
    # Get command arguments.
    if len(sys.argv) != 3:
        print("./AutoNMAP.py <<IP ADDRESS>> <<PORT RANGE>>")
        sys.exit(0)
    iptarget = sys.argv[1]
    rgports = sys.argv[2]

    print("---------" * 7)
    print("     SCANNING THE TARGET " + iptarget)
    print("---------" * 7)

    # Initialization of Nmap
    try:
        nm = nmap.PortScanner()
        nm.scan(iptarget, rgports, arguments='-vv -sA -sV -O')
    except nmap.PortScannerError:
        print('Nmap not found', sys.exc_info()[0])
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(0)

    # Write result of scanning
    for host in nm.all_hosts():
        print("     Host: %s (%s)" % (host, iptarget))
        print("     State: %s" % nm[host].state())
        print("     OS type: %s" % nm[host]['vendor'])

        for proto in nm[host].all_protocols():
            print("+++++++++" * 7)
            print("     protocol : %s" % proto)
            ports = nm[host][proto].keys()
            for port in ports:
                print("     Port : %s \t State : %s \t Service : %s" % (
                    port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))
            print("---------" * 7)


if __name__ == "__main__":
    sys.exit(main())
