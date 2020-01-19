import argparse
import binascii
from pcapfile import savefile
from pcapfile.protocols.transport import tcp, udp
from pcapfile.protocols.network import ip
from pcapfile.protocols.linklayer import ethernet
import os
import subprocess
import threading
results = {}


def get_pcaps_list(path):
    if os.path.isdir(path):
        result = []
        for file in os.listdir(path):
            if os.path.isfile(
                os.path.join(path, file)
            ) and "pcap" in os.path.splitext(
                os.path.join(path, file)
            )[1]:
                result.append(os.path.join(path, file))
    elif os.path.isfile(path):
        result.append(path)
    return result


class IPresult():
    """docstring for ."""

    def add_packet(self, ip_packet):
        try:
            t_p = tcp.TCP(binascii.unhexlify(ip_packet.payload))

        except Exception as e:
            pass
            try:
                t_p = udp.UDP(binascii.unhexlify(ip_packet.payload))
            except Exception as e:
                print("Wtf is this?")
                return
        if not self.ports.get(t_p.dst_port):
            self.ports[t_p.dst_port] = 1
        else:
            self.ports[t_p.dst_port] += 1
        self.total_packets += 1

    def get_whois(self):
        stdout, stderr = subprocess.Popen(
            ["torsocks", "whois", self.ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        ).communicate()
        for line in stdout.split(b"\n"):

            try:
                k_v = line.split(b":")
                k = k_v[0].decode("utf-8").strip()
                v = b":".join(k_v[1:]).decode("utf-8").strip()
                if self.info.get(k):
                    if self.info[k] != v+" ":
                        self.info[k] += v+" "
                else:
                    self.info[k] = v+" "

            except Exception as e:
                pass

    def __init__(self, ip):
        self.ip = ip
        self.ports = {}
        self.info = {}
        self.total_packets = 0
        try:
            threading.Thread(target=self.get_whois).start()
        except Exception as e:
            print(e)


def add_packet(ip_addr, ip_packet):
    if results.get(ip_addr):
        results[ip_addr].add_packet(ip_packet)
    else:
        results[ip_addr] = IPresult(ip_addr)
        results[ip_addr].add_packet(ip_packet)
        for k in results[ip_addr].info.keys():
            print(k, results[ip_addr].info[k])
        # exit()


def print_list(newlist):
    for res in newlist:
        print(res.ip, res.total_packets)
        print("Organisation:", res.info.get("org-name"))
        print("Country:", res.info.get("country"))
        print("Address:", res.info.get("address"))
        for port in res.ports.keys():
            print("\t", port, res.ports[port])
        print()
    print()


def main(args):
    for file in get_pcaps_list(args.input):
        with open(file, 'rb') as file:
            sf = savefile.load_savefile(file)
            for packet in sf.packets:
                eth_frame = ethernet.Ethernet(packet.raw())
                ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
                ip_addr = ip_packet.src.decode("utf-8")
                if args.e:
                    if ip_addr not in args.e:
                        add_packet(ip_addr, ip_packet)
        # print(results.items())
        newlist = sorted(results.values(), key=lambda x: x.total_packets, reverse=True)
    if args.l:
        if len(newlist) > args.l:
            print_list(newlist[:args.l])
        else:
            print_list(newlist)
    else:
        print_list(newlist)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create simple honeypot report from pcap files'
    )
    parser.add_argument(
        '-i',
        "--input",
        help="pcap file or dirrectory with files",
        required=True
    )
    parser.add_argument(
        '-e',
        nargs='*',
        help='exclude ip',
        default='127.0.0.1'
    )
    parser.add_argument(
        '-l',
        help='results limit'
    )
    args = parser.parse_args()
    # print(args.e)
    main(args)
