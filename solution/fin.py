import scapy.all as sc

def fin():
    dst = "206.189.1.230"
    dport = 1337

    # sc.send(sc.IP(dst=dst) / sc.TCP(dport=dport))

    fin = sc.sniff(filter=" ".join(["host", dst]), count=1)

    fin_ack = sc.IP(dst=dst) / sc.TCP(sport=fin[0][sc.TCP].dport, dport=dport, flags='RFA', seq=fin[0][sc.TCP].ack, ack=fin[0][sc.TCP].seq + 1)
    sc.send(fin_ack)

if __name__ == '__main__':
    fin()