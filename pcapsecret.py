import argparse, random, sys
from scapy.all import *
from tabulate import tabulate

PROG_DESC = "Embeds a secret message into a packet capture file."
ANSWER_KEY = []
MAC_ADDRS = []
IP_ADDRS = []
TIMES = []
TOTAL_PACKET_COUNT = 0

def prep_message(message: str, encoding_type: str, delimiter: str)->str:
    """ UNUSED
    returns ascii plaintext representation, 8-bit binary string representation, 
    or hex string representation of message with delimiter
    """
    if encoding_type == "binary":
        return delimiter.join([format(ord(character), 'b').zfill(8).strip() for character in message])
    elif encoding_type == "hex":
        return delimiter.join([format(ord(character), 'x').strip() + "h" for character in message])
    else: 
        return message

def pipe_extract(input_filename: str, output_filename: str)->None:
    """ 
    Pipesystem to extract general packet data (hwsrc, hwdst, src, dst, time) from all packets in input file.
    Data used in inject_malforms to provide hints to location of message segments.
    """
    global IP_ADDRS
    global MAC_ADDRS
    global TIMES
    source = RdpcapSource(input_filename)
    sink = Sink() 
    #sink = WrpcapSink(output_filename)
    def extract_(pkt: packet)->packet:
        if Ether in pkt: 
            MAC_ADDRS.append(pkt[Ether].src)
            MAC_ADDRS.append(pkt[Ether].dst)
        if IP in pkt:
            IP_ADDRS.append(pkt[IP].src)
            IP_ADDRS.append(pkt[IP].dst)
        TIMES.append(pkt.time)
        return pkt
    source > TransformDrain(extract_) > sink
    p = PipeEngine(source)
    p.start()
    p.wait_and_stop()

def segment_message(message: str, message_segment_count: int, encap: str)->list():
    """
    Segment message into n segments where n = message_segment count.
        Clamp message segment count to range 0 --> message length.
        If message segment == 0 (default), set message segments to random int between 2 and message length / 2.
        note alternative split method: zip is useful for splitting lists into n-length groups.  
            See https://docs.python.org/3/library/functions.html#zip
            segments = list(map(''.join, zip(*[iter(message)]*segment_length, strict=True)))
    Encapsulate each segment in encap[0] ane encap[1] (e.g., if encap="<>" -> <SEGMENT STRING>)
    Return list of segments.
    """
    if message_segment_count <= 0:
        message_segment_count = random.randint(2, math.trunc(len(message)/2))
    elif message_segment_count > len(message):
        message_segment_count = len(message)
    step = math.ceil(len(message) / message_segment_count)
    if len(encap) > 0 or encap == 'n':
        message_segments = [encap[0] + message[i:i+step] + encap[1] for i in range(0, len(message), step)] 
    else:
        message_segments = [message[i:i+step] for i in range(0, len(message), step)] 
    return message_segments

def inject_msg_and_hints(message: list, input_filename: str, output_filename: str)->None:
    """
    For each message segment, a random packet from the input pcap file is sequentially chosen.
    A payload containing the message segment is appended to the last bytes of each chosen packet.
    Each packet containing a message segment is malformed to provide a hint.
    Join the payloads to reconstruct the secret message.
         
    Hint Types (To Do: Extend with additional hint types):
        no_hint (disabled) = add segment as payload, reset length (difficult to detect)       
        time_hint_small = time changed to value outside range of time of pkts +2 or -2 indices away, causing packet to appear out of place 
        time_hint_large = significant time change
        length_hint = malformed packet length due to size on wire != captured size (does not call sync_length)
        addr_hint_1 = MAC and/or IP source and destination are random, not included in pcap file previously
        addr_hint_2 = Ethernet layer contains broadcast mac address in source and destination.
        addr_hint_3 = TBD -- Ideas?
        addr_hint_4 = TBD -- Ideas?
    """
    global ANSWER_KEY
    global TOTAL_PACKET_COUNT

    def generate_random_addr(addr_type: int)->str:
        """
        Generate random MAC addresses or IP address, not in input pcap file.
        addr_type = 0 for MAC, 1 for IP
        Due to how scapy handles assigning strings as MAC addresses vs IP addresses, keep
        else case for MAC addresses.
        """ 
        if addr_type == 1:       
            r_addr = RandIP()
            while r_addr in IP_ADDRS:
                r_addr = RandIP()
        else:
            r_addr = RandMAC()
            while r_addr in MAC_ADDRS:
                r_addr = RandMAC()
        return r_addr

    try:
        packets = rdpcap(input_filename)
    except Exception as e:
        print("Error reading input file:", input_filename, repr(e))
        sys.exit(1)
    
    TOTAL_PACKET_COUNT = len(packets)
    hint_types = ["time_hint_small", "time_hint_large", "length_hint", "addr_hint_1", "addr_hint_2"]
    """
    Note following line in cases below, which ensures that length on wire (wirelen) is equal to captured length (caplen)
        packets[cpi].wirelen = len(raw(packets[cpi]))
    Intentionally not called in length_hint type below.
    """
    n, step = 0, math.trunc(len(packets) / len(message))
    for i, segment in enumerate(message):
        # cpi = chosen packet index
        cpi = random.randint(n, n + step)
        match random.choice(hint_types):
            case "no_hint":                
                packets[cpi].add_payload("Secret Message Part: " + segment)
                packets[cpi].wirelen = len(raw(packets[cpi]))
                ANSWER_KEY.append([cpi+1, segment, "payload_only"])       
            case "length_hint":
                packets[cpi].add_payload(segment)
                ANSWER_KEY.append([cpi+1, segment, "length_hint"])
            case "time_hint_small":
                packets[cpi].add_payload(segment)
                packets[cpi].wirelen = len(raw(packets[cpi]))
                rt = random.choice(TIMES)
                while packets[cpi - 2].time < rt < packets[cpi + 2].time:
                    rt = random.choice(TIMES)
                packets[cpi].time = random.choice(TIMES)
                ANSWER_KEY.append([cpi+1, segment, "time_hint_small"])
            case "time_hint_large":
                packets[cpi].add_payload(segment)
                packets[cpi].wirelen = len(raw(packets[cpi]))
                very_small_time = random.uniform(packets[0].time/2, packets[0].time)
                very_large_time = random.uniform(packets[-1].time, packets[-1].time*2)
                rt = very_large_time if random.random() > 0.5 else very_small_time
                packets[cpi].time = rt
                ANSWER_KEY.append([cpi+1, segment, "time_hint_large"])
            case "addr_hint_1":
                packets[cpi].add_payload(segment)
                packets[cpi].wirelen = len(raw(packets[cpi]))
                if Ether in packets[cpi]:
                    packets[cpi][Ether].src = generate_random_addr(0)
                    packets[cpi][Ether].dst = generate_random_addr(0)
                else:
                    packets[cpi] = Ether() / packets[cpi]
                    packets[cpi][Ether].src = generate_random_addr(0)
                    packets[cpi][Ether].dst = generate_random_addr(0)
                if IP in packets[cpi]:
                    packets[cpi][IP].src = generate_random_addr(1)
                    packets[cpi][IP].dst = generate_random_addr(1)
                ANSWER_KEY.append([cpi+1, segment, "ip_hint_1"])   
            case "addr_hint_2":
                packets[cpi].add_payload(segment)
                packets[cpi].wirelen = len(raw(packets[cpi]))
                if Ether in packets[cpi]:
                    packets[cpi][Ether].src = "ff:ff:ff:ff:ff:ff"
                    packets[cpi][Ether].dst = "ff:ff:ff:ff:ff:ff"
                else:
                    packets[cpi] = Ether() / packets[cpi]
                    packets[cpi][Ether].src = "ff:ff:ff:ff:ff:ff"
                    packets[cpi][Ether].dst = "ff:ff:ff:ff:ff:ff"
                ANSWER_KEY.append([cpi+1, segment, "ip_hint_2"])
        n += step
    try:
        wrpcap(output_filename, packets)
    except Exception as e:
        print("Error writing to output file:", output_filename, repr(e))
        sys.exit(1)
    return None

def main()->None:
    """
    1) Parse command line arguments;
    2) Use pipe system to extract data from process input pcap file (used to embed hints via malforming packets);
    3) Segment message and encapsulate with encapsulation chars (default: <>)
    4) Add message segments as payload to random consecutive packets (malformed to provide hints);
    5) Save output pcap file; and
    6) Print answer key.

    Usage:  python pcapsecret.py input.pcap "Secret Message"

    Detailed Usage Information (with optional parameters):  python pcapsecret.py -h 
    """
    
    # unchanged in main(), therefore global decs are potentially unnecessary
    global PROG_DESC
    global ANSWER_KEY
    global TOTAL_PACKET_COUNT

    parser = argparse.ArgumentParser(description=PROG_DESC)
    
    parser.add_argument(dest="input_filename", nargs="?", metavar="input filename", action="store", help="input pcap file (required, pcapsecret does not modify this file)")    
    
    parser.add_argument(dest="secret_message", nargs="?", metavar="secret message", action="store", help="secret message (required, at least 4 characters)")
    
    parser.add_argument("-o", dest="output_filename", nargs="?", action="store", metavar="output filename", 
                        required=False, default="output.pcap", help="output pcap file (optional, default: %(default)s)")

    parser.add_argument("-s", dest="message_segment_count", type=int, nargs="?", action="store", metavar="msg segment count", 
                        required=False, default="0", help="may not exceed message length (optional, default: random integer between 2 and message length / 2)")

    parser.add_argument("-e", dest="encap", nargs="?", action="store", metavar="encap chars", 
                        required=False, default="<>", help="two chars to encapsulate hidden message segments (optional, 'n' for none, default: %(default)s)")

    """ UNUSED.  See prep_message above.
    parser.add_argument("-c", dest="encoding_type", nargs="?", action="store", metavar="plaintext, binary, or, hex", 
                        required=False, default="plaintext", choices=['plaintext', 'binary', 'hex'],
                        help="output encoding type (ascii plaintext, binary string, or hex string) (optional, default: %(default)s)")
    """
    try:
        args = parser.parse_args()
    except Exception as e:
        print("Error parsing command line arguments:", repr(e))
        sys.exit(1)

    if len(args.secret_message) < 4:
        print("Error: Message must be at least 4 characters.")
        sys.exit(1)

    if args.encap == "n":
        args.encap = ""
        print("Using no encapsulation string.")
    elif len(args.encap) != 2:
        print("Error: Encapsulation string must be 2 characters (or 'n' for none).  Example: \"<>\"")
        sys.exit(1)
    else:
        print("Using encapsulation string", args.encap)

    try:
        pipe_extract(args.input_filename, args.output_filename)
    except Exception as e:
        print("Error extracting data from input file:", repr(e))
        sys.exit(1)

    try: 
        inject_msg_and_hints(segment_message(args.secret_message, args.message_segment_count, args.encap), args.input_filename, args.output_filename)
    except Exception as e:
        print("Error segmenting and injecting message:", repr(e))
        sys.exit(1)

    print("Secret Message (" + args.secret_message + ") was segmented into " + str(len(ANSWER_KEY)) + 
          " parts and injected into the following packets:")
    headers = ["Packet No.", "Message Segment", "Hint Type"]
    print(tabulate(ANSWER_KEY, headers=headers, tablefmt="grid", colalign=("center", "center", "center")))
    print("Done!", str(TOTAL_PACKET_COUNT), "packets written to", args.output_filename)
    return None

if __name__ == "__main__":
    main()
    sys.exit(0)