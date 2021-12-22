import stl_path
from trex.stl.api import *
from scapy.contrib.gtp import *
from hdrh.histogram import HdrHistogram

from trex_stl_lib.api import *


def latency_test (tx_port, rx_port, packet_len, pps, duration):
    # create client
    c = STLClient()
    passed = True
    try:
        # Create base packet and pad it to size
        size = packet_len - 4; # HW will add 4 bytes ethernet FCS
        # 00:00:00:00:00:01 is "virtual" router MAC
        base_pkt =  Ether(dst="00:00:00:00:00:01")/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)
        pad = max(0, size - len(base_pkt)) * 'x'

        s1 = STLStream(name = 'rx',
                       packet = STLPktBuilder(pkt = base_pkt/pad, vm = []),
                       flow_stats = STLFlowLatencyStats(pg_id = 5),
                       mode = STLTXCont(pps = pps))

        # connect to server
        c.connect()

        # prepare our ports
        c.reset(ports = [tx_port, rx_port])

        # add both streams to ports
        c.add_streams([s1], ports = [tx_port])

        rc = rx_iteration(c, tx_port, rx_port,duration)
        if not rc:
            passed = False

    except STLError as e:
        passed = False
        print(e)

    finally:
        c.disconnect()

    if passed:
        print("\nTest passed :-)\n")
    else:
        print("\nTest failed :-(\n")


# RX one iteration
def rx_iteration (c, tx_port, rx_port,duration):
    
    c.clear_stats()

    c.start(ports = [tx_port],duration=duration)
    pgids = c.get_active_pgids()

    c.wait_on_traffic(ports = [tx_port])

    stats = c.get_pgid_stats(pgids['latency'])
    flow_stats = stats['flow_stats'].get(5)
    global_lat_stats = stats['latency']
    lat_stats = global_lat_stats.get(5)
    if not flow_stats:
        print("no flow stats available")
        return False
    if not lat_stats:
        print("no latency stats available")
        return False

    lat = lat_stats['latency']
    jitter = lat['jitter']
    avg = lat['average']
    tot_max = lat['total_max']
    tot_min = lat['total_min']
    last_max = lat['last_max']
    hist = lat ['histogram']
    hdrblob = lat ['hdrh']
    histogram = HdrHistogram.decode(hdrblob)
    count = histogram.get_total_count()
    print("hdr contains {0} entries\n".format(count))
    p50=histogram.get_value_at_percentile(50)
    p90=histogram.get_value_at_percentile(90)
    p99=histogram.get_value_at_percentile(99)
    p99_9=histogram.get_value_at_percentile(99.9)
    print('p50={0} p90={1} p99={2} p99.9={3}\n'.format(p50,p90,p99,p99_9))
    histogram.output_percentile_distribution(open("dist.hgrm", "wb+"), 1, use_csv=True)
    print('Latency info:')
    print("  Maximum latency(usec): {0}".format(tot_max))
    print("  Minimum latency(usec): {0}".format(tot_min))
    print("  Maximum latency in last sampling period (usec): {0}".format(last_max))
    print("  Average latency(usec): {0}".format(avg))
    print("  Jitter(usec): {0}".format(jitter))
    print("  Latency distribution histogram:")
    l = list(hist.keys()) # need to listify in order to be able to sort them.
    l.sort()
    for sample in l:
        range_start = sample
        if range_start == 0:
            range_end = 10
        else:
            range_end  = range_start + pow(10, (len(str(range_start))-1))
        val = hist[sample]
        print ("    Packets with latency between {0} and {1}: {2} ".format(range_start, range_end, val))
    
    return True


if __name__ == "__main__":
    latency_test(tx_port = 0, rx_port = 1, packet_len = 64, pps = 800000, duration=60)
