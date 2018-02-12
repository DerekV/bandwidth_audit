
extern crate pcap;
extern crate packet;

use std::env;
use std::collections::HashMap;
use std::path::Path;
use pcap::Capture;
use packet::ip::v4::Packet;


fn main() {
    let args:Vec<String> = env::args().collect();
    let filename = &args[1];
    let input_file_path = Path::new(filename);
    let mut cap = Capture::from_file(input_file_path).unwrap();

    let mut linkmap = HashMap::new();


    while let Ok(packet) = cap.next() {

        // TODO this assumes IPV4 packets in pcap
        // will often not be the case
        // we need to review the Capture global headers for the link type
        let ip_pkt = Packet::new(packet.data).unwrap();

        let src = ip_pkt.source();
        let dst = ip_pkt.destination();
        let link = if src <= dst {
            (src,dst)
        } else {
            (dst,src)
        };
        let total = linkmap.entry(link).or_insert(0);
        *total += packet.header.len;

        //  println!("{:?} src:{:?} dst:{:?}",ip_pkt.protocol(),ip_pkt.source(), ip_pkt.destination());

    }

    let mut totals_vec: Vec<(&(std::net::Ipv4Addr,std::net::Ipv4Addr),&u32)> = linkmap.iter().collect();
    totals_vec.sort_by(|a, b| b.1.cmp(a.1));

    for &(link, total) in &totals_vec {
        println!("{:?}: {:?}", link, total);
    }
}
