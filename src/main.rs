
extern crate pcap;
extern crate packet;

use std::env;
use std::collections::HashMap;
use std::path::Path;
use pcap::{Capture,Device,Activated,Linktype};
use packet::Packet;
use packet::ip::v4::Packet as IpPacket;
use packet::ether::Packet as EtherPacket;
use packet::ether::Protocol;



fn main() {
    let default_max = 100000000;
    
    let args:Vec<String> = env::args().collect();
    let src = &args[1].to_owned();
    
    let max = match &args[2].parse::<i32>() {
        &Ok(n) => n,
        &Err(_) => default_max,
    };
    println!("Quitting after {} packets",max);
    println!("{:?}",Device::list());

    let mut cap:Capture<Activated> = 
        if src.starts_with("en") || src.starts_with("tun") || src.starts_with("if") {
            let devices = Device::list().unwrap();
            let mut device = Device::lookup().unwrap();
            match devices.iter().find(|&d| d.name==src[..]) {
                Some(x) => {
                    device.name = x.name.clone();
                    device.desc = x.desc.clone();
                },
                _ => {
                    println!("Could not find device named {}", src);
                    return;
                },
            };
             
            //device=src.into();


            println!("{:?}",device);
            let r = Capture::from_device(device).unwrap().promisc(true).open();


            //let r = device.promisc(true).open();
            match r {
                Ok(d) => Capture::from(d),
                Err(e) => { println!("{}",e); return },      
            }

    } else {
        let input_file_path = Path::new(src);
        Capture::from(Capture::from_file(input_file_path).unwrap())
    };

    let linktype = cap.get_datalink();
    println!("{:?} {:?} {:?}",linktype, linktype.get_name().unwrap(), linktype.get_description().unwrap());
    
    let mut linkmap = HashMap::new();

    let mut count=0;
    while let Ok(packet) = cap.next() {
        if count >= max {break;}
        
        // TODO this assumes IPV4 packets in pcap
        // will often not be the case
        // we need to review the Capture global headers for the link type



        let mut eth_pkt; // need a place to hold the binding for eth packet
        
        let ip_pkt = match linktype {
            Linktype(12)=> IpPacket::new(packet.data).unwrap(),
            _ => {
                eth_pkt = EtherPacket::new(packet.data).unwrap();
                if eth_pkt.protocol() != Protocol::Ipv4 { continue; } // TODO 
                IpPacket::new(eth_pkt.payload()).unwrap()
            },
        };

        

        let src = ip_pkt.source();
        let dst = ip_pkt.destination();
        let link = if src <= dst {
            (src,dst)
        } else {
            (dst,src)
        };
        
        let total = linkmap.entry(link).or_insert(0);
        *total += packet.header.len;

        //println!("{:?} src:{:?} dst:{:?}",ip_pkt.protocol(),ip_pkt.source(), ip_pkt.destination());
        count+=1;
    }

    let mut totals_vec: Vec<(&(std::net::Ipv4Addr,std::net::Ipv4Addr),&u32)> = linkmap.iter().collect();
    totals_vec.sort_by(|a, b| b.1.cmp(a.1));

    for &(link, total) in &totals_vec {
        println!("{:?}: {:?}", link, total);
    }

    println!("Total processed packets: {}", count);
}
