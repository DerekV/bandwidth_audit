#[macro_use]

extern crate clap;
extern crate pcap;
extern crate packet;

use std::collections::HashMap;
use std::path::Path;
use pcap::{Capture,Device,Activated,Linktype};
use pcap::Packet as CapturedPacket;
use packet::Packet;
use packet::ip::v4::Packet as IpPacket;
use packet::ether::Packet as EtherPacket;
use packet::ether::Protocol;

use clap::{App, Arg, ArgGroup};


fn main() {
    let matches = App::new("Bandwidth Auditor")
        .version("0.0000000")
        .author("Derek VerLee - https://github.com/derekv")
        .about("Tracks where your bandwidth is going")
        .arg(Arg::with_name("interface")
             .short("i")
             .long("interface")
             .value_name("INTERFACE")
             .help("Listen on interface")
             .takes_value(true))
        .arg(Arg::with_name("read-file")
             .short("r")
             .long("read-file")
             .value_name("READ_FILE")
             .help("Read packets form a pcap file")
             .takes_value(true))
        .group(ArgGroup::with_name("source")
               .required(true)
               .args(&["interface", "read-file"]))
        .arg(Arg::with_name("count")
             .short("c")
             .long("count")
             .value_name("COUNT")
             .help("Exit after processing this number of packets")
             .takes_value(true))
        .arg(Arg::with_name("timeout")
             .short("t")
             .long("timeout")
             .value_name("TIMEOUT")
             .help("Timout after not receiving packet for ms")
             .takes_value(true))
        .get_matches();


    let max :u32 = if matches.is_present("count") {
        value_t!(matches, "count", u32).unwrap_or_else(|e| { e.exit(); })
    } else {0};


    println!("Quitting after {} packets",max);

    //println!("{:?}",Device::list());

    
    let mut cap:Capture<Activated> = 
        if let Some(ifname) = matches.value_of("interface") {
            if !matches.is_present("count") {
                eprintln!("Currently, count (-c --count) is required when listening on interface (-i --interface)");
                ::std::process::exit(1);
            }
            let devices = Device::list().unwrap();
            let mut device = Device::lookup().unwrap();
            match devices.iter().find(|&d| d.name==ifname[..]) {
                Some(x) => {
                    device.name = x.name.clone();
                    device.desc = x.desc.clone();
                },
                _ => {
                    println!("Could not find device named {}", ifname);
                    return;
                },
            };
             
            println!("Capturing from {:?}", device);
            
            let r = {
                let mut dev_capt = Capture::from_device(device).unwrap();
                if matches.is_present("timeout") {
                    dev_capt = dev_capt.timeout(value_t!(matches, "timeout", i32).unwrap_or_else(|e| {e.exit();}));
                }
                dev_capt.promisc(true).open()
            };
            match r {
                Ok(d) => Capture::from(d),
                Err(e) => { println!("{}",e); return },      
            }
        } else {
            let path = Path::new(matches.value_of("read-file").unwrap());
            Capture::from(Capture::from_file(path).unwrap())
        };
    
    let linktype = cap.get_datalink();
    println!("{:?} {:?} {:?}",linktype, linktype.get_name().unwrap(), linktype.get_description().unwrap());

    let extract_packet_info = 
    {
        fn extract_ip_packet(raw : &CapturedPacket) -> Result<(std::net::Ipv4Addr,std::net::Ipv4Addr,u32),String> {
            let ip = IpPacket::new(raw.data).unwrap();
            Ok((ip.source(),ip.destination(),raw.header.len))
        }
        
        fn extract_eth_packet(raw : &CapturedPacket) -> Result<(std::net::Ipv4Addr,std::net::Ipv4Addr,u32),String> {
            let eth_pkt = EtherPacket::new(raw.data).unwrap();                 
            if eth_pkt.protocol() == Protocol::Ipv4 {
                let ip = IpPacket::new(eth_pkt.payload()).unwrap();
                Ok((ip.source(),ip.destination(),raw.header.len))
            } else {
                Err(format!("Unsupported Protocol {:?}", eth_pkt.protocol()))
            }
        }
        
        match linktype {
            Linktype(12) => extract_ip_packet,
            _ => extract_eth_packet
        }
    };


    let mut linkmap = HashMap::new();
    let mut count=0;

                  
    loop {
        if max>0 && count >= max {println!("Hit max {}, {}", max,count); break;}
        let next = cap.next();
        
        if next.is_err() {
            println!("Stopping: {}", next.unwrap_err());
            break;
        }

        let packet = next.unwrap();
        
        match extract_packet_info(&packet) {
            Ok((src,dst,size)) => {
                let link = if src <= dst {
                    (src,dst)
                } else {
                    (dst,src)
                };
                
                let total = linkmap.entry(link).or_insert(0);
                *total += size;
                
                //println!("{} src:{} dst:{}",size,src,dst);
                count+=1;
            },
            Err(msg) => println!("Skipping packet: {}", msg),
        }
    }

    let mut totals_vec: Vec<(&(std::net::Ipv4Addr,std::net::Ipv4Addr),&u32)> = linkmap.iter().collect();
    totals_vec.sort_by(|a, b| b.1.cmp(a.1));

    for &(link, total) in &totals_vec {
        println!("{:?}: {:?}", link, total);
    }

    println!("Total processed packets: {}", count);
}
