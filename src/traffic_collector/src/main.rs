
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate lazy_static;
use clap::Parser;
use serde::{Serialize, Deserialize};

use std::{collections::HashSet, io::{Read, Write}, str::FromStr};



use actix_web::{web, App, HttpServer};
use aes_gcm::{aead::Aead, AeadCore, Aes128Gcm, Key, KeyInit, Nonce};
use cbc::cipher;
use etherparse::ether_type;
use pcap::Capture;
use aes::cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use chrono::{DateTime, NaiveDateTime, Utc};
use libc::timeval;
use worker::GLOBAL_TP_CONTEXT;

mod stat_tracker;
mod flow_stats;
mod flow5tuple;
mod ue_stats;
mod worker;

fn if_read_thread(if_name: String, ue_ip_range_start: u32, ue_ip_range_end: u32) {
    // open interface
    let mut cap = Capture::from_device(if_name.as_str()).unwrap()
        .promisc(true)
        .snaplen(400)
        .open().unwrap();
    // loop over packets
    while let Ok(packet) = cap.next_packet() {
        let ts_us = packet.header.ts.tv_sec as u64 * 1_000_000 + packet.header.ts.tv_usec as u64;
        let pkt_eth = packet.data;
        if pkt_eth.len() < 14 + 20 {
            continue;
        }
        let pkt_ipv4 = if pkt_eth[12] == 0x08 && pkt_eth[13] == 0x00 {
            &pkt_eth[14..]
        } else {
            continue;
        };
        // check if UDP is present, could be encapsulated in GTP, if so skip GTP
        let protocol = pkt_ipv4[9];
        let pkt_ipv4 = if protocol == 17 && pkt_ipv4.len() >= 20 + 8 + 16 {
            let udp_dst_port = u16::from_be_bytes([pkt_ipv4[20 + 2], pkt_ipv4[20 + 3]]);
            if udp_dst_port == 2152 {
                &pkt_ipv4[20 + 8 + 16..]
            } else {
                pkt_ipv4
            }
        } else {
            pkt_ipv4
        };
        let src_ip = u32::from_be_bytes([pkt_ipv4[12], pkt_ipv4[13], pkt_ipv4[14], pkt_ipv4[15]]);
        let dst_ip = u32::from_be_bytes([pkt_ipv4[16], pkt_ipv4[17], pkt_ipv4[18], pkt_ipv4[19]]);
        let ue_ip = if src_ip >= ue_ip_range_start && src_ip <= ue_ip_range_end {
            src_ip
        } else if dst_ip >= ue_ip_range_start && dst_ip <= ue_ip_range_end {
            dst_ip
        } else {
            continue;
        };
        let orig_len = u16::from_be_bytes([pkt_ipv4[2], pkt_ipv4[3]]);
        let cut_length = std::cmp::min(orig_len as usize, flow_stats::DPI_BYTES);
        GLOBAL_TP_CONTEXT.thread_pool.process_packet(ue_ip, &pkt_ipv4[..cut_length], orig_len, ts_us, true);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddUERequst {
    pub ue_ip: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUEStatsRequst {
    pub ue_ip: String
}

// add ue post handler
pub async fn add_ue(data: web::Data<WebData>, req: web::Json<AddUERequst>) -> web::Json<String> {
    let ue_ip = req.ue_ip.parse::<std::net::Ipv4Addr>().unwrap();
    GLOBAL_TP_CONTEXT.thread_pool.add_ue(u32::from_be_bytes(ue_ip.octets()));
    web::Json("OK".to_string())
}

// get ue stats post handler, return binary data
pub async fn get_ue_stats(data: web::Data<WebData>, req: web::Json<GetUEStatsRequst>) -> impl actix_web::Responder {
    let ue_ip = req.ue_ip.parse::<std::net::Ipv4Addr>().unwrap();
    let stats = GLOBAL_TP_CONTEXT.thread_pool.remove_ue_with_stats(u32::from_be_bytes(ue_ip.octets()));
    if stats.is_none() {
        return actix_web::HttpResponse::NotFound().finish();
    }
    let stats = stats.unwrap();
    let mut res = Vec::new();
    res.extend_from_slice(&stats);
    actix_web::HttpResponse::Ok().body(res)
}


#[derive(Debug, Clone)]
pub struct WebData {
}


// if mode handles packet from an interface
pub async fn if_mode_main(if_name: String, ue_ip_range_start: u32, ue_ip_range_end: u32) {    // create web server data
    // start if read thread
    let if_name_clone = if_name.clone();
    std::thread::spawn(move || {
        if_read_thread(if_name_clone, ue_ip_range_start, ue_ip_range_end);
    });
    // start web server
    let web_data = WebData {
    };
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(web_data.clone()))
            .route("/add_ue", web::post().to(add_ue))
            .route("/get_ue_stats", web::post().to(get_ue_stats))
    })
    .bind("0.0.0.0:5185").unwrap()
    .run()
    .await.unwrap();
}

// if mode handles packet from a pcap file
pub async fn pcap_mode_main(pcap_filename: String, ue_ip_range_start: u32, ue_ip_range_end: u32, out_csv_filename: String, out_dns_filename: String) {    
    // read pcap
    let mut cap = Capture::from_file(pcap_filename).unwrap();
    let mut seen_ues: HashSet<u32> = HashSet::new();
    while let Ok(packet) = cap.next_packet() {
        let pkt_eth = packet.data;
        if pkt_eth.len() < 14 + 20 {
            continue;
        }
        let pkt_ipv4 = if pkt_eth[12] == 0x08 && pkt_eth[13] == 0x00 {
            &pkt_eth[14..]
        } else {
            continue;
        };
        // check if UDP is present, could be encapsulated in GTP, if so skip GTP
        let protocol = pkt_ipv4[9];
        let pkt_ipv4 = if protocol == 17 && pkt_ipv4.len() >= 20 + 8 + 16 {
            let udp_dst_port = u16::from_be_bytes([pkt_ipv4[20 + 2], pkt_ipv4[20 + 3]]);
            if udp_dst_port == 2152 {
                &pkt_ipv4[20 + 8 + 16..]
            } else {
                pkt_ipv4
            }
        } else {
            pkt_ipv4
        };
        let src_ip = u32::from_be_bytes([pkt_ipv4[12], pkt_ipv4[13], pkt_ipv4[14], pkt_ipv4[15]]);
        let dst_ip = u32::from_be_bytes([pkt_ipv4[16], pkt_ipv4[17], pkt_ipv4[18], pkt_ipv4[19]]);
        let ue_ip = if src_ip >= ue_ip_range_start && src_ip <= ue_ip_range_end {
            src_ip
        } else if dst_ip >= ue_ip_range_start && dst_ip <= ue_ip_range_end {
            dst_ip
        } else {
            continue;
        };
        if !seen_ues.contains(&ue_ip) {
            seen_ues.insert(ue_ip);
            GLOBAL_TP_CONTEXT.thread_pool.add_ue(ue_ip);
        }
        let ts = packet.header.ts.tv_sec as u64 * 1_000_000 + packet.header.ts.tv_usec as u64;
        let orig_len = u16::from_be_bytes([pkt_ipv4[2], pkt_ipv4[3]]);
        let cut_length = std::cmp::min(orig_len as usize, flow_stats::DPI_BYTES);
        GLOBAL_TP_CONTEXT.thread_pool.process_packet(ue_ip, &pkt_ipv4[..cut_length], orig_len, ts, false);
    }

    while !GLOBAL_TP_CONTEXT.thread_pool.is_all_queues_empty() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    // create csv
    let mut csv_file = std::fs::File::create(out_csv_filename).unwrap();
    let mut dns_file = std::fs::File::create(out_dns_filename).unwrap();
    let mut header = "Flow ID,Host,Src IP,Src Port,Dst IP,Dst Port,Timestamp,Content,DNS Query,DNS Resp".to_string();
    for i in 0..(65+2) {
        header.push_str(&format!(",Feat {}", i));
    }
    header.push_str("\n");
    csv_file.write(header.as_bytes()).unwrap();
    let mut flow_id = 0;
    for ue in seen_ues.iter() {
        let stats = GLOBAL_TP_CONTEXT.thread_pool.remove_ue_with_stats(*ue);
        if stats.is_none() {
            continue;
        }
        let stats = stats.unwrap();
        let flow_count_bytes = u32::from_be_bytes([stats[0], stats[1], stats[2], stats[3]]);
        let flow_count = flow_count_bytes as usize;
        let mut offset = 4;
        for _ in 0..flow_count {
            let has_dns = stats[offset] != 0; offset += 1;
            let client_ip = u32::from_be_bytes([stats[offset], stats[offset+1], stats[offset+2], stats[offset+3]]); offset += 4;
            let client_port = u16::from_be_bytes([stats[offset], stats[offset+1]]); offset += 2;
            let server_ip = u32::from_be_bytes([stats[offset], stats[offset+1], stats[offset+2], stats[offset+3]]); offset += 4;
            let server_port = u16::from_be_bytes([stats[offset], stats[offset+1]]); offset += 2;
            let first_pkt_ts = u64::from_be_bytes([stats[offset], stats[offset+1], stats[offset+2], stats[offset+3], stats[offset+4], stats[offset+5], stats[offset+6], stats[offset+7]]); offset += 8;
            // extract 2 int features
            let mut feat_int = [0u32; 2];
            for i in 0..2 {
                feat_int[i] = u32::from_be_bytes([stats[offset], stats[offset+1], stats[offset+2], stats[offset+3]]); offset += 4;
            }
            // extract the 65 features
            let mut feat_fp = [0f64; 65];
            for i in 0..65 {
                feat_fp[i] = f64::from_be_bytes([stats[offset], stats[offset+1], stats[offset+2], stats[offset+3], stats[offset+4], stats[offset+5], stats[offset+6], stats[offset+7]]); offset += 8;
            }
            // extract the DPI content
            let content_len = flow_stats::DPI_BYTES;
            let dpi_bytes_len = u32::from_be_bytes([stats[offset], stats[offset+1], stats[offset+2], stats[offset+3]]) as usize; offset += 4;
            let content = &stats[offset..offset+content_len]; offset += content_len;
            // extract the DNS query
            let dns_query = if has_dns {
                let query_len = u32::from_be_bytes([stats[offset], stats[offset+1], stats[offset+2], stats[offset+3]]) as usize; offset += 4;
                let q = std::str::from_utf8(&stats[offset..offset+query_len]).unwrap(); offset += query_len;
                Some(q.to_string())
            } else {
                None
            };
            let ts = chrono::DateTime::from_timestamp_micros(first_pkt_ts as _).unwrap();
            let mut line = format!("{},{},{},{},{},{},{},{},{},{}",
                flow_id,
                std::net::Ipv4Addr::from(server_ip.to_be_bytes()),
                std::net::Ipv4Addr::from(client_ip.to_be_bytes()),
                client_port,
                std::net::Ipv4Addr::from(server_ip.to_be_bytes()),
                server_port,
                ts.format("%+"),
                hex::encode(&content[..dpi_bytes_len]),
                dns_query.as_ref().unwrap_or(&"N/A".into()),
                "N/A".to_string()
            );
            for ele in feat_int {
                line.push_str(&format!(",{}", ele));
            }
            for mut ele in feat_fp {
                if !ele.is_normal() {
                    ele = 0.0f64;
                }
                line.push_str(&format!(",{}", ele));
            }
            line.push_str("\n");
            csv_file.write(line.as_bytes()).unwrap();
            if let Some(dns_query) = dns_query {
                dns_file.write(format!("{}\n", dns_query).as_bytes()).unwrap();
            }
            flow_id += 1;
        }
    }
    GLOBAL_TP_CONTEXT.thread_pool.stop();
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Mode of operation: "if" for interface, "pcap" for pcap file
    #[arg(short, long)]
    mode: String,

    /// Interface name (if mode is "if")
    #[arg(short, long)]
    if_name: Option<String>,

    /// UE IP range CIDR (if mode is "if") (e.g. 10.0.2.0/24)
    #[arg(short, long)]
    ue_ip_range: Option<String>,

    /// Pcap filename (if mode is "pcap")
    #[arg(short, long)]
    pcap_filename: Option<String>,

    /// Output CSV filename (if mode is "pcap")
    #[arg(short, long)]
    out_csv_filename: Option<String>,
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Args = Args::parse();
    let ue_ip_range = args.ue_ip_range.unwrap();
    let ue_ip_range_cidr = cidr::IpCidr::from_str(ue_ip_range.as_str()).unwrap();
    let (ue_ip_range_start, ue_ip_range_end) = match ue_ip_range_cidr {
        cidr::IpCidr::V4(c) => (
            u32::from_be_bytes(c.first_address().octets()),
            u32::from_be_bytes(c.last_address().octets())
        ),
        _ => panic!("Only IPv4 supported"),
    };
    match args.mode.as_str() {
        "if" => {
            if_mode_main(args.if_name.unwrap(), ue_ip_range_start, ue_ip_range_end).await;
        },
        "pcap" => {
            let output_dns_filename = args.out_csv_filename.clone().unwrap() + ".dns.txt";
            pcap_mode_main(args.pcap_filename.unwrap(), ue_ip_range_start, ue_ip_range_end, args.out_csv_filename.unwrap(), output_dns_filename).await;
        },
        _ => {
            panic!("Invalid mode");
        }
    }

    Ok(())
}


