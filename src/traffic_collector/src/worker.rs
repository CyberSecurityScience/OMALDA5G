use std::sync::{Arc, Mutex};
use crossbeam::channel::unbounded;
use crossbeam::queue::{self, ArrayQueue};

use crate::ue_stats;


pub struct Worker {
    pub id: u32,
    pub ue_stats: dashmap::DashMap<u32, ue_stats::UEStats>,
    pub failed_pkts: u32,
}

fn worker_thread(worker: Arc<Mutex<Worker>>, recv: Arc<ArrayQueue<(u32, Vec<u8>, u64, u16, bool)>>) {
    loop {
        if let Some((ue_ip, pkt_ipv4, ts, orig_len, stop)) = recv.pop() {
            if stop {
                break;
            }
            let mut worker = worker.lock().unwrap();
            worker.process_packet(ue_ip, &pkt_ipv4, orig_len, ts);
        }
    }
}

impl Worker {
    pub fn new(id: u32) -> Worker {
        Worker {
            id,
            ue_stats: dashmap::DashMap::new(),
            failed_pkts: 0,
        }
    }

    pub fn process_packet(&mut self, ue_ip: u32, pkt_ipv4: &[u8], orig_len: u16, ts: u64) {
        if !self.ue_stats.contains_key(&ue_ip) {
            self.failed_pkts += 1;
            println!("Worker {} received packet for unknown UE {}, {}", self.id, std::net::Ipv4Addr::from(ue_ip), self.failed_pkts);
            return;
        }
        let mut ue_stats = self.ue_stats.get_mut(&ue_ip).unwrap();
        ue_stats.new_packet(pkt_ipv4, orig_len, ts);
    }

    pub fn add_ue(&self, ue_ip: u32) {
        self.ue_stats.insert(ue_ip, ue_stats::UEStats::new(ue_ip));
    }

    pub fn remove_ue_with_stats(&self, ue_ip: u32) -> Option<Vec<u8>> {
        let (_, mut ret) = self.ue_stats.remove(&ue_ip)?;
        ret.end_and_encode_stats()
    }
}

pub struct WorkerThreadPool {
    pub worker_handles: Vec<std::thread::JoinHandle<()>>,
    //pub send_channels: Vec<crossbeam::channel::Sender<(u32, Vec<u8>, u64, bool)>>,
    pub queues: Vec<Arc<ArrayQueue<(u32, Vec<u8>, u64, u16, bool)>>>,
    pub workers: Vec<Arc<Mutex<Worker>>>,
}

impl WorkerThreadPool {
    pub fn new() -> WorkerThreadPool {
        let num_cpus = 20;
        // start threads
        let mut worker_handles = Vec::with_capacity(num_cpus);
        let mut workers = Vec::with_capacity(num_cpus);
        //let mut send_channels = Vec::with_capacity(num_cpus);
        let mut queues = Vec::with_capacity(num_cpus);
        for i in 0..num_cpus {
            let worker = Worker::new(i as u32);
            let worker = Arc::new(Mutex::new(worker));
            workers.push(worker.clone());
            //let (send, recv) = unbounded();
            let q = Arc::new(ArrayQueue::new(1000));
            let recv = q.clone();
            let handle = std::thread::spawn(move || worker_thread(worker, recv));
            //send_channels.push(send);
            queues.push(q);
            worker_handles.push(handle);
        }
        WorkerThreadPool {
            worker_handles,
            //send_channels,
            queues,
            workers,
        }
    }

    pub fn process_packet(&self, ue_ip: u32, pkt_ipv4: &[u8], orig_len: u16, ts: u64, realtime: bool) {
        let worker_index = ue_ip as usize % self.workers.len();
        let data = (ue_ip, pkt_ipv4.to_vec(), ts, orig_len, false);
        //self.send_channels[worker_index].send((ue_ip, pkt_ipv4.to_vec(), ts, false)).unwrap();
        if realtime {
            self.queues[worker_index].force_push(data);
        } else {
            loop {
                if let Err(_) = self.queues[worker_index].push(data.clone()) {
                    continue;
                }
                break;
            }
        }
    }

    pub fn is_all_queues_empty(&self) -> bool {
        for q in &self.queues {
            if !q.is_empty() {
                return false;
            }
        }
        true
    }

    pub fn add_ue(&self, ue_ip: u32) {
        let worker_index = ue_ip as usize % self.workers.len();
        self.workers[worker_index].lock().unwrap().add_ue(ue_ip);
    }

    pub fn remove_ue_with_stats(&self, ue_ip: u32) -> Option<Vec<u8>> {
        let worker_index = ue_ip as usize % self.workers.len();
        self.workers[worker_index].lock().unwrap().remove_ue_with_stats(ue_ip)
    }

    pub fn stop(&self) {
        // for send in &self.send_channels {
        //     send.send((0, vec![], 0, true)).unwrap();
        // }
        for q in &self.queues {
            q.force_push((0, vec![], 0, 0, true));
        }
    }
}

pub struct GlobalThreadPoolContext {
    pub thread_pool: WorkerThreadPool,
}

impl GlobalThreadPoolContext {
    pub fn new() -> GlobalThreadPoolContext {
        GlobalThreadPoolContext {
            thread_pool: WorkerThreadPool::new(),
        }
    }
}

lazy_static! {
	pub static ref GLOBAL_TP_CONTEXT: GlobalThreadPoolContext = GlobalThreadPoolContext::new();
}
