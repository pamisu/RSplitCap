//! Flow grouping strategies and flow table management with LRU eviction.

use crate::cli::GroupArg;
use crate::packet::{FiveTuple, Packet};
use hashbrown::HashMap;
pub mod strategy;
pub use strategy::*;

/// Flow metadata maintained in memory.
#[derive(Debug, Clone)]
pub struct FlowState {
    pub flow_id: u64,
    pub five_tuple: Option<FiveTuple>,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub start_ts_sec: u32,
    pub start_ts_usec: u32,
    pub end_ts_sec: u32,
    pub end_ts_usec: u32,
    /// Packet data accumulated for this flow (for split mode).
    pub packets: Vec<Packet>,
    /// LRU generation — higher = more recently used.
    last_access: u64,
}

impl FlowState {
    pub fn new(flow_id: u64, pkt: &Packet, gen: u64) -> Self {
        Self {
            flow_id,
            five_tuple: pkt.five_tuple,
            packet_count: 1,
            total_bytes: pkt.orig_len as u64,
            start_ts_sec: pkt.ts_sec,
            start_ts_usec: pkt.ts_usec,
            end_ts_sec: pkt.ts_sec,
            end_ts_usec: pkt.ts_usec,
            packets: vec![pkt.clone()],
            last_access: gen,
        }
    }

    pub fn add_packet(&mut self, pkt: &Packet, gen: u64) {
        self.packet_count += 1;
        self.total_bytes += pkt.orig_len as u64;
        self.end_ts_sec = pkt.ts_sec;
        self.end_ts_usec = pkt.ts_usec;
        self.packets.push(pkt.clone());
        self.last_access = gen;
    }
}

/// Manages flow tables with LRU eviction.
pub struct FlowManager {
    strategy: GroupStrategyEnum,
    flows: HashMap<String, FlowState>,
    next_flow_id: u64,
    max_sessions: u32,
    global_pkt_idx: u64,
    /// Monotonically increasing generation counter for LRU tracking.
    lru_gen: u64,
}

impl FlowManager {
    pub fn new(arg: &GroupArg, max_sessions: u32) -> Self {
        let strategy = GroupStrategyEnum::from_group_arg(arg);
        Self {
            strategy,
            flows: HashMap::new(),
            next_flow_id: 1,
            max_sessions,
            global_pkt_idx: 0,
            lru_gen: 0,
        }
    }

    /// Assign a packet to its group(s). Returns the list of group keys.
    pub fn classify(&mut self, packet: &Packet) -> Vec<String> {
        let keys = self.strategy.group_keys(packet, self.global_pkt_idx);
        self.global_pkt_idx += 1;
        keys
    }

    /// Ensure a flow exists and add a packet to it.
    pub fn add_packet(&mut self, key: &str, packet: &Packet) {
        self.maybe_evict();
        self.lru_gen += 1;
        if let Some(flow) = self.flows.get_mut(key) {
            flow.add_packet(packet, self.lru_gen);
        } else {
            let id = self.next_flow_id;
            self.next_flow_id += 1;
            self.flows
                .insert(key.to_string(), FlowState::new(id, packet, self.lru_gen));
        }
    }

    /// Evict the least-recently-used flow when over threshold.
    fn maybe_evict(&mut self) {
        if self.flows.len() < self.max_sessions as usize {
            return;
        }
        // Find the LRU entry (lowest last_access generation)
        let mut min_gen = u64::MAX;
        let mut lru_key: Option<String> = None;
        for (key, flow) in self.flows.iter() {
            if flow.last_access < min_gen {
                min_gen = flow.last_access;
                lru_key = Some(key.clone());
            }
        }
        if let Some(key) = lru_key {
            tracing::debug!("LRU evicting flow {} (gen={})", key, min_gen);
            self.flows.remove(&key);
        }
    }

    /// Consume the flow manager and return all flows.
    pub fn into_flows(self) -> HashMap<String, FlowState> {
        self.flows
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}
