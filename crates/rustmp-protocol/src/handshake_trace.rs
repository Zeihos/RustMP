//! Offline handshake trace correlation from PCAP metadata.
//!
//! An observed offline open reply is NOT an authenticated game connection.
//! Missing packets may reflect capture loss, filtering or real packet loss.
//! There is no access to passwords, cookies or raw packet payloads here.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use crate::capture::{CaptureReport, FrameKind};

pub const MAX_OFFLINE_FLOWS: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowError { InvalidServerPort, TooManyFlows }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineState {
    AwaitingReply,
    OfflineReplyObserved,
    OrphanChallenge,
    OrphanReply,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineFlow {
    pub client: SocketAddrV4,
    pub server: SocketAddrV4,
    pub profile: &'static str,
    pub first_record: usize,
    pub last_record: usize,
    pub requests: usize,
    pub cookie_challenges: usize,
    pub open_replies: usize,
    pub repeated_requests: usize,
    pub retries_after_reply: usize,
    pub challenges_before_request: usize,
    pub replies_before_request: usize,
    pub timestamp_order_issues: usize,
    pub state: OfflineState,
}
impl OfflineFlow {
    fn new(c: SocketAddrV4, s: SocketAddrV4, profile: &'static str, n: usize) -> Self {
        Self {
            client:c, server:s, profile, first_record:n, last_record:n,
            requests:0, cookie_challenges:0, open_replies:0,
            repeated_requests:0, retries_after_reply:0,
            challenges_before_request:0, replies_before_request:0,
            timestamp_order_issues:0, state:OfflineState::AwaitingReply,
        }
    }
    /// This is a property of the capture, NOT proof of network packet loss.
    pub fn missing_reply_in_capture(&self) -> bool {
        self.requests > 0 && self.open_replies == 0
    }
    pub fn total_anomalies(&self) -> usize {
        self.retries_after_reply + self.challenges_before_request
            + self.replies_before_request + self.timestamp_order_issues
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineFlowReport {
    pub server_port: u16,
    pub flows: Vec<OfflineFlow>,
    pub skipped_events: usize,
}

/// Group observed offline messages by exact client/server endpoint and
/// profile. The server port must be explicit to avoid guessing direction.
/// Reports include no raw payloads, player identities or actual login state.
pub fn analyze_offline_flows(
    report: &CaptureReport, server_port: u16,
) -> Result<OfflineFlowReport, FlowError> {
    if server_port == 0 { return Err(FlowError::InvalidServerPort); }
    let mut out=OfflineFlowReport {
        server_port, flows:Vec::new(), skipped_events:0,
    };
    let mut indexes: HashMap<(SocketAddrV4,SocketAddrV4,&'static str),usize> = HashMap::new();
    let mut first_request_time: Vec<Option<(u32,u32)>> = Vec::new();
    for ev in &report.events {
        let FrameKind::Offline{profile,message} = ev.kind else { continue };
        if !matches!(message, "open-request" | "open-reply" | "cookie-challenge") {
            continue;
        }
        let (client,server) = if message=="open-request" {
            (ev.source,ev.destination)
        } else { (ev.destination,ev.source) };
        if server.port()!=server_port || client.port()==server_port {
            out.skipped_events+=1;
            continue;
        }
        let key=(client,server,profile);
        let i=if let Some(&i)=indexes.get(&key) { i } else {
            if out.flows.len()>=MAX_OFFLINE_FLOWS {
                return Err(FlowError::TooManyFlows);
            }
            let i=out.flows.len();
            out.flows.push(OfflineFlow::new(client,server,profile,ev.record));
            first_request_time.push(None);
            indexes.insert(key,i);
            i
        };
        let f=&mut out.flows[i];
        f.last_record=ev.record;
        match message {
            "open-request" => {
                if f.requests>0 { f.repeated_requests+=1; }
                if f.open_replies>0 { f.retries_after_reply+=1; }
                f.requests+=1;
                if first_request_time[i].is_none() {
                    first_request_time[i]=Some((ev.seconds,ev.fraction));
                }
            }
            "cookie-challenge" => {
                f.cookie_challenges+=1;
                if f.requests==0 { f.challenges_before_request+=1; }
                if first_request_time[i].is_some_and(|first| {
                    (ev.seconds,ev.fraction)<first
                }) { f.timestamp_order_issues+=1; }
            }
            "open-reply" => {
                f.open_replies+=1;
                if f.requests==0 { f.replies_before_request+=1; }
                if first_request_time[i].is_some_and(|first| {
                    (ev.seconds,ev.fraction)<first
                }) { f.timestamp_order_issues+=1; }
            }
            _ => unreachable!("messages already filtered"),
        }
        f.state=if f.open_replies>0 && f.requests>0 {
            OfflineState::OfflineReplyObserved
        } else if f.open_replies>0 {
            OfflineState::OrphanReply
        } else if f.requests>0 {
            OfflineState::AwaitingReply
        } else {
            OfflineState::OrphanChallenge
        };
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureReport, FrameKind, TimestampResolution, UdpEvent};
    use std::net::Ipv4Addr;

    fn a(ip:u8,port:u16)->SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192,0,2,ip),port)
    }
    fn e(n:usize,src:SocketAddrV4,dst:SocketAddrV4,
         profile:&'static str,message:&'static str)->UdpEvent {
        UdpEvent {
            record:n,seconds:10,fraction:n as u32,source:src,destination:dst,
            wire_bytes:3,kind:FrameKind::Offline{profile,message},
            reliable:None,
        }
    }
    fn r(events:Vec<UdpEvent>)->CaptureReport {
        CaptureReport {
            resolution:TimestampResolution::Microseconds,
            records:events.len(),udp_seen:events.len(),events,
            skipped_ip_fragments:0,skipped_malformed_packets:0,
        }
    }
    #[test]
    fn samp_retry_before_reply_is_not_claimed_as_loss() {
        let (c,s)=(a(1,45000),a(2,7777));
        let x=analyze_offline_flows(&r(vec![
            e(1,c,s,"SA-MP","open-request"),
            e(2,c,s,"SA-MP","open-request"),
            e(3,s,c,"SA-MP","open-reply"),
        ]),7777).unwrap();
        assert_eq!(x.flows.len(),1);
        let f=&x.flows[0];
        assert_eq!((f.requests,f.repeated_requests,f.open_replies),(2,1,1));
        assert_eq!(f.total_anomalies(),0);
        assert_eq!(f.state,OfflineState::OfflineReplyObserved);
    }
    #[test]
    fn openmp_cookie_retry_and_post_reply_request() {
        let (c,s)=(a(1,45000),a(2,7777));
        let x=analyze_offline_flows(&r(vec![
            e(1,c,s,"open.mp","open-request"),
            e(2,s,c,"open.mp","cookie-challenge"),
            e(3,c,s,"open.mp","open-request"),
            e(4,s,c,"open.mp","open-reply"),
            e(5,c,s,"open.mp","open-request"),
        ]),7777).unwrap();
        let f=&x.flows[0];
        assert_eq!(f.cookie_challenges,1);
        assert_eq!(f.repeated_requests,2);
        assert_eq!(f.retries_after_reply,1);
        assert_eq!(f.total_anomalies(),1);
    }
    #[test]
    fn missing_reply_and_orphans_are_only_observations() {
        let (c,s)=(a(1,45000),a(2,7777));
        let x=analyze_offline_flows(&r(vec![
            e(1,c,s,"SA-MP","open-request"),
            e(2,s,c,"open.mp","cookie-challenge"),
            e(3,s,c,"open.mp","open-reply"),
        ]),7777).unwrap();
        assert_eq!(x.flows.len(),2);
        assert!(x.flows[0].missing_reply_in_capture());
        assert_eq!(x.flows[1].challenges_before_request,1);
        assert_eq!(x.flows[1].replies_before_request,1);
        assert_eq!(x.flows[1].state,OfflineState::OrphanReply);
    }
    #[test]
    fn isolate_ports_ips_and_profiles() {
        let s=a(2,7777);
        let x=analyze_offline_flows(&r(vec![
            e(1,a(1,45000),s,"SA-MP","open-request"),
            e(2,a(1,45001),s,"SA-MP","open-request"),
            e(3,a(3,45000),s,"SA-MP","open-request"),
            e(4,a(1,45000),s,"open.mp","open-request"),
        ]),7777).unwrap();
        assert_eq!(x.flows.len(),4);
        assert!(x.flows.iter().all(|f|f.requests==1));
    }
    #[test]
    fn skip_wrong_and_ambiguous_server_ports() {
        let x=analyze_offline_flows(&r(vec![
            e(1,a(1,7777),a(2,7777),"SA-MP","open-request"),
            e(2,a(1,4000),a(2,5000),"SA-MP","open-request"),
        ]),7777).unwrap();
        assert_eq!(x.flows.len(),0);
        assert_eq!(x.skipped_events,2);
        assert_eq!(analyze_offline_flows(&r(vec![]),0),Err(FlowError::InvalidServerPort));
    }
    #[test]
    fn timestamp_regression_after_request_is_flagged() {
        let (c,s)=(a(1,45000),a(2,7777));
        let mut reply=e(2,s,c,"SA-MP","open-reply");
        reply.seconds=9;
        let x=analyze_offline_flows(&r(vec![
            e(1,c,s,"SA-MP","open-request"),reply,
        ]),7777).unwrap();
        assert_eq!(x.flows[0].timestamp_order_issues,1);
    }
    #[test]
    fn reject_unbounded_flow_proliferation() {
        let s=a(2,7777);
        let events=(0..=MAX_OFFLINE_FLOWS).map(|n| {
            e(n+1,a(1,10000+n as u16),s,"SA-MP","open-request")
        }).collect();
        assert_eq!(analyze_offline_flows(&r(events),7777),Err(FlowError::TooManyFlows));
    }
}
