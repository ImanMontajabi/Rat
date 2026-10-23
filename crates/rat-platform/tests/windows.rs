#![cfg(windows)]
use rat_platform::{Monitor, read_rules};
use std::net::{TcpListener, TcpStream};

#[test]
fn live_tcp_snapshot_contains_our_socket_and_process() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = listener.local_addr().unwrap();
    let client = TcpStream::connect(remote).unwrap();
    let (_server, _) = listener.accept().unwrap();
    let mut monitor = Monitor::default();
    let snapshot = monitor.sample().unwrap();
    let connection = snapshot
        .connections
        .iter()
        .find(|c| c.local == client.local_addr().unwrap() && c.remote == remote)
        .expect("our TCP client must appear");
    assert_eq!(connection.pid, std::process::id());
    assert!(!connection.process.is_empty());
    assert!(snapshot.sent_per_sec.is_finite() && snapshot.received_per_sec.is_finite());
}

#[test]
fn firewall_rules_can_be_read_without_mutating_them() {
    read_rules().unwrap();
}

#[test]
#[ignore = "Requires an elevated terminal; creates and removes two TEST-NET rules"]
fn elevated_firewall_rule_lifecycle() {
    use rat_core::{BlockRule, Direction};
    use rat_platform::set_block;
    for direction in [Direction::Inbound, Direction::Outbound] {
        let rule = BlockRule {
            ip: "192.0.2.254".parse().unwrap(),
            direction,
        };
        assert!(
            !read_rules().unwrap().contains(&rule),
            "test address already has a rule; refusing to touch it"
        );
        set_block(&rule, true).unwrap();
        let observed = read_rules();
        // Always attempt cleanup before asserting the query outcome.
        let cleanup = set_block(&rule, false);
        cleanup.unwrap();
        assert!(observed.unwrap().contains(&rule));
        assert!(!read_rules().unwrap().contains(&rule));
    }
}
