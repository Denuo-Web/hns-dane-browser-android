#![no_main]

use hns_core::network;
use hns_p2p::{
    DnsRelayPacket, FrameDecoder, GetDnsRelayPacket, Packet, decode_frame, prepare_dns_relay_query,
    validate_dns_relay_response,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mainnet = network::mainnet();
    let _ = decode_frame(&mainnet, data);
    let mut decoder = FrameDecoder::new(mainnet);
    let _ = decoder.feed(data);

    if let Some((&packet_type, payload)) = data.split_first() {
        let _ = Packet::decode_payload(packet_type, payload);
    }

    let _ = GetDnsRelayPacket::decode(data);
    let _ = DnsRelayPacket::decode(data);
    let _ = prepare_dns_relay_query(data);
    let midpoint = data.len() / 2;
    let _ = validate_dns_relay_response(&data[..midpoint], &data[midpoint..]);
});
