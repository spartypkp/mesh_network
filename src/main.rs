use ring::signature;
use zerocopy::{AsBytes, FromBytes, Unaligned};

// A simple packet structure
#[derive(FromBytes, AsBytes, Debug, Unaligned)]
#[repr(C, packed)]
struct SimplePacket {
    magic: [u8; 4],
    payload_length: u16,
}

fn main() {
    // Create some test data
    let test_packet = SimplePacket {
        magic: *b"MESH", // Using b"MESH" creates a byte array from ASCII
        payload_length: 10,
    };

    // Convert our packet to bytes
    let packet_bytes = test_packet.as_bytes();

    println!("Created packet with bytes: {:?}", packet_bytes);

    // Try to parse the bytes back into a packet
    match zerocopy::LayoutVerified::<&[u8], SimplePacket>::new_unaligned(packet_bytes) {
        Some(parsed_packet) => {
            let packet = parsed_packet.into_ref();
            // Copy fields to local variables first
            let magic = packet.magic;
            let payload_length = packet.payload_length;

            println!("Successfully parsed packet: {:?}", packet);
            println!("Magic bytes: {:?}", magic);
            println!("Payload length: {}", payload_length);
        }
        None => {
            println!("Failed to parse packet!");
        }
    }
}
