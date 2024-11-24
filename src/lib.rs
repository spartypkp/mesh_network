#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use hashbrown::HashMap;
use ring::{agreement::PublicKey, signature::KeyPair};

enum PacketBody<'a> {
    Advertisement(Vec<Grant>),         // Advertisement of a node in annetwork
    Content(Vec<PublicKey>, &'a [u8]), // Content being sent to a node
    Routable(PublicKey, &'a [u8]), // I have some bytes not sure where just gonna pass this to a router node
}

pub struct Packet<'a> {
    body: PacketBody<'a>,
    sig: Vec<Grant>,
}

// Main network structure
pub struct NetworkNode<T: Transmitter, K: KeyPair> {
    transmitter: T,
    keypair: K,
    sig_chain: Vec<Grant>, // Our permissions within the network
    routes: HashMap<PublicKey, Vec<PublicKey>>,
    is_router: bool,
}
pub struct Grant {
    pub key: PublicKey,
    pub rights: Rights,
}
pub struct Rights {
    pub can_route: bool,  // Can you forward packets?
    pub can_manage: bool, // Can you add/remove nodes from the network
    pub can_sublet: bool, // Can you sublet your rights to another node
    pub ttl: u64,         // Time to live
}

impl<T: Transmitter, K: KeyPair> NetworkNode<T, K> {
    // pub fn new

    // pub fn accept(some data)
    // Takes in some random data:
    // 1. Verify the signature chain (check that each grant is signed by the previous grant and that the Rights are valid)
    // 2. Match packet content
    // - If this is a content packet, handle it
    // - If this is a forward packet, forward it -> Straight to known destination in range
    // - If this is a routable packet, route it -> Throw it to the next hop in the network

    //  pub fn send(destination - public key, content - some data as bytes)
    //  - Create a new packet with the destination, content, and our key
    //  - Sign the packet with our key
    //  - Transmit the packet
}

pub trait Transmitter {
    fn transmit(&mut self, bytes: &[u8]);
}

mod tests {
    use super::*;

    #[test]
    fn generate_new_keypairs() {
        // TODO: Implement
    }

    #[test]
    fn test_network_node() {
        // TODO: Implement
    }
}
