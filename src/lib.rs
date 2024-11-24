#![no_std]
extern crate alloc;
use alloc::vec; // Import the vec! macro
use alloc::vec::Vec;
use hashbrown::HashMap;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair, Signature, ED25519_PUBLIC_KEY_LEN},
};

enum PacketBody<'a> {
    Advertisement(Vec<Grant>),     // Advertisement of a node in network
    Content(Vec<Grant>, &'a [u8]), // Content being sent to a node (path of public keys, content)
    Routable(Grant, &'a [u8]),     // (destination grant, content)
}

pub struct Packet<'a> {
    body: PacketBody<'a>,
    sig: Vec<Grant>,
}

impl<'a> Packet<'a> {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // First byte: packet type
        bytes.push(match &self.body {
            PacketBody::Advertisement(_) => 0,
            PacketBody::Content(_, _) => 1,
            PacketBody::Routable(_, _) => 2,
        });

        // Write signature chain length and grants
        bytes.extend_from_slice(&(self.sig.len() as u16).to_le_bytes());
        for grant in &self.sig {
            // Serialize grant
            bytes.extend_from_slice(&(grant.key.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&grant.key);
            bytes.push(u8::from(grant.rights.can_route));
            bytes.push(u8::from(grant.rights.can_manage));
            bytes.push(u8::from(grant.rights.can_sublet));
            bytes.extend_from_slice(&grant.rights.ttl.to_le_bytes());
        }

        // Write body based on type
        match &self.body {
            PacketBody::Advertisement(grants) => {
                bytes.extend_from_slice(&(grants.len() as u16).to_le_bytes());
                for grant in grants {
                    bytes.extend_from_slice(&(grant.key.len() as u16).to_le_bytes());
                    bytes.extend_from_slice(&grant.key);
                    bytes.push(u8::from(grant.rights.can_route));
                    bytes.push(u8::from(grant.rights.can_manage));
                    bytes.push(u8::from(grant.rights.can_sublet));
                    bytes.extend_from_slice(&grant.rights.ttl.to_le_bytes());
                }
            }
            PacketBody::Content(path, content) => {
                bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
                for grant in path {
                    bytes.extend_from_slice(&(grant.key.len() as u16).to_le_bytes());
                    bytes.extend_from_slice(&grant.key);
                    bytes.push(u8::from(grant.rights.can_route));
                    bytes.push(u8::from(grant.rights.can_manage));
                    bytes.push(u8::from(grant.rights.can_sublet));
                    bytes.extend_from_slice(&grant.rights.ttl.to_le_bytes());
                }
                bytes.extend_from_slice(&(content.len() as u32).to_le_bytes());
                bytes.extend_from_slice(content);
            }
            PacketBody::Routable(dest, content) => {
                bytes.extend_from_slice(&(dest.key.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&dest.key);
                bytes.push(u8::from(dest.rights.can_route));
                bytes.push(u8::from(dest.rights.can_manage));
                bytes.push(u8::from(dest.rights.can_sublet));
                bytes.extend_from_slice(&dest.rights.ttl.to_le_bytes());
                bytes.extend_from_slice(&(content.len() as u32).to_le_bytes());
                bytes.extend_from_slice(content);
            }
        }

        bytes
    }

    pub fn deserialize(bytes: &'a [u8]) -> Option<Self> {
        let mut pos = 0;

        // Read packet type
        if bytes.is_empty() {
            return None;
        }
        let packet_type = bytes[pos];
        pos += 1;

        // Helper function to deserialize a grant
        let deserialize_grant = |pos: &mut usize| -> Option<Grant> {
            if *pos + 2 > bytes.len() {
                return None;
            }
            let key_len = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
            *pos += 2;

            if *pos + key_len > bytes.len() {
                return None;
            }
            let key = bytes[*pos..*pos + key_len].to_vec();
            *pos += key_len;

            if *pos + 3 + 8 > bytes.len() {
                return None;
            }
            let rights = Rights {
                can_route: bytes[*pos] != 0,
                can_manage: bytes[*pos + 1] != 0,
                can_sublet: bytes[*pos + 2] != 0,
                ttl: u64::from_le_bytes(bytes[*pos + 3..*pos + 11].try_into().ok()?),
            };
            *pos += 11;

            Some(Grant { key, rights })
        };

        // Read signature chain
        if pos + 2 > bytes.len() {
            return None;
        }
        let sig_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;

        let mut sig = Vec::with_capacity(sig_len);
        for _ in 0..sig_len {
            sig.push(deserialize_grant(&mut pos)?);
        }

        // Read body based on packet type
        let body = match packet_type {
            0 => {
                // Advertisement
                if pos + 2 > bytes.len() {
                    return None;
                }
                let grant_count = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                pos += 2;

                let mut grants = Vec::with_capacity(grant_count);
                for _ in 0..grant_count {
                    grants.push(deserialize_grant(&mut pos)?);
                }

                PacketBody::Advertisement(grants)
            }
            1 => {
                // Content
                if pos + 2 > bytes.len() {
                    return None;
                }
                let path_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                pos += 2;

                let mut path = Vec::with_capacity(path_len);
                for _ in 0..path_len {
                    path.push(deserialize_grant(&mut pos)?);
                }

                if pos + 4 > bytes.len() {
                    return None;
                }
                let content_len = u32::from_le_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ]) as usize;
                pos += 4;

                if pos + content_len > bytes.len() {
                    return None;
                }
                let content = &bytes[pos..pos + content_len];

                PacketBody::Content(path, content)
            }
            2 => {
                // Routable
                let dest = deserialize_grant(&mut pos)?;

                if pos + 4 > bytes.len() {
                    return None;
                }
                let content_len = u32::from_le_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ]) as usize;
                pos += 4;

                if pos + content_len > bytes.len() {
                    return None;
                }
                let content = &bytes[pos..pos + content_len];

                PacketBody::Routable(dest, content)
            }
            _ => return None,
        };

        Some(Packet { body, sig })
    }
}

// Main network structure

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Grant {
    pub key: Vec<u8>,
    pub rights: Rights,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Rights {
    pub can_route: bool,
    pub can_manage: bool,
    pub can_sublet: bool,
    pub ttl: u64,
}

pub struct NetworkNode<T: Transmitter> {
    transmitter: T,
    keypair: Ed25519KeyPair,
    sig_chain: Vec<Grant>,
    routes: HashMap<Grant, Vec<Grant>>, // Change from NetworkKey to Vec<u8>
    is_router: bool,
}

impl<T: Transmitter> NetworkNode<T> {
    pub fn new(
        transmitter: T,
        keypair: Ed25519KeyPair,
        initial_grant: Grant,
        is_router: bool,
    ) -> Self {
        Self {
            transmitter,
            keypair,
            sig_chain: vec![initial_grant],
            routes: HashMap::new(),
            is_router,
        }
    }
    // Add this new method to advertise ourselves to the network
    pub fn advertise(&mut self) {
        let packet = Packet {
            body: PacketBody::Advertisement(self.sig_chain.clone()),
            sig: self.sig_chain.clone(),
        };
        self.transmitter.transmit(&packet.serialize());
    }

    pub fn accept(&mut self, packet: Packet) {
        // Remove separate sig_chain parameter
        // Verify the signature chain from the packet itself
        self.verify_chain(&packet.sig);

        match packet.body {
            PacketBody::Content(path, content) => {
                // Convert keypair's public key to NetworkKey for comparison
                let self_key = self.keypair.public_key().as_ref().to_vec();

                if path[0].key == self_key {
                    self.handle_content(content)
                } else if self.is_router {
                    let path_keys: Vec<Grant> = path[1..].to_vec();
                    self.forward_content(path_keys, content)
                } else {
                    panic!("Node is not a router");
                }
            }

            PacketBody::Routable(dest, content) => {
                if !self.is_router {
                    panic!("Node is not a router");
                }
                if let Some(path) = self.routes.get(&dest) {
                    self.forward_content(path.clone(), content)
                } else {
                    panic!("No route to destination");
                }
            }

            PacketBody::Advertisement(new_grants) => {
                // Verify the grant chain
                self.verify_chain(&new_grants);

                // Get the advertising node's key (last in chain)
                if let Some(advertiser_grant) = new_grants.last() {
                    let advertiser_key = advertiser_grant.key.clone();

                    // If it's a router, update our routing table
                    if advertiser_grant.rights.can_route {
                        // Create route path from the grant chain
                        let route = new_grants.clone(); // Use the grants directly instead of extracting keys

                        // Update our routes
                        self.update_routes(advertiser_grant.clone(), route);

                        // If we're also a router, re-broadcast the advertisement
                        if self.is_router {
                            let packet = Packet {
                                body: PacketBody::Advertisement(new_grants),
                                sig: self.sig_chain.clone(),
                            };
                            self.transmitter.transmit(&packet.serialize());
                        }
                    }
                }
            }
        }
    }

    pub fn send(&mut self, destination: Grant, content: &[u8]) {
        // Case 1: We have a direct route to the destination
        if let Some(path) = self.routes.get(&destination) {
            let packet = Packet {
                body: PacketBody::Content(path.clone(), content),
                sig: self.sig_chain.clone(),
            };
            self.transmitter.transmit(&packet.serialize());
        } else if self.is_router {
            // Case 2: We're a router but don't know the route
            // Broadcast to all known routers
            for (_, router_path) in self.routes.iter() {
                if let Some(first_grant) = router_path.first() {
                    if first_grant.rights.can_route {
                        let routable_packet = Packet {
                            body: PacketBody::Routable(destination.clone(), content),
                            sig: self.sig_chain.clone(),
                        };
                        let serialized = routable_packet.serialize();
                        let packet = Packet {
                            body: PacketBody::Content(router_path.clone(), &serialized),
                            sig: self.sig_chain.clone(),
                        };
                        self.transmitter.transmit(&packet.serialize());
                    }
                }
            }
        } else {
            // Case 3: We're not a router, forward to nearest router
            if let Some(router_path) = self.find_nearest_router() {
                let routable_packet = Packet {
                    body: PacketBody::Routable(destination, content),
                    sig: self.sig_chain.clone(),
                };
                let serialized = routable_packet.serialize();
                let packet = Packet {
                    body: PacketBody::Content(router_path, &serialized),
                    sig: self.sig_chain.clone(),
                };
                self.transmitter.transmit(&packet.serialize());
            } else {
                panic!("No route to destination");
            }
        }
    }

    fn verify_chain(&self, chain: &[Grant]) {
        for window in chain.windows(2) {
            let grantor = &window[0];
            let grantee = &window[1];

            if !grantor.rights.can_sublet || grantor.rights.ttl == 0 {
                panic!("Invalid grant");
            }

            if !self.verify_rights(&grantor.rights, &grantee.rights) {
                panic!("Invalid rights");
            }
        }
    }

    fn verify_rights(&self, grantor: &Rights, grantee: &Rights) -> bool {
        if grantee.can_route && !grantor.can_route {
            return false;
        }
        if grantee.can_manage && !grantor.can_manage {
            return false;
        }
        if grantee.can_sublet && !grantor.can_sublet {
            return false;
        }
        if grantee.ttl > grantor.ttl {
            return false;
        }
        true
    }

    fn update_routes(&mut self, key: Grant, path: Vec<Grant>) {
        let route: Vec<Grant> = path;
        self.routes.insert(key, route);
    }

    fn find_nearest_router(&self) -> Option<Vec<Grant>> {
        self.routes
            .iter()
            .find(|(_, path)| {
                path.iter().any(|path_grant| {
                    self.sig_chain.iter().any(|chain_grant| {
                        chain_grant.key == path_grant.key && chain_grant.rights.can_route
                    })
                })
            })
            .map(|(_, path)| path.clone())
    }

    fn forward_content(&mut self, path: Vec<Grant>, content: &[u8]) {
        let packet = Packet {
            body: PacketBody::Content(path, content),
            sig: self.sig_chain.clone(),
        };
        self.transmitter.transmit(&packet.serialize());
    }

    fn handle_content(&self, content: &[u8]) {
        // Process content meant for this node
    }
}

pub trait Transmitter {
    fn transmit(&mut self, bytes: &[u8]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use core::cell::RefCell;

    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    // Simple no_std channel implementation
    struct Sender<T>(Arc<RefCell<Vec<T>>>);
    struct Receiver<T>(Arc<RefCell<Vec<T>>>);

    impl<T> Sender<T> {
        fn send(&self, value: T) {
            self.0.borrow_mut().push(value);
        }
    }

    impl<T> Receiver<T> {
        fn try_recv(&self) -> Option<T> {
            self.0.borrow_mut().pop()
        }
    }

    fn channel<T>() -> (Sender<T>, Receiver<T>) {
        let buffer = Arc::new(RefCell::new(Vec::new()));
        (Sender(buffer.clone()), Receiver(buffer))
    }

    struct MockTransmitter {
        tx: Arc<Sender<Vec<u8>>>,
    }

    impl Transmitter for MockTransmitter {
        fn transmit(&mut self, bytes: &[u8]) {
            self.tx.send(bytes.to_vec());
        }
    }

    fn create_test_network(size: usize) -> Vec<(NetworkNode<MockTransmitter>, Receiver<Vec<u8>>)> {
        let mut nodes = Vec::new();
        let rng = SystemRandom::new();

        for _ in 0..size {
            // Create communication channel
            let (tx, rx) = channel();
            let tx = Arc::new(tx);

            // Generate keypair
            let keypair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let keypair = Ed25519KeyPair::from_pkcs8(keypair.as_ref()).unwrap();

            // Create initial grant
            let initial_grant = Grant {
                key: keypair.public_key().as_ref().to_vec(),
                rights: Rights {
                    can_route: true,
                    can_manage: true,
                    can_sublet: true,
                    ttl: 100,
                },
            };

            // Create node
            let transmitter = MockTransmitter { tx };
            let node = NetworkNode::new(transmitter, keypair, initial_grant, true);

            nodes.push((node, rx));
        }

        nodes
    }

    #[test]
    fn test_single_node() {
        let mut nodes = create_test_network(1);
        let (node, _) = &mut nodes[0];

        // Test self-advertisement
        node.advertise();

        // Verify node's initial state
        assert_eq!(node.routes.len(), 0);
        assert_eq!(node.sig_chain.len(), 1);
    }

    #[test]
    fn test_basic_network_formation() {
        let mut nodes = create_test_network(3);

        // Have all nodes advertise
        for (node, _) in nodes.iter_mut() {
            node.advertise();
        }

        // Give time for advertisements to propagate
        for _ in 0..10 {
            // Simple delay loop without std
            for (node, rx) in nodes.iter_mut() {
                if let Some(data) = rx.try_recv() {
                    let packet = Packet::deserialize(&data).unwrap();
                    node.accept(packet);
                }
            }
        }

        // Verify routing tables
        for (node, _) in &nodes {
            assert!(node.routes.len() > 0, "Node should have routes");
        }
    }

    #[test]
    fn test_message_routing() {
        let mut nodes = create_test_network(5);

        // Setup network
        for (node, _) in nodes.iter_mut() {
            node.advertise();
        }

        // Process all advertisements
        for _ in 0..10 {
            for (node, rx) in nodes.iter_mut() {
                while let Some(data) = rx.try_recv() {
                    let packet = Packet::deserialize(&data).unwrap();
                    node.accept(packet);
                }
            }
        }

        // Test multi-hop message
        let content = b"Multi-hop test";
        let destination = nodes[4].0.sig_chain[0].clone();
        nodes[0].0.send(destination, content);

        // Process messages
        let mut message_received = false;
        for _ in 0..10 {
            if let Some(data) = nodes[4].1.try_recv() {
                let packet = Packet::deserialize(&data).unwrap();
                if let PacketBody::Content(_, received_content) = packet.body {
                    assert_eq!(received_content, content);
                    message_received = true;
                    break;
                }
            }
        }
        assert!(message_received, "Message should have been received");
    }

    #[test]
    fn test_network_partitioning() {
        let mut nodes = create_test_network(6);

        // Initial network formation
        for (node, _) in nodes.iter_mut() {
            node.advertise();
        }

        // Process initial advertisements
        for _ in 0..10 {
            for (node, rx) in nodes.iter_mut() {
                while let Some(data) = rx.try_recv() {
                    let packet = Packet::deserialize(&data).unwrap();
                    node.accept(packet);
                }
            }
        }

        // Remove nodes 2 and 3 to create a network partition
        nodes.remove(3);
        nodes.remove(2);

        // Test message routing around partition
        let content = b"Route around partition";
        let destination = nodes[3].0.sig_chain[0].clone();
        nodes[0].0.send(destination, content);

        // Verify message arrives despite partition
        let mut message_received = false;
        for _ in 0..10 {
            if let Some(data) = nodes[3].1.try_recv() {
                let packet = Packet::deserialize(&data).unwrap();
                if let PacketBody::Content(_, received_content) = packet.body {
                    assert_eq!(received_content, content);
                    message_received = true;
                    break;
                }
            }
        }
        assert!(message_received, "Message should route around partition");
    }

    #[test]
    fn test_grant_verification() {
        let mut nodes = create_test_network(2);

        // Create invalid grant with higher TTL than parent
        let invalid_grant = Grant {
            key: vec![1, 2, 3],
            rights: Rights {
                can_route: true,
                can_manage: true,
                can_sublet: true,
                ttl: 1000, // Higher than parent
            },
        };

        // Attempt to advertise with invalid grant chain
        let packet = Packet {
            body: PacketBody::Advertisement(vec![nodes[0].0.sig_chain[0].clone(), invalid_grant]),
            sig: nodes[0].0.sig_chain.clone(),
        };

        #[should_panic(expected = "Invalid grant")]
        {
            nodes[1].0.accept(packet);
        }
    }
}
