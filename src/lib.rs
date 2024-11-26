#![no_std]
extern crate alloc;
use alloc::vec; // Import the vec! macro
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;
use ring::signature::{Ed25519KeyPair, KeyPair};

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

        // First byte is packet type
        match &self.body {
            PacketBody::Advertisement(grants) => {
                bytes.push(0);
                // Serialize grants
                for grant in grants {
                    bytes.extend_from_slice(&grant.key);
                    bytes.extend_from_slice(&[
                        grant.rights.can_route as u8,
                        grant.rights.can_manage as u8,
                        grant.rights.can_sublet as u8,
                    ]);
                    bytes.extend_from_slice(&grant.rights.ttl.to_be_bytes());
                }
            }
            PacketBody::Content(path, content) => {
                bytes.push(1);
                // Serialize path
                for grant in path {
                    bytes.extend_from_slice(&grant.key);
                    bytes.extend_from_slice(&[
                        grant.rights.can_route as u8,
                        grant.rights.can_manage as u8,
                        grant.rights.can_sublet as u8,
                    ]);
                    bytes.extend_from_slice(&grant.rights.ttl.to_be_bytes());
                }
                // Serialize content
                bytes.extend_from_slice(content);
            }
            PacketBody::Routable(dest, content) => {
                bytes.push(2);
                // Serialize destination
                bytes.extend_from_slice(&dest.key);
                bytes.extend_from_slice(&[
                    dest.rights.can_route as u8,
                    dest.rights.can_manage as u8,
                    dest.rights.can_sublet as u8,
                ]);
                bytes.extend_from_slice(&dest.rights.ttl.to_be_bytes());
                // Serialize content
                bytes.extend_from_slice(content);
            }
        }

        // Serialize signature chain
        for grant in &self.sig {
            bytes.extend_from_slice(&grant.key);
            bytes.extend_from_slice(&[
                grant.rights.can_route as u8,
                grant.rights.can_manage as u8,
                grant.rights.can_sublet as u8,
            ]);
            bytes.extend_from_slice(&grant.rights.ttl.to_be_bytes());
        }

        bytes
    }

    pub fn deserialize(data: &'a [u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let packet_type = data[0];
        let mut pos = 1;

        let (body, new_pos) = match packet_type {
            0 => {
                // Advertisement
                let (grants, next_pos) = Self::deserialize_grants(data, pos)?;
                (PacketBody::Advertisement(grants), next_pos)
            }
            1 => {
                // Content
                let (path, next_pos) = Self::deserialize_grants(data, pos)?;
                let content = &data[next_pos..];
                (PacketBody::Content(path, content), data.len())
            }
            2 => {
                // Routable
                let (dest, next_pos) = Self::deserialize_grant(data, pos)?;
                let content = &data[next_pos..];
                (PacketBody::Routable(dest, content), data.len())
            }
            _ => return None,
        };

        Some(Packet {
            body,
            sig: Vec::new(), // Signature chain is handled separately
        })
    }

    fn deserialize_grant(data: &[u8], pos: usize) -> Option<(Grant, usize)> {
        // 32 bytes for key + 3 bytes for flags + 8 bytes for TTL
        if pos + 32 + 3 + 8 > data.len() {
            return None;
        }

        let key = data[pos..pos + 32].to_vec();
        let rights = Rights {
            can_route: data[pos + 32] != 0,
            can_manage: data[pos + 33] != 0,
            can_sublet: data[pos + 34] != 0,
            ttl: u64::from_be_bytes(data[pos + 35..pos + 43].try_into().ok()?),
        };

        Some((Grant { key, rights }, pos + 43))
    }

    fn deserialize_grants(data: &[u8], start_pos: usize) -> Option<(Vec<Grant>, usize)> {
        let mut grants = Vec::new();
        let mut pos = start_pos;

        while pos < data.len() {
            let (grant, next_pos) = Self::deserialize_grant(data, pos)?;
            grants.push(grant);
            pos = next_pos;
        }

        Some((grants, pos))
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
        let public_key = keypair.public_key().as_ref().to_vec();
        assert_eq!(
            initial_grant.key, public_key,
            "Initial grant must match node's public key"
        );

        Self {
            transmitter,
            keypair,
            sig_chain: vec![initial_grant],
            routes: HashMap::new(),
            is_router,
        }
    }
    // Sign a packet
    fn sign_packet(&self, packet: &[u8]) -> Vec<u8> {
        self.keypair.sign(packet).as_ref().to_vec()
    }
    // Advertise the node's grants to the network
    pub fn advertise(&mut self) {
        let packet = Packet {
            body: PacketBody::Advertisement(self.sig_chain.clone()),
            sig: self.sig_chain.clone(),
        };
        let serialized = packet.serialize();
        let signature = self.sign_packet(&serialized);

        self.transmitter
            .transmit(&[&serialized[..], &signature[..]].concat());
    }
    // Accept incoming packets with unknown qualities.
    pub fn accept(&mut self, packet: Packet, signature: &[u8]) -> bool {
        let packet_data = packet.serialize();
        if !self.verify_signature(&packet_data, signature, &packet.sig[0].key) {
            return false;
        }

        if !self.verify_chain(&packet.sig) {
            return false;
        }

        self.handle_packet(packet);
        true
    }
    // Verify the signature of a packet
    fn verify_signature(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        use ring::signature::UnparsedPublicKey;
        use ring::signature::ED25519;

        let key = UnparsedPublicKey::new(&ED25519, public_key);
        key.verify(data, signature).is_ok()
    }

    // Assuming a packet's signature is valid, and the signature chain is verified as well.
    // Handle incoming packet. Determine what to do with it.
    fn handle_packet(&mut self, packet: Packet) {
        match packet.body {
            PacketBody::Content(path, content) => {
                if let Some(last_grant) = path.last() {
                    if self.sig_chain.iter().any(|g| g.key == last_grant.key) {
                        self.handle_content(content);
                        return;
                    }
                }

                if self.is_router && self.is_path_valid(&path) {
                    if let Some(new_path) = path.get(1..).map(|p| p.to_vec()) {
                        self.forward_content(new_path, content);
                    }
                }
            }

            PacketBody::Routable(dest, content) => {
                if !self.is_router {
                    return;
                }

                if let Some(path) = self.routes.get(&dest).cloned() {
                    if self.is_path_valid(&path) {
                        self.forward_content(path, content);
                        return;
                    }
                    self.routes.remove(&dest);
                }

                if let Some(router_path) = self.find_nearest_router() {
                    let packet = Packet {
                        body: PacketBody::Routable(dest, content),
                        sig: [self.sig_chain.clone(), router_path].concat(),
                    };
                    self.transmitter.transmit(&packet.serialize());
                }
            }

            PacketBody::Advertisement(new_grants) => {
                self.handle_advertisement(new_grants, packet.sig);
            }
        }
    }

    pub fn send(&mut self, destination: Grant, content: &[u8]) {
        // Try direct route first
        if let Some(path) = self.routes.get(&destination).cloned() {
            if self.is_path_valid(&path) && (path.len() == 1 || self.is_router) {
                self.forward_content(path, content);
                return;
            }
        }

        // Try through router
        if let Some(router_path) = self.find_nearest_router() {
            let packet = Packet {
                body: PacketBody::Routable(destination, content),
                sig: [self.sig_chain.clone(), router_path].concat(),
            };
            self.transmitter.transmit(&packet.serialize());
        }
    }

    fn is_path_valid(&self, path: &[Grant]) -> bool {
        if path.is_empty() {
            return false;
        }

        // Check each hop in the path
        path.windows(2).all(|window| {
            let (current, next) = (&window[0], &window[1]);
            current.rights.can_route && current.rights.ttl > 0 && next.rights.ttl > 0
        })
    }

    // Verify the signature chain
    fn verify_chain(&self, chain: &[Grant]) -> bool {
        for window in chain.windows(2) {
            let grantor = &window[0];
            let grantee = &window[1];

            if !grantor.rights.can_sublet || grantor.rights.ttl == 0 {
                return false;
            }

            if !self.verify_rights(&grantor.rights, &grantee.rights) {
                return false;
            }
        }
        true
    }

    // Verify the rights of a grant
    fn verify_rights(&self, grantor: &Rights, grantee: &Rights) -> bool {
        // Debug assertions
        assert!(true, "Verifying rights:");
        assert!(
            true,
            "Grantor: route={}, manage={}, sublet={}, ttl={}",
            grantor.can_route, grantor.can_manage, grantor.can_sublet, grantor.ttl
        );
        assert!(
            true,
            "Grantee: route={}, manage={}, sublet={}, ttl={}",
            grantee.can_route, grantee.can_manage, grantee.can_sublet, grantee.ttl
        );

        if grantee.can_route && !grantor.can_route {
            assert!(true, "Failed: routing rights");
            return false;
        }
        if grantee.can_manage && !grantor.can_manage {
            assert!(true, "Failed: management rights");
            return false;
        }
        if grantee.can_sublet && !grantor.can_sublet {
            assert!(true, "Failed: subletting rights");
            return false;
        }
        if grantee.ttl > grantor.ttl {
            assert!(true, "Failed: TTL check {} > {}", grantee.ttl, grantor.ttl);
            return false;
        }
        true
    }

    // Update the routes
    fn update_routes(&mut self, key: Grant, new_path: Vec<Grant>) {
        // Verify the path is valid
        let path_valid = new_path.windows(2).all(|window| {
            let (prev, next) = (&window[0], &window[1]);
            // Each hop must have routing rights and valid TTL
            prev.rights.can_route && prev.rights.ttl > 0
        });

        if !path_valid {
            return;
        }

        match self.routes.get(&key) {
            Some(existing_path) => {
                // Only update if:
                // 1. New path is shorter, or
                // 2. Existing path contains expired TTLs, or
                // 3. Existing path contains nodes that can no longer route
                let should_update = new_path.len() < existing_path.len()
                    || existing_path
                        .iter()
                        .any(|grant| grant.rights.ttl == 0 || !grant.rights.can_route);

                if should_update {
                    self.routes.insert(key, new_path);
                }
            }
            None => {
                // New route, just insert it
                self.routes.insert(key, new_path);
            }
        }
    }

    // Find the nearest router
    fn find_nearest_router(&self) -> Option<Vec<Grant>> {
        self.routes
            .iter()
            .filter_map(|(_, path)| {
                // Find the first router in the path that we can reach
                let router_position = path.iter().position(|path_grant| {
                    // Check if this node is a router we can reach
                    self.sig_chain.iter().any(|chain_grant| {
                        chain_grant.key == path_grant.key
                            && chain_grant.rights.can_route
                            && chain_grant.rights.ttl > 0
                    })
                })?;

                // Return the path to this router (including the router)
                Some((router_position, path[..=router_position].to_vec()))
            })
            // Choose the shortest valid path
            .min_by_key(|(pos, _)| *pos)
            .map(|(_, path)| path)
    }

    // Forward content to a destination
    fn forward_content(&mut self, path: Vec<Grant>, content: &[u8]) {
        let packet = Packet {
            body: PacketBody::Content(path, content),
            sig: self.sig_chain.clone(),
        };
        let serialized = packet.serialize();
        let signature = self.sign_packet(&serialized);

        self.transmitter
            .transmit(&[&serialized[..], &signature[..]].concat());
    }

    // Handle content meant for this node
    fn handle_content(&self, content: &[u8]) {
        // Process content meant for this node
    }

    // Handle advertisements from other nodes
    fn handle_advertisement(&mut self, new_grants: Vec<Grant>, _sig: Vec<Grant>) -> bool {
        if !self.verify_chain(&new_grants) {
            return false;
        }

        if let Some(advertiser_grant) = new_grants.last() {
            if advertiser_grant.rights.can_route {
                self.update_routes(advertiser_grant.clone(), new_grants.clone());

                if self.is_router {
                    let packet = Packet {
                        body: PacketBody::Advertisement(new_grants),
                        sig: self.sig_chain.clone(),
                    };
                    self.transmitter.transmit(&packet.serialize());
                }
            }
        }
        true
    }
}

pub trait Transmitter {
    fn transmit(&mut self, bytes: &[u8]);
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use alloc::{sync::Arc, vec::Vec};
//     use core::cell::RefCell;

//     use ring::rand::SystemRandom;
//     use ring::signature::Ed25519KeyPair;

//     // Simple no_std channel implementation
//     struct Sender<T>(Arc<RefCell<Vec<T>>>);
//     struct Receiver<T>(Arc<RefCell<Vec<T>>>);

//     impl<T> Sender<T> {
//         fn send(&self, value: T) {
//             self.0.borrow_mut().push(value);
//         }
//     }

//     impl<T> Receiver<T> {
//         fn try_recv(&self) -> Option<T> {
//             self.0.borrow_mut().pop()
//         }
//     }

//     fn channel<T>() -> (Sender<T>, Receiver<T>) {
//         let buffer = Arc::new(RefCell::new(Vec::new()));
//         (Sender(buffer.clone()), Receiver(buffer))
//     }

//     struct MockTransmitter {
//         tx: Arc<Sender<Vec<u8>>>,
//     }

//     impl Transmitter for MockTransmitter {
//         fn transmit(&mut self, bytes: &[u8]) {
//             self.tx.send(bytes.to_vec());
//         }
//     }

//     fn create_test_network(size: usize) -> Vec<(NetworkNode<MockTransmitter>, Receiver<Vec<u8>>)> {
//         let mut nodes = Vec::new();
//         let rng = SystemRandom::new();

//         for _ in 0..size {
//             // Create communication channel
//             let (tx, rx) = channel();
//             let tx = Arc::new(tx);

//             // Generate keypair
//             let keypair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
//             let keypair = Ed25519KeyPair::from_pkcs8(keypair.as_ref()).unwrap();

//             // Create initial grant
//             let initial_grant = Grant {
//                 key: keypair.public_key().as_ref().to_vec(),
//                 rights: Rights {
//                     can_route: true,
//                     can_manage: true,
//                     can_sublet: true,
//                     ttl: 100,
//                 },
//             };

//             // Create node
//             let transmitter = MockTransmitter { tx };
//             let node = NetworkNode::new(transmitter, keypair, initial_grant, true);

//             nodes.push((node, rx));
//         }

//         nodes
//     }

//     static MESSAGE_COUNTER: AtomicUsize = AtomicUsize::new(0);
//     static ROUTE_COUNTER: AtomicUsize = AtomicUsize::new(0);

//     #[test]
//     fn test_single_node() {
//         let mut nodes = create_test_network(1);
//         let (node, rx) = &mut nodes[0];

//         // Test self-advertisement
//         node.advertise();

//         // Verify advertisement was signed and sent
//         if let Some(data) = rx.try_recv() {
//             let (packet, signature) = Packet::deserialize(&data).expect("Valid packet");
//             assert!(node.verify_signature(&packet.serialize(), signature, &node.sig_chain[0].key));
//         } else {
//             panic!("No advertisement received");
//         }
//     }

//     #[test]
//     fn test_basic_network_formation() {
//         let mut nodes = create_test_network(3);

//         // Have all nodes advertise
//         for (node, _) in nodes.iter_mut() {
//             node.advertise();
//         }

//         // Process advertisements
//         for _ in 0..10 {
//             for (node, rx) in nodes.iter_mut() {
//                 while let Some(data) = rx.try_recv() {
//                     let (packet, signature) = Packet::deserialize(&data).expect("Valid packet");
//                     assert!(node.accept(packet, signature), "Packet should be accepted");
//                 }
//             }
//         }

//         // Verify routing tables
//         for (node, _) in &nodes {
//             assert!(!node.routes.is_empty(), "Node should have routes");

//             // Verify all routes have valid signatures
//             for (dest, path) in &node.routes {
//                 assert!(node.is_path_valid(path), "Route path should be valid");
//                 assert_eq!(
//                     &path.last().unwrap().key,
//                     &dest.key,
//                     "Route should lead to destination"
//                 );
//             }
//         }
//     }

//     #[test]
//     fn test_message_routing() {
//         MESSAGE_COUNTER.store(0, Ordering::SeqCst);
//         let mut nodes = create_test_network(5);

//         // Setup network
//         for (node, _) in nodes.iter_mut() {
//             node.advertise();
//             MESSAGE_COUNTER.fetch_add(1, Ordering::SeqCst);
//         }

//         // Process advertisements with signature verification
//         for round in 0..5 {
//             let mut messages_this_round = 0;
//             for (node, rx) in nodes.iter_mut() {
//                 while let Some(data) = rx.try_recv() {
//                     let (packet, signature) = Packet::deserialize(&data).expect("Valid packet");
//                     if node.accept(packet, signature) {
//                         messages_this_round += 1;
//                         MESSAGE_COUNTER.fetch_add(1, Ordering::SeqCst);
//                     }
//                 }
//             }

//             if messages_this_round == 0 && round < 4 {
//                 panic!(
//                     "Round {}: Processed {} messages",
//                     round,
//                     MESSAGE_COUNTER.load(Ordering::SeqCst)
//                 );
//             }
//         }

//         // Test message sending
//         let content = b"Test message";
//         let dest = nodes[4].0.sig_chain[0].clone();
//         nodes[0].0.send(dest, content);

//         // Verify message receipt with signature
//         let mut message_received = false;
//         for _ in 0..5 {
//             if let Some(data) = nodes[4].1.try_recv() {
//                 let (packet, signature) = Packet::deserialize(&data).expect("Valid packet");
//                 if nodes[4].0.accept(packet.clone(), signature) {
//                     if let PacketBody::Content(_, received_content) = packet.body {
//                         assert_eq!(received_content, content);
//                         message_received = true;
//                         break;
//                     }
//                 }
//             }
//         }
//         assert!(message_received, "Message should be received and verified");
//     }

//     #[test]
//     fn test_invalid_signatures() {
//         let mut nodes = create_test_network(2);

//         // Create packet with invalid signature
//         let packet = Packet {
//             body: PacketBody::Advertisement(nodes[0].0.sig_chain.clone()),
//             sig: nodes[0].0.sig_chain.clone(),
//         };

//         let invalid_signature = vec![0; 64]; // Wrong signature
//         assert!(!nodes[1].0.accept(packet, &invalid_signature));
//     }

//     #[test]
//     fn test_grant_verification() {
//         let mut nodes = create_test_network(2);

//         let invalid_grant = Grant {
//             key: vec![1, 2, 3],
//             rights: Rights {
//                 can_route: true,
//                 can_manage: true,
//                 can_sublet: true,
//                 ttl: 1000,
//             },
//         };

//         let packet = Packet {
//             body: PacketBody::Advertisement(vec![nodes[0].0.sig_chain[0].clone(), invalid_grant]),
//             sig: nodes[0].0.sig_chain.clone(),
//         };

//         // Sign the packet
//         let data = packet.test_serialize_with_signature(&nodes[0].0.keypair);
//         let (packet, signature) = Packet::deserialize(&data).expect("Valid packet");

//         // Should fail due to invalid grant, not signature
//         assert!(!nodes[1].0.accept(packet, signature));
//     }
// }
