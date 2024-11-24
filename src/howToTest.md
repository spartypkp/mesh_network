// Two Devices:
// Device A: My Computer
// Device B: Friend's Computer


// Each Device Needs:
// 1. Way to send messages (radio transmitter)
// 2. Uniquye KeyPair Signature
// 3. The Mesh Network code


// Example Usage
// Device A wants to send a message to Device B
// Device A uses mesh network code to:
// 1. Package up the message.
// 2. Sign the message with its own private key.
// 3. Transmit the message to the network.

// Device B Does:
// 1. Receives radio signal
// 2. Uses mesh network code to see if message is for them
// 3. Reads the message if it is.




// To actually use this with two devices:

// First Steps

// Install Rust on both devices
// Copy our mesh network code to both devices
// Connect your radio hardware to both devices


// For Each Device

// Write code to control your radio (the MyRadio part)
// Generate an ID (keypair) for the device
// Share the public part of the ID with the other device
// Run the program


// Testing

// Start the program on both devices
// Try sending a message from one to the other
// Check if the other device receives it



// The hardest part will probably be writing the radio control code, since that depends on what kind of radio hardware you're using. Do you know what kind of radio/communication hardware you'll be using? That would help me give more specific examples!
// Key things to remember:

// Both devices need to be running the program at the same time
// They need to know each other's public keys
// They need to be within radio range
// The radio hardware needs to be properly set up and working