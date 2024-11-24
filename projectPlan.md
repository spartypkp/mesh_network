# USS Hornet Hackathon Project Plan

# Name
We ned a concise and memorable name for our project:
"Daedelus Drone System"

# Description
A 1 sentence description of our project. Non negotiable.
- An autonomous fixed wing drone which flies to target area, drops RF bricks which create a communication mesh network, and drop munitions payloads. 


# Components of the System
1. Deadelus Drone Platform
- Fixed wing drone
- Carries 8-12 Bricks
- Carries 6 Munition Payloads
- Autonomous flight to target area, flight path, loitering
2. Brick
- RF receiver/transmitter
- Network node of the mesh network
- Enables communication between payloads, daedelus and bricks
Passive Abilities:
- Listening to enemy signals in target area?
- Listen for commands or communications from Daedelus/other bricks?
- Store data.
- Convert signal data to targeting data?
- Sleep/power down to save energy?
Active Abilities:
- Transmit data to outside listener? (Home base?)
- Transmit data to other bricks/mesh network?
- Relay incoming signals.
- Act as a jammer? **
- Spoof enemy communications?
- Broadcast fake friendly coummunications?
Autonomous/Sentry Mode:
- Passively listen and gather data.
- Wait for certain trigger conditions. Possibly configurable for different missions.
- When trigger conditions are met by a single brick, it becomes active and carries out the programmed active task. Could "wake up" other bricks to propogate the alert.
- Ex: "Serving as sentry waiting for enemy to pass through target area"
- Ex: "Wait for friendly activation signal to begin jamming enemy communications"
- Ex: "Wait for friendly command to convert SigInt data into targeting coordinates and broadcast to payloads on network"

Payloads (Hornets):
1. Custom munitions delivery vehicles dropped from Daedelus
2. Basic version is like a "glide bomb"
3. Advanced version could contain rocket motor for increased range/advanced manuevers
4. Autonomous targetting and guidance
5. Communicate with mesh network
6. Receive targetting coordinates from bricks
7. Completey customizable munitions
8. Customizable attack direction
- Ex: Top down for tanks, from certain angle, from side, etc.
9. Customize attack mode
-Ex: Direct impact, air burst, delayed detonation, etc.

Smart Payloads (Future):
1. Smarter mini drones with cameras. Can complete more advanced tasks/missions autonomously.
2. Can navigate and make basic decisions on their own.
Ex: "Search the target area for enemies", "What's the unit strength in the target area?", "How many armored vehicles are in the target area?", "Is specific target in the area (ex: MLRS or air defence)"
3. Can communicate with other smart payloads and Daedelus


## Questions About Deadelus
1. What are the dimensions?
2. Can it easily be deconstructed for storage/transport?
3. Is it easy annough to assemble by non-experts quickly? 
- On frontlines?
- Time to assemble?
4. How are the drones launched?
- Neeed flat runway, length? or jump launched?
- num of people needed to launch?
5. How are drones recovered
7. What is the default configuration for the Daedelus?
- ~ 8-12 Bricks?
- ~ 6 munition payloads? (Hornets)
8. What is the maximum range/flight time of the Daedelus?
- Loiter time?
- Max round trip distance?
9. How do we prevent Daedelus from being shot down by ManPads?
- Low flying?
- Auto-evasion?
- EW?

## Questions About Mesh Netwrok of Bricks
1. What is the mechanism for dropping bricks?
2. What is the ideal range-distance between bricks in target area?
3. What size target area can a single Deadelus (~ 8-12 bricks) effectively cover?
4. How does Daedelus attempt even distribution of bricks in target area?
5. What are the passive abilities of the bricks?
- Listening to enemy signals in target area?
- Listen for commands or communications from Daedelus/other bricks?
- Store data.
- Convert signal data to targeting data?
- Sleep/power down to save energy?
6. What are the active abilities of the bricks?
- Transmit data to outside listener? (Home base?)
- Transmit data to other bricks/mesh network?
- Relay incoming signals.
- Act as a jammer? **
- Spoof enemy communications?
- Broadcast fake friendly coummunications?
7. Can there be a "autonomous" or "sentry" mode for bricks?
- Passively listen and gather data.
- Wait for certain trigger conditions. Possibly configurable for different missions.
- When trigger conditions are met by a single brick, it becomes active and carries out the programmed active task. Could "wake up" other bricks to propogate the alert.
- Ex: "Serving as sentry waiting for enemy to pass through target area"
- Ex: "Wait for friendly activation signal to begin jamming enemy communications"
- Ex: "Wait for friendly command to convert SigInt data into targeting coordinates and broadcast to payloads on network"
8. Brick Dimensions?
9. Brick Cost?
10. BRICK BATTERY POWER **** VERY IMPORTANT ****
11. Other brick details?
12. How do we prevent enemy from jamming the bricks from communicating?
- If the enemy decides to completely jam all bricks within the target area there may be little we can do. However, they would have to CONTINUOUSLY jam all bricks within the target area until bricks ran out
- Assuming the target area is in a forward area near enemy positions, in order to jam our network they would have to jam themselves.

## Questions About Payloads