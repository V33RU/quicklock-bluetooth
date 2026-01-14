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
