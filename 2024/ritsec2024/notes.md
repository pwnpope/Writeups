# HACKING SDS Protocol


1.3 Security Access ($22)

- Security Access Service is used to request security challenge token and solve security
challenge. Unlocking security access allows for `Device_Control` mode to be enabled.

1.3.1 Security Key Algorithm

The security key shall be derived from the security seed using an internal cryptographic algorithm. 
The 5-Byte seed/key algorithm is only known to the Original Vehicle Manufacturer, ensuring that only 
properly authorized parties can unlock an ECU.

1.8 Transfer Data ($27)

- The TransferData Service is used to send bytes to an ECU at a specified address. 
- The subfunction DownloadAndExecute ($80) can be used to execute the bytes sent. DeviceControl session is required

==================================================================================================

- The ECU ID for the ECM is 7E0
- The ECU ID for the BCM is 7C0 . The BCM only supports the ReadDIDByID($24) message 

- BCM = body control module
- ecm = engine control module
==================================================================================================

Section      Start       End
ROM:       0x60010000 0x61000000
PROTECTED: 0x61000000 0x62000000
RAM:       0x70000000 0x71000000
