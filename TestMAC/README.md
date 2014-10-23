# TestMAC

This Java Card applet support APDUs to test HMAC and CMAC. 
It uses Java Card 2.2.2.

## Supported APDU Commands
Supported commands (<b>CLA INS</b>):
<ul>
<li><b>00 A4</b>: Select [00 A4 04 00 AidLength Aid 10 00, Aid=A0 FF FF FF FF 10 10]
<li><b>80 10</b>: Set HMAC Key [80 10 HashFunction 00 KeyLength Key; HashFunction: 0x01=SHA-1, 0x02=SHA-256]
<li><b>80 12</b>: Generate HMAC [80 12 00 00 MsgLength Msg 00]
<li><b>80 20</b>: Set CMAC Key [80 20 00 00 KeyLength Key]
<li><b>80 22</b>: Generate CMAC [80 22 00 00 MsgLength Msg 00]
</ul>

## Testing
TestResults.txt contains script traces of test results.
Provided test scripts:
<ul>
<li><b>PrepareApplet.jcsh</b>: Script to load and install test applet.
<li><b>TestCmac_1.jcsh</b>: Script to test CMAC.
<li><b>TestHmacSha_1.jcsh</b>: Script to test SHA-1 HMAC.
<li><b>TestHmacSha_2.jcsh</b>: Script to test SHA-1 HMAC.
<li><b>TestHmacSha_3.jcsh</b>: Script to test SHA-1 HMAC.
<li><b>TestHmacSha256_1.jcsh</b>: Script to test SHA-256 HMAC.
<li><b>TestHmacSha256_2.jcsh</b>: Script to test SHA-256 HMAC.
<li><b>TestHmacSha256_3.jcsh</b>: Script to test SHA-256 HMAC.
</ul>
