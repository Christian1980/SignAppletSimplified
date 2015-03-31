This applet signs a PDF-document using a certificate on the user's computer.

It is based on the DSS project,
https://joinup.ec.europa.eu/software/sd-dss/home

The cert must be available through CAPI (Windows) or PKCS#11. It's possible to
use MOCCA as well, but that is commented out because its license is suspect.

For compiling, you need DSS 4.2.0 source. The applet runs entirely by itself,
it does not require any backend services.

The applet is designed to have as much as possible of the user interface in
html/javascript. Only popups are generated from Java.

A simple test.html is included for demonstration (note: demo doesn't run in Chrome)
A more complete example can be seen at
https://upload.businessindenmark.dk/SignApplet.aspx?ID=TEST_001



Known issues:
- Java doesn't return the calls from Javascript until the operation is complete.
  This causes Chrome to display "page unresponsive" after 30 seconds.
  Chrome is removing its Java-support entirely in 2015, so there is not much
  reason to fix this.
- Java windows may hide below browser.
- Not all certs are available through an API. Swedish BankID with a file
on the computer isn't; Danish NemID only if email-functionality is installed.


If you find bugs, improvements or questions, please get in touch.

Rune Kock
ID Solutions ApS
rk@idsolutions.dk
