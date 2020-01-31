# ledctl

_A cli/http interface for controlling Magic Home RGB LEDs_


## Usage

`ledctl set-wifi --ip <IP ADDRESS> --ssid <SSID> --password <PASSWORD> --mode <MODE> --algo <ALGO>`

_Instructs the controller to connect to a wifi network_

- IP ADDRESS: the current IP address of your LED controller (usually 10.10.123.3 when connected to its wifi network)
- SSID: the SSID of the wifi network you want the controller to connect to
- PASSWORD: the password for the wifi network you want the controller to connect to
- MODE: the wifi security mode (OPEN|SHARED|WPAPSK)
- ALGO: encryption algorithm used (NONE|WEP|TKIP|AES)

`ledctl set-color --ip <IP ADDRESS> RR GG BB`

_Sets the color of the LEDs_

- IP ADDRESS: the IP address of your LED controller
- RR: hex value of the red channel (00 - FF)
- GG: hex value of the green channel (00 - FF)
- BB: hex value of the blue channel (00 - FF)

`ledctl power-on --ip <IP ADDRESS>`

_Powers on the LED strip_

`ledctl power-off --ip <IP ADDRESS`

_Powers off the LED strip_

`ledctl http --port <PORT>`

_Starts an HTTP server that accepts commands_

- PORT: the port you want to run the HTTP server on
- The API accepts the following requests:
  - GET /power-on
  - GET /power-off
  - GET /set-color?r=RR&b=BB&g=GG