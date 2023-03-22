The emulated relays are capable of publishing GOOSE messages with TRIP and CLOSE payloads.Hence names goose_publisher.
The GOOSE pattern will be the current state will be published every T0 (2000milli sec). When it receives SV message indicating a new event. It increasing state number and  publishes the event immediately or with delay indicated in SV payload. This repeats after T1(500milli sec) with increasing sequence number. The repeation interval doubles until it hits T0. 


The SV messages are dummy messages sent by gen event program. To generate simple close the command is "s 0", while trip is "s 1". To generate byzantine behaviour "b delay1 t/c_1 dleay_2 t/c_2 delay_3 t/c_3 delay_4 t/c_4". If we want any relay to be silent make payload other than t/c. t is 1 , c is 0.
