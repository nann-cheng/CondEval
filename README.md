## How to test the protocol?

The protocol run in a setting with four parties.

* A client submitting secret input to the two servers.
* A bank generating offline phase correlated randomness as well as referenced template for authentication.
* Two servers responsible for executing secure computation.

To test the protocol, run  

1. python server.py 0   python server.py 1

2. python bank.py

3. python client.py