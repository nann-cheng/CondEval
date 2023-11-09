This is a fast proto-type implementation of the protocol in the paper *Privacy-preserving Cosine Similarity Computation with Malicious Security Applied to Biometric Authentication*.

## Offline phase

We have the bank distribute secret sharing of the required correlated randomness in the offline phase, which happens before online authentication, generate correlated randomness data written to data/offline.pk0 and data/offline.pk1.

`python3 dealer.py`

## Online phase

The protocol run in a setting with four parties.

* A client submitting secret input to the two servers.
* A bank generating offline phase correlated randomness as well as referenced template for authentication.
* Two servers responsible for executing secure computation.

To test the protocol, sequentially run   

`python server.py 0`   `python server.py 1`

<!-- 2. python bank.py
3. python client.py -->