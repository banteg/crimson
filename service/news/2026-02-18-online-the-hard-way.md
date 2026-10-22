# Online, the Hard Way

Co-op in the Python port now works over the internet, not just on a LAN. Someone runs a small relay server, the host shares a room code, and a friend joins with it.

It runs on rollback netcode: each game races ahead on its own input and quietly corrects itself when your friend's arrives, so your aim never waits on the network.

It's for the brave for now, since you have to run the relay yourself. Stay tuned.
