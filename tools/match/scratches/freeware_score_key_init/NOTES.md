The 1.3.0 and 1.4.0 originals generate a 243-byte key before loading or saving
a score file. Each initializes the seed register to zero, then negates and
doubles it on every iteration. The seed therefore stays zero, but both native
bodies still evaluate the terms containing it, including the signed remainders
modulo 21 and 5. The source preserves that arithmetic.

The encoder accumulates the weighted checksum of the signed plaintext bytes
before adding the repeating key. The decoder subtracts the key before computing
the same checksum. The final four bytes store the checksum in little-endian
order.
