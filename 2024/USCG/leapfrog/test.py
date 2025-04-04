def decrypt(cipher):
    print("The decryption uses the fact that the first 12bit of the plaintext (the fwd pointer) is known,")
    print("because of the 12bit sliding.")
    print("And the key, the ASLR value, is the same with the leading bits of the plaintext (the fwd pointer)")
    key = 0
    plain = 0

    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
        print(f"round {i}:")
        print(f"key:    {key:016x}")
        print(f"plain:  {plain:016x}")
        print(f"cipher: {cipher:016x}\n")

    return plain

decrypt(0x7ff9a0d67b24)
