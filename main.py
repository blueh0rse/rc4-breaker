from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
from collections import Counter


def main():
    ###
    # CHANNEL EAVESDROPPING
    ###

    print("=== CHANNEL EAVESDROPPING ===")
    print("* ORIGINAL VALUES *")
    message = get_random_bytes(1)
    key = get_random_bytes(13)
    print(f"[MSG] 0x{message.hex()}")
    print(f"[KEY] 0x{key.hex()}")

    print("* GUESSING PART *")
    # create file, empty it if existing
    cipher_file = "./cs.txt"
    open(cipher_file, "w").close()

    print("[...] Generating all ciphers...")
    # from 01FF00 to 0FFFFF
    for i in range(1, 20):
        beg = format(i, "02X")
        for j in range(256):
            end = format(j, "02X")
            iv = beg + "FF" + end
            # for each iv:
            enc_key = bytes.fromhex(iv) + key
            cipher = ARC4.new(enc_key)
            c = cipher.encrypt(message)
            # store IV and c into file
            with open(cipher_file, "a") as cifile:
                cifile.write(f"{iv} {c.hex()}\n")
    print("[...] Done!")

    ###
    # FACT 1
    ###

    print("=== FACT 1 ===")
    # extract lines starting by 01FF...
    with open(cipher_file, "r") as cifile:
        iv_and_cipher = cifile.readlines()[0:256]
    guesses = []
    for line in iv_and_cipher:
        parts = line.split()
        x = parts[0][-2:]
        c = parts[1]
        # c[0] XOR (x+2)
        result = hex((int(c, 16) ^ (int(x, 16) + 2)) % 256)
        guesses.append(result)
    # find most frequent result
    counts = Counter(guesses).most_common(1)
    msg_guessed = counts[0][0]
    nb_times = counts[0][1]
    print(f"[MSG] Original: 0x{message.hex()}")
    print(f"[MSG] Guessed : {msg_guessed}, found {nb_times} times")

    ###
    # FACT 2
    ###

    print("=== FACT 2 ===")
    # extract lines starting by 03FF...
    with open(cipher_file, "r") as cifile:
        iv_and_cipher = cifile.readlines()[512:768]
    key_guesses = []
    for line in iv_and_cipher:
        parts = line.split()
        x = parts[0][-2:]
        c = parts[1]
        # (c[0] XOR m[0]) - x - 6
        guess = hex(((int(c, 16) ^ int(msg_guessed, 16)) - int(x, 16) - 6) % 256)
        key_guesses.append(guess)
    # find most frequent result
    counts = Counter(key_guesses).most_common(1)
    k0 = counts[0][0]
    nb_times = counts[0][1]
    print(f"[KEY 0] Original: 0x{key.hex()[0:2]}")
    print(f"[KEY 0] Guessed : {k0}, found {nb_times} times")

    # extract lines starting by 04FF...
    with open(cipher_file, "r") as cifile:
        iv_and_cipher = cifile.readlines()[768:1024]
    key_guesses = []
    for line in iv_and_cipher:
        parts = line.split()
        x = parts[0][-2:]
        c = parts[1]
        # (c[0] XOR m[0]) - x - 10 - k[0]
        guess = hex(
            ((int(c, 16) ^ int(msg_guessed, 16)) - int(x, 16) - 10 - int(k0, 16)) % 256
        )
        key_guesses.append(guess)
    # find most frequent result
    counts = Counter(key_guesses).most_common(1)
    k1 = counts[0][0]
    nb_times = counts[0][1]
    print(f"[KEY 1] Original: 0x{key.hex()[2:4]}")
    print(f"[KEY 1] Guessed : {k1}, found {nb_times} times")

    ###
    # FACT 3
    ###

    print("=== FACT 3 ===")
    guessing_key = []
    # from i=0 to i=12
    for i in range(13):
        # compute lines to be extracted
        iv_beg = 256 * (i + 3) - 256
        iv_end = 256 * (i + 3)
        with open(cipher_file, "r") as cifile:
            iv_and_cipher = cifile.readlines()[iv_beg:iv_end]
        key_guesses = []
        for line in iv_and_cipher:
            parts = line.split()
            x = parts[0][-2:]
            c = parts[1]
            d = sum(range(1, i + 4))
            # (c[0] XOR m[0]) - x + d[i] + k[0] + k[1] + ... +k[i]
            result = (
                (int(c, 16) ^ int(msg_guessed, 16))
                - int(x, 16)
                - int(d)
                - sum(int(x, 16) for x in guessing_key[0 : i + 1])
            ) % 256
            key_guesses.append("0x" + hex(result)[2:].zfill(2))
        # find most frequent result
        counts = Counter(key_guesses).most_common(1)
        k = counts[0][0]
        guessing_key.append(k)
        nb_times = counts[0][1]
        print(f"[KEY {i}]: {k}, found {nb_times} times")

    guessed_key = [byte[2:] for byte in guessing_key]
    result = "0x" + "".join(guessed_key)
    print(f"[KEY] Guessed : {result}")
    print(f"[KEY] Original: 0x{key.hex()}")


if __name__ == "__main__":
    main()
