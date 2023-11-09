from collections import Counter


def main():
    cipher_file = "./prof_ciphertexts.txt"

    with open(cipher_file, "r") as cifile:
        iv_and_cipher = cifile.readlines()[0:256]
    guesses = []
    for line in iv_and_cipher:
        parts = line.split()
        ivx = parts[0][-2:]
        ciphertext = parts[1]
        result_hex = hex((int(ciphertext, 16) ^ (int(ivx, 16) + 2)) % 256)
        guesses.append(result_hex)
    counts = Counter(guesses).most_common(1)
    msg_guessed = counts[0][0]
    nb_msg = counts[0][1]

    guessing_key = []

    for i in range(13):
        iv_beg = 256 * (i + 3) - 256
        iv_end = 256 * (i + 3)
        with open(cipher_file, "r") as cifile:
            iv_and_cipher = cifile.readlines()[iv_beg:iv_end]
        key_guesses = []
        for line in iv_and_cipher:
            parts = line.split()
            ivx = parts[0][-2:]
            ciphertext = parts[1]
            d = sum(range(1, i + 4))
            # (c[0] XOR m[0]) - x + d[i] + k[0] + k[1] + ... +k[i]
            result = (
                (int(ciphertext, 16) ^ int(msg_guessed, 16))
                - int(ivx, 16)
                - int(d)
                - sum(int(x, 16) for x in guessing_key[0 : i + 1])
            ) % 256
            key_guesses.append("0x" + hex(result)[2:].zfill(2))
        counts = Counter(key_guesses).most_common(1)
        k = counts[0][0]
        guessing_key.append(k)
    guessed_key = [byte[2:] for byte in guessing_key]
    result = "0x" + "".join(guessed_key)
    print(f"I think the key is: {result}")
    print(f"I think the msg is: {msg_guessed}, found {nb_msg} times")


if __name__ == "__main__":
    main()
