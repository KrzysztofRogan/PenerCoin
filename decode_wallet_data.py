from penercoin_hd import HDWallet

path = "wallet_keystore.json"
password = "supersecret"

path_2 = "wallet_keystore2.json"
password_2 = "notsecret!"

try:
    w = HDWallet.load_keystore(path, password)
    print("Keystore decoded")
    print("Next index:", w.next_index)
    print("Used addresses:", w.used_addresses)

    w = HDWallet.load_keystore(path_2, password_2)
    print("Keystore decoded")
    print("Next index:", w.next_index)
    print("Used addresses:", w.used_addresses)
except Exception as e:
    print("Fail:", e)
