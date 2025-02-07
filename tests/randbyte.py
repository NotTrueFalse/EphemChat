import os
import secrets
import hashlib

data = secrets.token_bytes(1024**2*10)

if os.path.exists("random_received.txt"):
    with open("random_received.txt","rb") as file_received:
        with open("random_hash.txt","rb") as file_hash:
            data_received = file_received.read()
            data_hash = file_hash.read()
            if hashlib.sha256(data_received).digest() == data_hash:
                print("File received successfully")
            else:
                print("File received unsuccessfully")
        file_hash.close()
        file_received.close()
else:
    with open("random_hash.txt","wb") as file_hash:
        with open("random.txt","wb") as file:
            file.write(data)
            file_hash.write(hashlib.sha256(data).digest())
            file_hash.close()
            file.close()
    print("File created successfully")