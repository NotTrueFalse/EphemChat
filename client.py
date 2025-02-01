import socket
import os
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from threading import Thread
from hashlib import shake_256
import secrets
from CPRNG import Shake256PRNG

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
#change OPCODE OR ID_LENGTH to be more or less stealth
ASK_OPCODE = b"\x15"
ACCEPT_OPCODE = b"\x16"
ADDRESS_LENGTH = 16#16^16-16^15 => 1.7293823x10^19 possibilities ((1.7293823x10^19)/(1000*60*60*24*365.24) => 548023185 years to test all possibilities if we go at 1 adderss per ms)
#this is just for security, you can get it higher but if you choose to lower it will be easier to bruteforce (not recommended)
MAIN_KEY_LENGTH = 32
#used to find your partner: OTV (One Time Verifier added randomly to the message)
ONE_TIME_LENGTH = 32
class Client:
    def __init__(self):
        self.address = {}#{address:seed} to only use once to generate a contact
        self.contacts = {}#{address:main_key} to use to send messages
        self.main()

    def iv_generator(self, random_iterator: Shake256PRNG) -> bytes:
        global MAIN_KEY_LENGTH
        """Generate a random IV from a seed (main_key)
        Args:
            random_iterator (Shake256PRNG): The random iterator used to generate the IV.
        Returns:
            bytes: The IV

        Works by XORing the message number with the main key, then hashing the result with SHAKE-256.
        Why: The IV is unpredictable to an attacker who doesn't know the main key.
        """
        iv = shake_256(random_iterator.randbytes(MAIN_KEY_LENGTH)).digest(16)
        return iv

    def add_one_time(self,ciphertext:bytes,r:Shake256PRNG)-> bytes:
        """
        Adds a one-time verifier (OTV) to the ciphertext at random positions.
        Uses two random credits:
        1. To generate the OTV.
        2. To shuffle the insertion positions.
        """
        if not ciphertext:
            raise ValueError("Ciphertext cannot be empty.")
        OT_verifier = r.randbytes(ONE_TIME_LENGTH)
        #sub random iterator to prevent using idk much credit
        r_for_place = Shake256PRNG(r.randbytes(32))#use a new random iterator to shuffle the indexes

        indexes = list(range(len(ciphertext) + ONE_TIME_LENGTH))  # Account for added bytes
        r_for_place.shuffle(indexes)

        # Embed the OTV into the ciphertext at random positions
        combined = bytearray(len(ciphertext) + ONE_TIME_LENGTH)
        ciphertext_idx, otv_idx = 0, 0

    #randomly place OTV & ciphertext in the combined array
        for i in indexes:
            if otv_idx < ONE_TIME_LENGTH:
                combined[i] = OT_verifier[otv_idx]
                otv_idx += 1
            elif ciphertext_idx < len(ciphertext):
                combined[i] = ciphertext[ciphertext_idx]
                ciphertext_idx += 1
        return bytes(combined)

    def check_one_time(self,ciphertext:bytes, r:Shake256PRNG)-> bytes:
        """
        Verifies the one-time verifier (OTV) in the modified ciphertext.
        """
        OT_verifier = r.randbytes(ONE_TIME_LENGTH)
        OT_verifier_copy = b"" + OT_verifier
        r_for_place = Shake256PRNG(r.randbytes(32))#use a new random iterator to shuffle the indexes
        indexes = list(range(len(ciphertext)))  #Already Account for added bytes don't need to add ONE_TIME_LENGTH
        r_for_place.shuffle(indexes)

        exctracted_OTV = bytearray(ONE_TIME_LENGTH)
        extracted_ciphertext = bytearray(len(ciphertext) - ONE_TIME_LENGTH)
        ciphertext_idx, otv_idx = 0, 0

        for i in indexes:
            if otv_idx < ONE_TIME_LENGTH:
                exctracted_OTV[otv_idx] = ciphertext[i]
                otv_idx += 1
            elif ciphertext_idx < len(ciphertext):
                extracted_ciphertext[ciphertext_idx] = ciphertext[i]
                ciphertext_idx += 1
        if exctracted_OTV == OT_verifier_copy:
            return extracted_ciphertext
        return False


    def generate_address(self,length:int=ADDRESS_LENGTH)->str:
        return secrets.token_hex(length//2)

    # AES Encryption
    def aes_encrypt(self, plaintext: bytes, password: bytes, random_iterator:Shake256PRNG=Shake256PRNG(b"\x00"))->bytes:
        """
        Encrypts the given plaintext using AES encryption with the provided password.

        Args:
            plaintext (bytes): The data to be encrypted. If a string is provided, it will be encoded to bytes using UTF-8.
            password (bytes): The password used for encryption. If a string is provided, it will be encoded to bytes using UTF-8.
                              The password must be 32 bytes long. If it is not, it will be hashed using SHAKE-256 to generate a 16-byte key.
            random_iterator (Shake256PRNG): The random iterator used to generate the initialization vector (IV). Default is a new random iterator seeded with 0.
        Returns:
            bytes: The encrypted ciphertext.
        Raises:
            ValueError: If the password length is not 32 bytes and cannot be hashed to the required length.
        Notes:
            - The plaintext is padded with null bytes to ensure its length is a multiple of 16 bytes.
            - The initialization vector (IV) is generated using the `iv_generator` method, which is assumed to be defined elsewhere in the class.
            - The AES encryption is performed in CBC mode.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if len(password) != 32:
            password = shake_256(password).digest(16)
        if len(plaintext) % 16 != 0:
            plaintext += b"\x00" * (16 - len(plaintext) % 16)
        iv = self.iv_generator(random_iterator)
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    # AES Decryption
    def aes_decrypt(self, ciphertext: bytes, password: bytes, random_iterator:Shake256PRNG=Shake256PRNG(b"\x00")) -> bytes:
        if isinstance(password, str):
            password = password.encode("utf-8")
        if len(password) != 32:
            password = shake_256(password).digest(16)
        iv = self.iv_generator(random_iterator)
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        #remove trailing null bytes
        plaintext = plaintext.rstrip(b"\x00")
        return plaintext

    # Client handler to receive messages
    def listen_for_messages(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((SERVER_HOST, SERVER_PORT))
        while True:
            try:
                data = self.client.recv(4096)
                if not data:
                    break
                offset = 1
                #0:1 -> OPCODE
                #1:11 -> TO ADDRESS
                #11:21 -> FROM CONTACT ADDRESS
                #21:53 -> MAIN KEY
                if data[0:offset] == ASK_OPCODE:
                    to_addr = data[offset:offset+ADDRESS_LENGTH]
                    to_addr = to_addr.decode("utf-8")
                    if to_addr in self.address:
                        #its me :D
                        offset += ADDRESS_LENGTH
                        contact = data[offset:offset+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)]#to match the required length of AES that is %16 == 0
                        contact = self.aes_decrypt(contact, self.address[to_addr]["seed"])
                        contact = contact.decode("utf-8")
                        offset += ADDRESS_LENGTH+(16%ADDRESS_LENGTH)
                        main_key = data[offset:offset+MAIN_KEY_LENGTH+(16%MAIN_KEY_LENGTH)]#match requirements
                        main_key = self.aes_decrypt(main_key, self.address[to_addr]["seed"])#don't decode its mainly random bytes
                        r = Shake256PRNG(main_key,debug=True)
                        self.contacts[contact] = {"main_key":main_key,"random_iterator":r}
                        print(f"\n[+] You have a new contact: {contact}")
                        # print(f"main_key: {main_key}")#debug
                        #now send accept message
                        #0:1 -> OPCODE
                        #1:11 -> MY CONTACT ADDRESS
                        #11:43 -> VERIFIER (hash of the main key)
                        contact_address = self.generate_address()
                        contact_address = self.aes_encrypt(contact_address, main_key)
                        ph = PasswordHasher(
                            time_cost=2,
                            memory_cost=2**17,
                            parallelism=2,
                        )
                        #cut the main key in half and hash it
                        verifier = ph.hash(main_key)
                        verifier = "$".join(verifier.split("p=")[1].split("$")[1:]).encode("utf-8")#remove indication of how the hash was made
                        payload = ACCEPT_OPCODE + verifier + contact_address
                        self.client.sendall(payload)
                        del self.address[to_addr]#remove the address from the list
                elif data[0:offset] == ACCEPT_OPCODE:
                    #0:32 -> VERIFIER
                    #32:42 -> CONTACT ADDRESS
                    verifier = data[offset:offset+MAIN_KEY_LENGTH*2+2]
                    verifier = "$argon2id$v=19$m=131072,t=2,p=2$" + verifier.decode("utf-8")
                    ph = PasswordHasher(
                        time_cost=2,
                        memory_cost=2**17,
                        parallelism=2
                    )
                    offset += MAIN_KEY_LENGTH*2+2
                    #find the key that matches the verifier
                    for contact_address in self.contacts:
                        p = self.contacts[contact_address]["main_key"]
                        if ph.verify(verifier,p):
                            print(f"\n[*] verfied a contact")
                            break
                    else:
                        print(f"\n[-] Couldn't verify the contact ({verifier})")
                        continue
                    contact = data[offset:offset+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)]
                    contact = self.aes_decrypt(contact, p).decode("utf-8")#replace random contact with the real one
                    self.contacts[contact] = self.contacts[contact_address].copy()
                    del self.contacts[contact_address]#remove the random contact
                    print(f"[+] You have a new contact: {contact}")
                else:
                    #check if the message come from a contact
                    #here there are no deterministic pattern for the message so we need to check for all contact the OTV
                    for contact in self.contacts:
                        r = self.contacts[contact]["random_iterator"]#use the random iterator of the contact
                        r_state = r.get_state()#save the state of the random iterator to decrypt the message
                        # print(f"snap before simulate: {r_state.hex()}")#debug
                        r.randbytes(32)#simulate the random iterator to get the same state as the sender
                        # print(f"snap after simulate: {r.get_state().hex()}")#debug
                        data = self.check_one_time(data,r)
                        # print(f"snap after check_one_time: {r.get_state().hex()}")#debug
                        if data:
                            r.set_state(r_state)#restore the state of the random iterator
                            message = self.aes_decrypt(data, self.contacts[contact]["main_key"], r)
                            for i in range(2):r.randbytes(32)#use two credit of the random iterator
                            print(f"{contact}: {message.decode('utf-8', errors='ignore')}")
                            break
                        else:
                            self.contacts[contact]["random_iterator"].set_state(r_state)#restore the state of the random iterator
                            print("[-] Block not from a contact")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    # Main client function
    def main(self):
        global SERVER_HOST, SERVER_PORT, ADDRESS_LENGTH, MAIN_KEY_LENGTH

        pseudo_main_key = os.urandom(MAIN_KEY_LENGTH)
        self.test = {
            "rnd":Shake256PRNG(pseudo_main_key),
            "main_key":pseudo_main_key
        }
        # Generate 10 random addresses
        for i in range(10):
            addr,seed = self.generate_address(),self.generate_address()
            self.address[addr] = {"seed":seed}
        del addr,seed#prevent missuse
        print("Welcome to the chat client!")
        Thread(target=self.listen_for_messages, daemon=True).start()

        options = ("List addresses", "add contact" ,"chat", "test", "Exit")
        while True:
            print("Options:")
            for i, option in enumerate(options):
                print(f" {i+1}. {option}")
            choice = input("Enter your choice: ")
            if choice == "1":
                print("Addresses | Seeds:")
                for addr, item in self.address.items():
                    print(f" - {addr}|{item['seed']}")
            elif choice == "2":
                address,seed = input("Enter address|seed of the recipient: ").split("|")
                if address in self.address and seed == self.address[address]:
                    print("[-] You can't send messages to yourself!")
                    continue
                me_contact = self.generate_address()
                print(f"me_contact: {me_contact}")
                me_contact = self.aes_encrypt(me_contact, seed)
                main_key = os.urandom(MAIN_KEY_LENGTH)
                # print(f"main_key: {main_key}")#debug
                idk_contact = self.generate_address()
                r = Shake256PRNG(main_key,debug=True)
                self.contacts[idk_contact] = {"main_key":main_key,"random_iterator":r}#temporarly save a random contact instead of the real one
                main_key = self.aes_encrypt(main_key, seed)
                payload = ASK_OPCODE + address.encode("utf-8") + me_contact + main_key
                self.client.sendall(payload)
            elif choice == "3":
            # Send messages
                if len(self.contacts) == 0:
                    print("[-] You don't have any savec contact")
                    continue
                for (i,address) in enumerate(self.contacts.keys()):
                    print(f"{i}. {address}")
                contact = input("Enter contact n°: ")
                try:
                    contact = int(contact)
                except ValueError:
                    print("[-] Invalid contact")
                    continue
                if contact < 0 or contact >= len(self.contacts):
                    print("[-] Invalid contact")
                    continue
                contact = list(self.contacts.keys())[contact]
                message = input("Enter your message: ")
                main_key = self.contacts[contact]["main_key"]
                r = self.contacts[contact]["random_iterator"]
                message = self.aes_encrypt(message, main_key, r)#use one credit of the random iterator
                message = self.add_one_time(message,r)#use two credit of the random iterator
                self.client.sendall(message)
            elif choice == "4":
                # create a test message, encrypt it, add OTV, remove OTV, decrypt it
                message = "This is a test message."
                r = self.test["rnd"]
                for i in range(2):
                    saved_state = r.get_state()#save the state of the random iterator
                    print(f"SNAP START {saved_state.hex()}")
                    ciphertext = self.aes_encrypt(message, self.test["main_key"], r)
                    print(f"SNAP ENCRYPT {r.get_state().hex()}")
                    ciphertext = self.add_one_time(ciphertext, r)
                    print(f"SNAP ONE TIME {r.get_state().hex()}")
                    print(f"Encrypted message: {ciphertext.hex()}")#should print the ciphertext
                    r.set_state(saved_state)#restore the state of the random iterator
                    print(f"SNAP RESET1 {r.get_state().hex()}")
                    self.aes_encrypt(message, self.test["main_key"], r)
                    print(f"SNAP SIMULATE1 {r.get_state().hex()}")
                    ciphertext = self.check_one_time(ciphertext, r)
                    print(f"SNAP ONE TIME2 {r.get_state().hex()}")
                    if ciphertext:
                        r.set_state(saved_state)#restore the state of the random iterator
                        print(f"SNAP RESET2 {r.get_state().hex()}")
                        decrypted = self.aes_decrypt(ciphertext, self.test["main_key"], r)
                        print(f"SNAP DECRYPT {r.get_state().hex()}")
                        for i in range(2):r.randbytes(32)#use two credit of the random iterator
                        print(f"SNAP SIMULATE2 {r.get_state().hex()}")
                        print(f"Decrypted message: {decrypted.decode('utf-8')}")#should print the message
                    else:
                        print("[-] Error in the OTV check <- something is wrong")
            elif choice == "5":
                self.client.close()
                exit()
            else:
                print("Invalid choice")
            input("Press Enter to continue...")
            os.system("cls" if os.name == "nt" else "clear")


if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    client = Client()
    client.main()

    #NEXT UPDATE: (to have deterministic addresses)
    # password = input("Enter your password: ")
    # pin = input("Enter your PIN: ")
    # self.derive_password(password, pin)
    # del password, pin

    # def derive_password(self, password: str, pin:str):
    #     """Generate a final key from a password and a PIN"""
    #     pin = ()shake_256.update(pin).dig.digest(16)est(16)
    #     ph = PasswordHasher(
    #         time_cost=2,
    #         memory_cost=2**17,
    #         parallelism=2,
    #         hash_len=32,
    #         salt_len=len(pin),
    #     )
    #     hashed_password = ph.hash(password,salt=pin)
    #     self.final_key = hashed_password.encode()