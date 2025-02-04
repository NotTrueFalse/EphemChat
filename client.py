import socket
import os
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from threading import Thread
from hashlib import shake_256
import secrets
from CPRNG import Shake256PRNG
from tkinter import filedialog

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
#change OPCODE OR ID_LENGTH to be more or less stealth
ASK_OPCODE = b"\x15"#don't ask me why I choose 15, you can configure it to be anything (btw 01 - ff)
ACCEPT_OPCODE = b"\x16"
# SEND_OPCODE = b"\x17"
# SENDING_OPCODE = b"\x18"
ADDRESS_LENGTH = 10#10^63-9^63 => 9.9868998e+62  possibilities ((9.9868998e+62 )/(1000*60*60*24*365.24) => 3.1647442e+52 years to test all possibilities if we go at 1 adderss per ms)
#this is just for security, you can get it higher but if you choose to lower it will be easier to bruteforce (not recommended)
MAIN_KEY_LENGTH = 32
#used to find your partner: OTV (One Time Verifier added randomly to the message)
ONE_TIME_LENGTH = 32
# MAX_FILE_SIZE = 1024**3*4#4GB max accepted file size

# def to_humain_readable(size:int)->str:
#     for unit in ['Octets', 'Ko', 'Mo', 'Go', 'To']:
#         if size < 1024.0:
#             break
#         size /= 1024.0
#     return f"{size:.2f} {unit}"

class Client:
    def __init__(self):
        self.address = {}#{address:seed} to only use once to generate a contact
        self.contacts = {}#{address:main_key} to use to send messages
        self.send_queue = {}#{address:filename} to send files
        self.receive_queue = {}#{address:filename} to receive files

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
        bytes = secrets.token_bytes(length)
        allowed = (48,57),(64,64+26),(97,97+25)#0-9,A-Z,a-z+@
        allowed = [list(range(i,j+1)) for i,j in allowed]
        allowed = [chr(i) for i in sum(allowed,[])]
        address = ""
        for byte in bytes:
            address += allowed[byte%len(allowed)]
        return address

    # AES Encryption
    def aes_encrypt(self, plaintext: bytes, password: bytes, random_iterator:Shake256PRNG)->bytes:
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
    def aes_decrypt(self, ciphertext: bytes, password: bytes, random_iterator:Shake256PRNG) -> bytes:
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

    def ask(self,data:bytes,offset:int):
        #0:1 -> OPCODE
        #1:11 -> TO ADDRESS
        #11:21 -> FROM CONTACT ADDRESS
        #21:53 -> MAIN KEY
        to_addr = data[offset:offset+ADDRESS_LENGTH]
        to_addr = to_addr.decode("utf-8")
        if to_addr in self.address:
            #its me :D
            offset += ADDRESS_LENGTH
            contact = data[offset:offset+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)]#to match the required length of AES that is %16 == 0
            null_iterator = Shake256PRNG(b"\x00")
            contact = self.aes_decrypt(contact, self.address[to_addr]["seed"],null_iterator)
            contact = contact.decode("utf-8")
            offset += ADDRESS_LENGTH+(16%ADDRESS_LENGTH)
            main_key = data[offset:offset+MAIN_KEY_LENGTH+(16%MAIN_KEY_LENGTH)]#match requirements
            null_iterator = Shake256PRNG(b"\x00")
            main_key = self.aes_decrypt(main_key, self.address[to_addr]["seed"],null_iterator)#don't decode its mainly random bytes
            r = Shake256PRNG(main_key,debug=True)
            self.contacts[contact] = {"main_key":main_key,"random_iterator":r}
            print(f"\n[+] You have a new contact: {contact}")
            # print(f"main_key: {main_key}")#debug
            #now send accept message
            #0:1 -> OPCODE
            #1:11 -> MY CONTACT ADDRESS
            #11:43 -> VERIFIER (hash of the main key)
            contact_address = self.generate_address()
            null_iterator = Shake256PRNG(b"\x00")
            contact_address = self.aes_encrypt(contact_address, main_key,null_iterator)
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
            del self.address[to_addr]#remove the address from the list (its used only once)

    def verify(self,data:bytes,offset:int):
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
            try:
                if ph.verify(verifier,p):
                    print(f"\n[*] verfied a contact")
                    break
            except:pass#verify naturaly return an exception
        else:
            #can happen when two random personne try to match
            #print(f"\n[-] Couldn't verify the contact ({verifier})")
            return
        contact = data[offset:offset+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)]
        null_iterator = Shake256PRNG(b"\x00")
        contact = self.aes_decrypt(contact, p, null_iterator).decode("utf-8")#replace random contact with the real one
        self.contacts[contact] = self.contacts[contact_address].copy()
        del self.contacts[contact_address]#remove the random contact
        print(f"[+] You have a new contact: {contact}")

    def check_received(self,contact:str,data:bytes):
            """from a decrypted message check if the message is a request or a message"""
        # offset = 1
        #0:1 -> OPCODE
        #1:9 -> FILE SIZE
        #9: -> FILE NAME
        # if data[0:offset] == SEND_OPCODE:
        #     #user sent a file
        #     file_size = int.from_bytes(data[offset:offset+8], "big")
        #     offset += 8
        #     file_name = data[offset:].decode("utf-8")
        #     print(f"\n[+] You received a file: {file_name} ({to_humain_readable(file_size)})")
        #     accept = input("Do you want to accept the file? (y/n): ").lower() == "y"
        #     if accept:
        #         main_key = self.contacts[contact]["main_key"]
        #         r = self.contacts[contact]["random_iterator"]
        #         payload = self.aes_encrypt(ACCEPT_OPCODE, main_key, r)
        #         payload = self.add_one_time(payload,r)
        #         self.client.sendall(payload)
        #         self.receive_queue[contact] = filedialog.asksaveasfilename(defaultextension=os.path.splitext(file_name)[1],initialfile=file_name)
        # elif data[0:offset] == ACCEPT_OPCODE and contact in self.send_queue:
            #user accepted the file
            # file_path = self.send_queue[contact]
            # file_name = os.path.basename(file_path)
            # file_size = os.path.getsize(file_path)
            # if file_size > MAX_FILE_SIZE:
            #     print(f"[-] File size too big ({to_humain_readable(file_size)})")
            #     return
            # print(f"[*] Sending file: {file_name} ({to_humain_readable(file_size)})")
            # with open(file_path, "rb") as f:
            #     while True:
            #         chunk = f.read(4096-ONE_TIME_LENGTH-1)#-1 for the opcode, -ONE_TIME_LENGTH for the OTV
            #         if not chunk:
            #             break
            #         main_key = self.contacts[contact]["main_key"]
            #         r = self.contacts[contact]["random_iterator"]
            #         payload = self.aes_encrypt(SENDING_OPCODE + chunk, main_key, r)
            #         payload = self.add_one_time(payload,r)
            #         self.client.sendall(payload)
            # print(f"[+] File sent: {file_name}")
            # del self.send_queue[contact]
        # elif data[0:offset] == SENDING_OPCODE:
        #     #user is sending a file
        #     file_name = self.receive_queue[contact]
        #     with open(file_name, "ab") as f:
        #         f.write(data[offset:])
        #     print(f"[*] Receiving file: {file_name}",end="\r")
        # else:
            print(f"\n{contact}: {data.decode('utf-8')}")

    # Client handler to receive messages
    def listen_packets(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((SERVER_HOST, SERVER_PORT))
        while True:
            # try:
                data = self.client.recv(4096)
                if not data:continue
                offset = 1
                if data[0:offset] == ASK_OPCODE:
                    self.ask(data,offset)
                elif data[0:offset] == ACCEPT_OPCODE:
                    self.verify(data,offset)
                else:
                    #check if the message come from a contact
                    #here there are no deterministic pattern for the message so we need to check for all contact the OTV
                    for contact in self.contacts:
                        contact_random_iterator = self.contacts[contact]["random_iterator"]#use the random iterator of the contact
                        contact_random_iterator_state = contact_random_iterator.get_state()#save the state of the random iterator to decrypt the message
                        contact_random_iterator.randbytes(32)#simulate the random iterator to get the same state as the sender
                        OTcheck = self.check_one_time(data,contact_random_iterator)
                        if OTcheck:
                            contact_random_iterator.set_state(contact_random_iterator_state)#restore the state of the random iterator
                            message = self.aes_decrypt(OTcheck, self.contacts[contact]["main_key"], contact_random_iterator)
                            for i in range(2):contact_random_iterator.randbytes(32)#use two credit of the random iterator
                            self.check_received(contact,message)
                            break
                        else:
                            self.contacts[contact]["random_iterator"].set_state(contact_random_iterator_state)#restore the state of the random iterator
                    
                            # print("[-] Block not from a contact")
            # except Exception as e:
            #     print(f"Error receiving message: {e}")
            #     break

    def add_contact(self,address:str,seed:str):
        me_contact = self.generate_address()
        null_iterator = Shake256PRNG(b"\x00")
        me_contact = self.aes_encrypt(me_contact, seed, null_iterator)
        main_key = os.urandom(MAIN_KEY_LENGTH)
        # print(f"main_key: {main_key}")#debug
        idk_contact = self.generate_address()
        r = Shake256PRNG(main_key,debug=True)
        self.contacts[idk_contact] = {"main_key":main_key,"random_iterator":r}#temporarly save a random contact instead of the real one
        null_iterator = Shake256PRNG(b"\x00")
        main_key = self.aes_encrypt(main_key, seed, null_iterator)
        payload = ASK_OPCODE + address.encode("utf-8") + me_contact + main_key
        self.client.sendall(payload)

    def send_message(self, contact: str, message: str):
        main_key = self.contacts[contact]["main_key"]
        r = self.contacts[contact]["random_iterator"]
        message = self.aes_encrypt(message, main_key, r)#use one credit of the random iterator
        message = self.add_one_time(message,r)#use two credit of the random iterator
        self.client.sendall(message)

    def _get_contact(self)->str:
        if len(self.contacts) == 0:
            print("[-] You don't have any savec contact")
            return
        for (i,address) in enumerate(self.contacts.keys()):
            print(f"{i}. {address}")
        contact = input("Enter contact n°: ")
        try:
            contact = int(contact)
        except ValueError:
            print("[-] Invalid contact")
            return
        if contact < 0 or contact >= len(self.contacts):
            print("[-] Invalid contact")
            return
        contact = list(self.contacts.keys())[contact]
        return contact

    # Main client function
    def main(self):
        global SERVER_HOST, SERVER_PORT, ADDRESS_LENGTH, MAIN_KEY_LENGTH
        # Generate 10 random addresses
        for i in range(10):
            addr,seed = self.generate_address(),self.generate_address()
            self.address[addr] = {"seed":seed}
        del addr,seed#prevent missuse
        print("Welcome to the chat client!")
        Thread(target=self.listen_packets, daemon=True).start()

        options = ("List addresses", "add contact" ,"chat","exit")#, "file", "Exit")
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
                    print("[-] You can't add yourself as a contact")
                    continue
                self.add_contact(address,seed)
            elif choice == "3":
                contact = self._get_contact()
                if not contact:continue   
                message = input("Enter your message: ")
                self.send_message(contact, message)
            elif choice == "4":
                self.client.close()
                exit()
                #will be implemented in the next update (GUI)
                # contact = self._get_contact()
                # if not contact:continue
                # file_path = filedialog.askopenfilename()
                # file_name = os.path.basename(file_path)#max filename => 4096 - 9 = 4087 - otv (ONE_TIME_LENGTH) = 4055
                # file_size = os.path.getsize(file_path)
                # main_key = self.contacts[contact]["main_key"]
                # r = self.contacts[contact]["random_iterator"]
                # payload = SEND_OPCODE + file_size.to_bytes(8, "big") + file_name.encode("utf-8")
                # payload = self.aes_encrypt(payload, main_key, r)
                # payload = self.add_one_time(payload,r)
                # self.client.sendall(payload)
                # self.send_queue[contact] = file_path
                # print(f"[+] file added to queue, will send when accepted")
            # elif choice == "5":
            #     self.client.close()
            #     exit()
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