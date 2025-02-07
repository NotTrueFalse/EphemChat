import socket
import os
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from threading import Thread
from hashlib import shake_256
import secrets
from CPRNG import Shake256PRNG
import re
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
ADDRESS_LENGTH = 10#10^63-9^63 => 9.9868998e+62  possibilities ((9.9868998e+62 )/(1000*60*60*24*365.24) => 3.1647442e+52 years to test all possibilities if we go at 1 adderss per ms)
#this is just for security, you can get it higher but if you choose to lower it will be easier to bruteforce (not recommended)
MAIN_KEY_LENGTH = 32
#used to find your partner: OTV (One Time Verifier added randomly to the message)
ONE_TIME_LENGTH = 32

OK_OPCODE = b"\x01"
ASK_OPCODE = b"\x15"#don't ask me why I choose 15, you can configure it to be anything (btw 01 - ff)
ACCEPT_OPCODE = b"\x16"
SEND_OPCODE = b"\x17"
SENDING_OPCODE = b"\x18"
MAX_FILE_SIZE = 1024**3*4#4GB max accepted file size
DEBUG = 0
def to_humain_readable(size:int)->str:
    for unit in ['Octets', 'Ko', 'Mo', 'Go', 'To']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"

class Client:
    def __init__(self, ip:str=SERVER_HOST, port:int=SERVER_PORT):
        self.ip = ip
        self.port = port
        self.address = {}#{address:seed} to only use once to generate a contact
        self.contacts = {}#{address:main_key} to use to send messages
        self.send_queue = {}#{address:filename} to send files
        self.receive_queue = {}#{address:{filename,progress}} to receive files
        self._events = {}
        self.address_reg = r"[A-Za-z0-9@]{10}"
        self.argon_reg = r"[A-Za-z0-9+/]{11,64}\$[A-Za-z0-9+/]{16,86}"
        for i in range(10):
            addr,seed = self.generate_address(),self.generate_address()
            self.address[addr] = {"seed":seed}
        del addr,seed
        Thread(target=self.listen_packets, daemon=True).start()

    def event(self, func):
        self._events[func.__name__] = func
        return func

    def trigger_event(self, event_name, *args, **kwargs):
        if event_name in self._events:
            self._events[event_name](*args, **kwargs)

    def receive_message(self, sender: str, message: str):
        self.trigger_event('on_message', sender, message)

    def log(self, message: str):
        self.trigger_event('on_log', message)

    def contact_update(self):
        self.trigger_event('on_contact_list_update', self.contacts)

    def ask_file(self, sender: str, file_size: int, file_name: str):
        self.trigger_event('on_ask_file', sender, file_size, file_name)

    def progress(self, sender: str, progress: float):
        self.trigger_event('on_file_progress', sender, progress)

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

    def ask(self,data:bytes,offset:int)->int:
        #0:1 -> OPCODE
        #1:11 -> TO ADDRESS
        #11:21 -> FROM CONTACT ADDRESS
        #21:53 -> MAIN KEY
        #1+10+32+16 = 59
        MAX_ASK = 1+ADDRESS_LENGTH+MAIN_KEY_LENGTH+(16%MAIN_KEY_LENGTH)
        to_addr = data[offset:offset+ADDRESS_LENGTH]
        try:
            to_addr = to_addr.decode("utf-8")
            if not re.match(self.address_reg,to_addr):return 0
            if to_addr not in self.address:return 0
            if len(data) != MAX_ASK:return 0
            print("c")
        except:#not a valid address
            return 0
        if to_addr in self.address:
            #its me :D
            offset += ADDRESS_LENGTH
            contact = data[offset:offset+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)]#to match the required length of AES that is %16 == 0
            null_iterator = Shake256PRNG(b"\x00")
            contact = self.aes_decrypt(contact, self.address[to_addr]["seed"],null_iterator)
            try:
                contact = contact.decode("utf-8")
            except:
                return 0
            offset += ADDRESS_LENGTH+(16%ADDRESS_LENGTH)
            main_key = data[offset:offset+MAIN_KEY_LENGTH+(16%MAIN_KEY_LENGTH)]#match requirements
            null_iterator = Shake256PRNG(b"\x00")
            main_key = self.aes_decrypt(main_key, self.address[to_addr]["seed"],null_iterator)#don't decode its mainly random bytes
            r = Shake256PRNG(main_key,debug=True)
            self.contacts[contact] = {"main_key":main_key,"random_iterator":r}
            self.log(f"You have a new contact: {contact}")
            self.contact_update()
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
            self.conn.sendall(payload)
            del self.address[to_addr]#remove the address from the list (its used only once)
            return 1

    def verify(self,data:bytes,offset:int):
        #0:32 -> VERIFIER
        #32:42 -> CONTACT ADDRESS
        MAX_ACCEPT = 1+MAIN_KEY_LENGTH*2+2+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)
        verifier = data[offset:offset+MAIN_KEY_LENGTH*2+2]
        try:
            verifier = verifier.decode("utf-8")
            if not re.match(self.argon_reg,verifier):return 0
            if len(data) != MAX_ACCEPT:return 0
        except:#not a valid verifier
            return
        verifier = "$argon2id$v=19$m=131072,t=2,p=2$" + verifier
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
                    self.log(f"[*] verfied a contact")
                    break
            except:pass#verify naturaly return an exception
        else:
            #can happen when two random personne try to match
            return 0
        contact = data[offset:offset+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)]
        null_iterator = Shake256PRNG(b"\x00")
        contact = self.aes_decrypt(contact, p, null_iterator).decode("utf-8")#replace random contact with the real one
        self.contacts[contact] = self.contacts[contact_address].copy()
        del self.contacts[contact_address]#remove the random contact
        self.log(f"You have a new contact: {contact}")
        self.contact_update()
        return 1

    def check_received(self,contact:str,data:bytes):
        """from a decrypted message check if the message is a request or a message"""
        offset = 1
        #0:1 -> OPCODE
        #1:9 -> FILE SIZE
        #9: -> FILE NAME
        OPCODE = data[0:offset]
        if OPCODE == SEND_OPCODE:
            #user sent a file
            file_size = int.from_bytes(data[offset:offset+8], "big")
            offset += 8
            file_name = data[offset:].decode("utf-8")
            self.ask_file(contact, file_size, file_name)
        elif OPCODE == ACCEPT_OPCODE and contact in self.send_queue:
            # user accepted the file
            file_name = self.send_queue[contact]["file_name"]
            file_size = self.send_queue[contact]["file_size"]
            if file_size > MAX_FILE_SIZE:
                print(f"[-] File size changed ({to_humain_readable(file_size)} > {to_humain_readable(MAX_FILE_SIZE)})")
                return
            self.log(f"[*] Sending file: {file_name} ({to_humain_readable(file_size)})")
            chunk = self.send_queue[contact]["file"].read(4096-ONE_TIME_LENGTH-1)#-1 for the opcode, -ONE_TIME_LENGTH for the OTV
            if not chunk:return print("[-] Error: file is empty")
            self.send(contact, SENDING_OPCODE + chunk)
        elif OPCODE == SENDING_OPCODE:
            #user is sending a file
            if not self.receive_queue[contact]:return#no file to receive
            file_name = self.receive_queue[contact]["file_name"]
            file_size = self.receive_queue[contact]["file_size"]
            file = self.receive_queue[contact]["file"]
            file.write(data[offset:])
            if DEBUG:print(f"recv: {data[offset:10]}, t: {time.time()}")#debug
            self.receive_queue[contact]["received"] += len(data[offset:])
            self.progress(contact, self.receive_queue[contact]["received"])
            self.send(contact, OK_OPCODE)
        elif OPCODE == OK_OPCODE:
            if data[offset:] != b"":return print("[-] Error: extra data after OK_OPCODE")
            if DEBUG:print("OK, t: ",time.time())#debug
            if contact in self.send_queue:
                #user need next chunk
                file = self.send_queue[contact]["file"]
                chunk = file.read(4096-ONE_TIME_LENGTH-1)#-1 for the opcode, -ONE_TIME_LENGTH for the OTV
                if not chunk:
                    file.close()
                    del self.send_queue[contact]
                    print("done sending file")
                    self.send(contact, OK_OPCODE)
                    return
                if DEBUG:print(f"sent: {chunk[:10]}, t: {time.time()}")#debug
                self.send(contact, SENDING_OPCODE + chunk)
            elif contact in self.receive_queue:
                #done receiving file
                file = self.receive_queue[contact]["file"]
                file_name = self.receive_queue[contact]["file_name"]
                file_size = self.receive_queue[contact]["file_size"]
                file.close()
                print(f"file received: {file_name} ({to_humain_readable(file_size)})")
                self.progress(contact, -1)#all done
                del self.receive_queue[contact]
                self.log(f"[+] File received: {file_name} ({to_humain_readable(file_size)})")
        else:
            try:
                data = data.decode("utf-8")
            except Exception as e:
                print(f"[-] Error decoding message: {e}")
                return
            self.receive_message(contact, data)

    # Client handler to receive messages
    def listen_packets(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((self.ip, self.port))
        while True:
            # try:
                data = self.conn.recv(4096)
                if not data:continue
                #texting / sending file is more important than checking for OP_CODE
                #so we need to check for the contact first (receiving a valid OTV by pure luck is extremely low, that's why we check for the contact first)

                #check if the message come from a contact
                #here there are no deterministic pattern for the message so we need to check for all contact the OTV
                for contact in self.contacts:
                    contact_random_iterator = self.contacts[contact]["random_iterator"]#use the random iterator of the contact
                    contact_random_iterator_state = contact_random_iterator.get_state()#save the state of the random iterator to decrypt the message
                    contact_random_iterator.iterate()
                    OTcheck = self.check_one_time(data,contact_random_iterator)
                    if OTcheck:
                        contact_random_iterator.set_state(contact_random_iterator_state)#restore the state of the random iterator
                        message = self.aes_decrypt(OTcheck, self.contacts[contact]["main_key"], contact_random_iterator)
                        contact_random_iterator.iterate(2)#use two credit of the random iterator
                        self.check_received(contact,message)
                        break
                    else:
                        self.contacts[contact]["random_iterator"].set_state(contact_random_iterator_state)#restore the state of the random iterator
                        # print("[-] Block not from a contact")

                offset = 1
                #test if functions work in case its not a ASK / ACCEPT / any other OP_CODE
                if data[0:offset] == ASK_OPCODE:
                    if self.ask(data,offset):continue
                if data[0:offset] == ACCEPT_OPCODE:
                    if self.verify(data,offset):continue
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
        self.conn.sendall(payload)

    def send(self, contact: str, payload: bytes):
        main_key = self.contacts[contact]["main_key"]
        r = self.contacts[contact]["random_iterator"]
        payload = self.aes_encrypt(payload, main_key, r)
        payload = self.add_one_time(payload,r)
        self.conn.sendall(payload)
        if DEBUG:print(f"REAL sent: {payload[:10]}, t: {time.time()}")#debug

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