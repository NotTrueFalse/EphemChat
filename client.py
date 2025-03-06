import socket
import os
from argon2 import PasswordHasher
from threading import Thread
from hashlib import sha256
import secrets
from utils.CPRNG import Shake256PRNG
from utils.AES import AES_Manager
from utils.cool import to_humain_readable
import re
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
ADDRESS_LENGTH = 10#10^63-9^63 => 9.9868998e+62  possibilities ((9.9868998e+62 )/(1000*60*60*24*365.24) => 3.1647442e+52 years to test all possibilities if we go at 1 adderss per ms)
#this is just for security, you can get it higher but if you choose to lower it will be easier to bruteforce (not recommended)
MAIN_KEY_LENGTH = 32
#used to find your partner: OTV (One Time Verifier added randomly to the message)
ONE_TIME_LENGTH = 32
#how many octets to use to store the n° order of a file chunk (a file chunk is 4096 (4063-CHUNK_INTORD_SIZE data, 32 ONE_TIME, 1 SENDING_OPCODE) octets long)
#so in theory we can send a file of (2^(8*CHUNK_INTORD_SIZE)-1)*(4063-CHUNK_INTORD_SIZE)/(1024**4) To before hitting the limit
CHUNK_INTORD_SIZE = 8

OK_OPCODE = b"\x01"
ASK_OPCODE = b"\x15"#don't ask me why I choose 15, you can configure it to be anything (btw 01 - ff)
ACCEPT_OPCODE = b"\x16"
SEND_OPCODE = b"\x17"
SENDING_OPCODE = b"\x18"
MAX_FILE_SIZE = 1024**3*4#4GB max accepted file size (self imposed limit)
#DEBUG: 0: no debug, 1: print debug, 2: print and save debug
DEBUG = 2

CHUNK_DATA_SIZE = 4096 - ONE_TIME_LENGTH - 1 - CHUNK_INTORD_SIZE

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
        self.chunk_hash_logs = {}  # Store hashes for verification
        self.aes = AES_Manager()
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
        except:#not a valid address
            return 0
        if to_addr in self.address:
            #its me :D
            offset += ADDRESS_LENGTH
            contact = data[offset:offset+ADDRESS_LENGTH+(16%ADDRESS_LENGTH)]#to match the required length of AES that is %16 == 0
            null_iterator = Shake256PRNG(b"\x00")
            contact = self.aes.decrypt(contact, self.address[to_addr]["seed"],null_iterator)
            try:
                contact = contact.decode("utf-8")
            except:
                return 0
            offset += ADDRESS_LENGTH+(16%ADDRESS_LENGTH)
            main_key = data[offset:offset+MAIN_KEY_LENGTH+(16%MAIN_KEY_LENGTH)]#match requirements
            null_iterator = Shake256PRNG(b"\x00")
            main_key = self.aes.decrypt(main_key, self.address[to_addr]["seed"],null_iterator)#don't decode its mainly random bytes
            r = Shake256PRNG(main_key,debug=DEBUG==1)
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
            contact_address = self.aes.encrypt(contact_address, main_key,null_iterator)
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
        contact = self.aes.decrypt(contact, p, null_iterator).decode("utf-8")#replace random contact with the real one
        self.contacts[contact] = self.contacts[contact_address].copy()
        del self.contacts[contact_address]#remove the random contact
        self.log(f"You have a new contact: {contact}")
        self.contact_update()
        return 1

    def chunk_generator(self,contact:str):
        """Generate chunks of a file (with chunk order)"""
        chunk_num = 0
        while True:
            chunk = self.send_queue[contact]["_file"].read(CHUNK_DATA_SIZE)
            if not chunk:break
            chunk_num += 1
            chunk += chunk_num.to_bytes(CHUNK_INTORD_SIZE, "big")
            yield chunk

    def check_received(self,contact:str,data:bytes):
        """from a decrypted message check if the message is a request or a message"""
        offset = 1
        #0:1 -> OPCODE
        #1:9 -> FILE SIZE
        #9: -> FILE NAME
        OPCODE = data[:offset]
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
            self.log(f"[*] loading file {file_name} ({to_humain_readable(file_size)}) in memory")
            self.send_queue[contact]["chunks"] = []
            for chunk in self.chunk_generator(contact):
                self.send_queue[contact]["chunks"].append(chunk)
            if not self.send_queue[contact]["chunks"]:
                print("[-] Error: no chunks to send")
                return
            self.log(f"[*] sending chunks for {file_name}")
            self.send(contact, SENDING_OPCODE + self.send_queue[contact]["chunks"].pop(0))
        elif OPCODE == SENDING_OPCODE:
            #user is sending a file
            if not self.receive_queue[contact]:return#no file to receive
            chunk = data[1:]#remove the opcode
            chunk_num = int.from_bytes(chunk[-CHUNK_INTORD_SIZE:], "big")
            chunk_data = chunk[:-CHUNK_INTORD_SIZE]
            if DEBUG==1:print(f"recv: {chunk_data[:10]}, t: {time.time()}")#debug
            self.receive_queue[contact]["received"] += len(chunk_data)
            self.progress(contact, self.receive_queue[contact]["received"])
            self.receive_queue[contact]["chunks"][str(chunk_num)] = chunk_data#place:chunk
            self.send(contact, OK_OPCODE)
        elif OPCODE == OK_OPCODE:
            if data[offset:] != b"":return print("[-] Error: extra data after OK_OPCODE")
            if DEBUG==1:print("OK, t: ",time.time())#debug
            if contact in self.send_queue:
                try:
                    chunk = self.send_queue[contact]["chunks"].pop(0)
                except IndexError as e:
                    print("done sending file")
                    self.send_queue[contact]["_file"].close()
                    del self.send_queue[contact]
                    self.send(contact, OK_OPCODE)
                    return
                if DEBUG==1:print(f"sent: {chunk[:10]}, t: {time.time()}")#debug
                self.send(contact, SENDING_OPCODE + chunk)
            elif contact in self.receive_queue:
                #done receiving file
                chunks = self.receive_queue[contact]["chunks"]
                file_name = self.receive_queue[contact]["file_name"]
                file_size = self.receive_queue[contact]["file_size"]
                with open(self.receive_queue[contact]["file_path"], "wb") as file:
                    for chunk_num in sorted(chunks, key=lambda x: int(x)):
                        file.write(chunks[chunk_num])
                    file.close()
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
                        message = self.aes.decrypt(OTcheck, self.contacts[contact]["main_key"], contact_random_iterator)
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
        me_contact = self.aes.encrypt(me_contact, seed, null_iterator)
        main_key = os.urandom(MAIN_KEY_LENGTH)
        # print(f"main_key: {main_key}")#debug
        idk_contact = self.generate_address()
        r = Shake256PRNG(main_key,debug=DEBUG==1)
        self.contacts[idk_contact] = {"main_key":main_key,"random_iterator":r}#temporarly save a random contact instead of the real one
        null_iterator = Shake256PRNG(b"\x00")
        main_key = self.aes.encrypt(main_key, seed, null_iterator)
        payload = ASK_OPCODE + address.encode("utf-8") + me_contact + main_key
        self.conn.sendall(payload)

    def send(self, contact: str, payload: bytes):
        main_key = self.contacts[contact]["main_key"]
        r = self.contacts[contact]["random_iterator"]
        payload = self.aes.encrypt(payload, main_key, r)
        payload = self.add_one_time(payload,r)
        self.conn.sendall(payload)
        if DEBUG==1:print(f"REAL sent: {payload[:10]}, t: {time.time()}")#debug

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