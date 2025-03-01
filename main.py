from PyQt5.QtCore import *
from PyQt5.QtGui  import *
from PyQt5.QtWidgets import *
from client import Client
import os

ACCEPT_OPCODE = b"\x16"
SEND_OPCODE = b"\x17"
MAX_FILE_SIZE = 1024**3*4#4GB max accepted file size

def to_humain_readable(size:int)->str:
    for unit in ['Octets', 'Ko', 'Mo', 'Go', 'To']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"

class EphemChat(QMainWindow):

    message_received = pyqtSignal(str, str)
    log_message = pyqtSignal(str)
    contact_list_updated = pyqtSignal(dict)
    file_requested = pyqtSignal(str, int, str)
    file_progress_updated = pyqtSignal(str, float, int)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("EphemChat")
        self.setFixedSize(800, 600)
        self.client = Client("127.0.0.1", 12345)
        self.progress_bars = {}
        self.init_signals()
        self.init_client_events()
        self.initUI()
        
    def init_signals(self):
        # Connect signals to GUI update methods
        self.message_received.connect(self.on_message_gui)
        self.log_message.connect(self.on_log_gui)
        self.contact_list_updated.connect(self.on_contact_list_update_gui)
        self.file_requested.connect(self.on_ask_file_gui)
        self.file_progress_updated.connect(self.on_file_progress_gui)

    def init_client_events(self):
        @self.client.event
        def on_message(sender: str, message: str):
            self.message_received.emit(sender, message)

        @self.client.event
        def on_log(message: str):
            self.log_message.emit(message)

        @self.client.event
        def on_contact_list_update(contacts: dict):
            self.contact_list_updated.emit(contacts)

        @self.client.event
        def on_ask_file(sender: str, file_size: int, file_name: str):
            self.file_requested.emit(sender, file_size, file_name)

        @self.client.event
        def on_file_progress(sender: str, received: float):
            fsize = self.client.receive_queue[sender]["file_size"]
            self.file_progress_updated.emit(sender, received, fsize) 

    # Slots (GUI updates happen here)
    def on_message_gui(self, sender: str, message: str):
        self.chat.append(f"{sender}: {message}")

    def on_log_gui(self, message: str):
        self.log_list.addItem(message)

    def on_contact_list_update_gui(self, contacts: list):
        self.contact_list.clear()
        for contact in contacts:
            self.contact_list.addItem(contact)

    def on_ask_file_gui(self, sender: str, file_size: int, file_name: str):
        self.log_list.addItem(f"{sender} wants to send {file_name} ({to_humain_readable(file_size)})")
        self.receive_file(sender, file_size, file_name)

    def on_file_progress_gui(self, sender: str, received: int, fsize: int):
        if sender in self.progress_bars:
            self.progress_bars[sender].setValue(int(received / fsize * 100))
            if received == -1:
                self.progress_bars[sender].deleteLater()
                self.progress_bars.pop(sender)


    def create_progress_bar(self,contact:str):
        self.file_progress = QProgressBar()
        self.file_progress.setRange(0, 100)
        self.file_progress.setValue(0)
        self.middle_layout.addWidget(self.file_progress)
        self.progress_bars[contact] = self.file_progress

    def initUI(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        self.left_box = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_box.setLayout(self.left_layout)

        self.contact_list = QListWidget()
        self.left_layout.addWidget(self.contact_list)

        self.add_contact_button = QPushButton("Add Contact")
        self.add_contact_button.clicked.connect(self.add_contact_window)
        self.list_address_button = QPushButton("List my address")
        self.list_address_button.clicked.connect(self.list_address_box)
        self.left_layout.addWidget(self.add_contact_button)
        self.left_layout.addWidget(self.list_address_button)

        self.main_layout.addWidget(self.left_box)

        self.middle_box = QWidget()
        self.middle_layout = QVBoxLayout()
        self.middle_box.setLayout(self.middle_layout)

        self.chat = QTextEdit()
        self.chat.setReadOnly(True)
        self.middle_layout.addWidget(self.chat)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Type a message")
        self.middle_layout.addWidget(self.input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.middle_layout.addWidget(self.send_button)

        self.file_button = QPushButton("Send file")
        self.file_button.clicked.connect(self.send_file)
        self.middle_layout.addWidget(self.file_button)

        self.main_layout.addWidget(self.middle_box)

        # Right box: Log messages
        self.right_box = QWidget()
        self.right_layout = QVBoxLayout()
        self.right_box.setLayout(self.right_layout)

        self.log_list = QListWidget()
        self.right_layout.addWidget(self.log_list)

        self.main_layout.addWidget(self.right_box)

    def list_address_box(self):
        """Show the user's address and seeds"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Your addresses")
        layout = QVBoxLayout(dialog)
        
        label = QLabel("Your addresses and seeds:")
        layout.addWidget(label)
        
        lst = QListWidget()
        for address, seed in self.client.address.items():
            lst.addItem(f"{address}|{seed["seed"]}")
        layout.addWidget(lst)
        
        dialog.setLayout(layout)
        dialog.exec_()


    def add_contact_window(self):
        #make an input dialog to get the contact name
        contact, ok = QInputDialog.getText(self, "Add Contact", "Enter the contact address|seed:")
        if ok and contact:
            address, seed = contact.split("|")
            self.client.add_contact(address, seed)

    def send_message(self):
        contact = self._get_contact()
        if not contact:
            return
        message = self.input.text()
        if message:
            self.client.send(contact, message.encode("utf-8"))
            self.chat.append(f"Me: {message}")
            self.input.clear()

    def receive_file(self, sender: str, file_size: int, file_name: str):
        """
        Ask the user if they want to receive a file, and handle the response inline.
        """
        # Build the message to display
        msg = (f"{sender} wants to send you {file_name} "
            f"({to_humain_readable(file_size)}). Do you accept?")
        
        # Create a QMessageBox for the user prompt
        dialog = QMessageBox(self)
        dialog.setWindowTitle("File Transfer Request")
        dialog.setText(msg)
        
        # Add Yes and No buttons
        yes_button = dialog.addButton("Yes", QMessageBox.AcceptRole)
        no_button = dialog.addButton("No", QMessageBox.RejectRole)
        
        dialog.exec_()
        if dialog.clickedButton() == yes_button:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save file", file_name)
            if file_path:
                try:
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    self.client.receive_queue[sender] = {
                        "file_path": file_path,
                        "file_name": file_name,
                        "file_size": file_size,
                        "chunks": {},
                        "received": 0,
                    }
                    self.client.send(sender, ACCEPT_OPCODE)
                    self.create_progress_bar(sender)
                except OSError as e:
                    QMessageBox.critical(self, "Error", f"Could not prepare file: {str(e)}")
        else:
            return

    def send_file(self):
        contact = self._get_contact()
        if not contact:
            return
            
        file_path = QFileDialog.getOpenFileName(self, "Send file", "", "All files (*.*)")[0]
        if not file_path:  # User cancelled
            return
            
        try:
            file_name = os.path.basename(file_path)
            if len(file_name) > 4055:  # Check filename length limit
                QMessageBox.warning(self, "Error", "File name is too long")
                return
                
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:  # Check file size limit
                QMessageBox.warning(self, "Error", "File is too large")
                return
            payload = SEND_OPCODE + file_size.to_bytes(8, "big") + file_name.encode("utf-8")
            self.client.send(contact, payload)
            self.client.send_queue[contact] = {
                "file_name": file_name,
                "file_size": file_size,
                "_file": open(file_path, "rb"),
            }
            QMessageBox.information(self, "File added to queue", f"File {file_name} added to queue, will send when accepted")
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Could not access file: {str(e)}")

    def _get_contact(self) -> str:
        if self.contact_list.count() == 0:
            QMessageBox.warning(self, "No Contacts", "You don't have any saved contacts.")
            return None

        contact_item = self.contact_list.currentItem()
        if not contact_item:
            QMessageBox.warning(self, "No Contact Selected", "Please select a contact from the list.")
            return None

        contact = contact_item.text()
        return contact


if __name__ == "__main__":
    app = QApplication([])
    window = EphemChat()
    window.show()
    app.exec_()