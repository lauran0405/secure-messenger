import os
import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from encryption import open_message, protect_message
from gui_common import COLORS, SecureMessengerWindow
from message_format import create_file_message, create_text_message, parse_message, save_received_file
from msg_handler import receive_data, send_data


# client gui that connects to the server and sends encrypted messages
class ClientGUI(SecureMessengerWindow):

    # initializes the client socket state and gui controls
    def __init__(self, root: tk.Tk) -> None:

        # initializes the shared gui layout
        super().__init__(root, "Client")

        # stores server ip address
        self.host_var = tk.StringVar(value="127.0.0.1")

        # stores server port number
        self.port_var = tk.StringVar(value="5001")

        # stores connected client socket
        self.client_socket: socket.socket | None = None

        # tracks whether client is connected
        self.connected = False

        # prevents multiple threads from sending at the same time
        self.send_lock = threading.Lock()

        # creates client specific gui section
        self._build_connection_panel()
        self._build_buttons()

        # starts gui in disconnected state
        self._set_connected(False)

        # closes socket before closing gui
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    # creates the server address, password, and encryption controls
    def _build_connection_panel(self) -> None:

        # creates connection section title
        ttk.Label(self.left, text="CONNECTION & SECURITY", style="Section.TLabel").pack(fill="x")

        # creates a frame for the connection controls
        form = ttk.Frame(self.left, style="Panel.TFrame", padding=14)
        form.pack(fill="both", expand=True)

        # creates the server ip address label
        ttk.Label(form, text="Server IP Address").pack(anchor="w")

        # creates server ip address entry
        self.host_entry = ttk.Entry(form, textvariable=self.host_var)
        self.host_entry.pack(fill="x", pady=(4, 12))

        # creates port label
        ttk.Label(form, text="Port").pack(anchor="w")

        # creates the port entry
        self.port_entry = ttk.Entry(form, textvariable=self.port_var)
        self.port_entry.pack(fill="x", pady=(4, 12))

        # creates shared password label
        ttk.Label(form, text="Shared Password").pack(anchor="w")

        # creates shared password entry
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, show="•")
        self.password_entry.pack(fill="x", pady=(4, 12))

        # creates encryption mode label
        ttk.Label(form, text="Encryption Mode").pack(anchor="w", pady=(2, 4))

        # creates the des-56 radio button
        self.des_radio = ttk.Radiobutton(form, text="DES-56", value="DES-56", variable=self.mode_var)

        # creates aes-128 radio button
        self.aes_radio = ttk.Radiobutton(form, text="AES-128", value="AES-128", variable=self.mode_var)
        self.des_radio.pack(anchor="w", pady=2)
        self.aes_radio.pack(anchor="w", pady=2)

        # creates the connect button
        self.connect_button = ttk.Button(form, text="Connect", style="Accent.TButton", command=self.connect)
        self.connect_button.pack(fill="x", pady=(16, 6))

        # creates the disconnect button
        self.disconnect_button = ttk.Button(form, text="Disconnect", style="Danger.TButton", command=self.disconnect)
        self.disconnect_button.pack(fill="x")

        # displays the security summary
        ttk.Label(
            form,
            text="Encryption: selected mode\nIntegrity: HMAC-SHA256\nTransport: TCP\nKey derivation: PBKDF2",
            style="Muted.TLabel",
            justify="left",
        ).pack(anchor="w", pady=(20, 0))

    # creates buttons for sending text, images, audio, and files
    def _build_buttons(self) -> None:

        # creates send text button
        self.send_button = ttk.Button(self.button_row, text="Send Text", style="Accent.TButton", command=self.send_text)
        self.send_button.pack(side="left", padx=(0, 5))

        # creates attach image button
        self.image_button = ttk.Button(self.button_row, text="Attach Image", command=lambda: self.send_file("IMAGE"))
        self.image_button.pack(side="left", padx=5)

        # creates attach audio button
        self.audio_button = ttk.Button(self.button_row, text="Attach Audio", command=lambda: self.send_file("AUDIO"))
        self.audio_button.pack(side="left", padx=5)

        # creates attach file button
        self.file_button = ttk.Button(self.button_row, text="Attach File", command=lambda: self.send_file("FILE"))
        self.file_button.pack(side="left", padx=5)

        # clear image button
        ttk.Button(self.button_row, text="Clear", command=lambda: self.message_box.delete("1.0", "end")).pack(side="right")

    # validates the connection fields and starts a background connection
    def connect(self) -> None:

        # prevents second connection
        if self.connected:
            return

        # verifies that a password was entered
        if not self.password_var.get():
            messagebox.showerror("Missing password", "Enter the shared password.")
            return

        # converts port into integer
        try:
            port = int(self.port_var.get())

        except ValueError:
            messagebox.showerror("Invalid port", "Port must be a number.")
            return

        # displays connecting status
        self.status_var.set("Connecting")
        self.status_label.configure(foreground=COLORS["warning"])

        # record the connection attempt
        self.log("info", f"opening tcp connection to {self.host_var.get()}:{port}")
        threading.Thread(target=self._connect_worker, args=(self.host_var.get(), port), daemon=True).start()

    # opens tcp connection
    def _connect_worker(self, host: str, port: int) -> None:
        try:

            # creates a tcp socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # connects to server
            sock.connect((host, port))

            # stored connected socket
            self.client_socket = sock

            # records that client is connected
            self.connected = True

            # updates the gui connection controls
            self.root.after(0, lambda: self._set_connected(True))

            # records successful connection
            self.root.after(0, lambda: self.log("success", "connected to server"))

            # starts listening to server messages
            threading.Thread(target=self._receive_loop, daemon=True).start()

        except OSError as error:

            # sends connection error to the gui thread
            self.root.after(0, lambda: self._connect_failed(str(error)))

    # handles a failed connection
    def _connect_failed(self, error: str) -> None:

        # records the error
        self.log("error", f"connection failed: {error}")

        # restores disconnected gui state
        self._set_connected(False)

    # converts the typed text into json before sending it
    def send_text(self) -> None:

        # reads text from message box
        text = self.message_box.get("1.0", "end").strip()

        # prevents empty messages
        if not text:
            return

        # creates and send the json text message
        self._send(create_text_message(text), "TEXT", text, None)

        # clears the message box
        self.message_box.delete("1.0", "end")

    # lets the user choose a file and creates its json message
    def send_file(self, message_type: str) -> None:

        # opens file selection window
        path = self.choose_file(message_type)

        # stops if no file was selection
        if not path:
            return

        try:

            # creates and sends json file message
            self._send(
                create_file_message(path, message_type),
                message_type,
                self.file_plaintext_label(path, message_type),
                os.path.basename(path),
            )

        except (OSError, ValueError) as error:

            # records a file reading or format error
            self.log("error", f"file error: {error}")

    # encrypts, authenticates, and transmits one complete message
    def _send(self, message_json: str, message_type: str, plaintext: str, filename: str | None) -> None:

        # prevents sending without connection
        if not self.connected or self.client_socket is None:
            self.log("warning", "connect before sending")
            return

        try:
            # encrypts json message and adds hmac tag
            protected = protect_message(message_json, self.password_var.get(), self.selected_mode())

            # separates the ciphertext for display
            ciphertext = protected.rsplit("|", 1)[0]

            # prevents overlapping socket sends
            with self.send_lock:
                # sends the complete protected message
                send_data(self.client_socket, protected.encode("utf-8"))

            # displays sent message
            self.append_conversation("sent", "You", message_type, plaintext

            # selects value shown in conversation panel
            if message_type == "TEXT"

            else filename or "unnamed file")

            # displays plaintext and ciphertext info
            self.update_details(message_type, filename, plaintext, self._ciphertext_preview(ciphertext), "Generated")

            # records the successful transmission
            self.log("success", f"{message_type.lower()} encrypted and sent")

        except (OSError, ConnectionError, ValueError) as error:
            self.log("error", str(error))

    # continuously receives server responses in a background thread
    def _receive_loop(self) -> None:

        # continues while socket is connected
        while self.connected and self.client_socket is not None:

            try:
                # receives one complete protected message
                protected = receive_data(self.client_socket).decode("utf-8")

                # verifies hmac and decrypts message
                message_json, ciphertext = open_message(protected, self.password_var.get(), self.selected_mode())

                # converts json into a dictionary
                message = parse_message(message_json)

                # displays message one gui thread
                self.root.after(0, lambda m=message, c=ciphertext: self._display_received(m, c))

            except (OSError, ConnectionError) as error:
                # handles a closed or interrupted connection
                if self.connected:
                    self.root.after(0, lambda e=str(error): self._connection_lost(e))
                break

            except ValueError as error:
                # handles failed hmac verification or invalid data
                self.root.after(0, lambda e=str(error): self.log("error", f"security error: {e}"))

    # displays a verified message and saves received files
    def _display_received(self, message: dict, ciphertext: str) -> None:

        # obtains the message type
        message_type = message["type"]

        # obtains the optional filename
        filename = message.get("filename")

        # handles a text message
        if message_type == "TEXT":

            # stores received plaintext
            plaintext = message["data"]

            # displays the plaintext in the conversation
            content = plaintext

        # handles an image, audio recording, or general file
        else:
            # saves the received image, audio recording, or general file
            saved = save_received_file(
                message, "client_received_files")

            # creates a readable plaintext description
            plaintext = (f"<binary {message_type.lower()} data saved to {saved}>")

            # displays the filename and saved location in the conversation
            content = (
                f"Received: {filename}\n"
                f"Saved to: {saved}")

            # records the saved file location
            self.log("success", f"file saved to {saved}")

        # displays received message
        self.append_conversation("received", "Server", message_type, content)

        # displays verified message details
        self.update_details(message_type, filename, plaintext, self._ciphertext_preview(ciphertext), "Verified")

        # records successful hmac verification
        self.log("success", "hmac verified")

        # closes when the server send quit or exit
        if message_type == "TEXT" and message["data"].lower() in ("quit", "exit"):
            self.disconnect()

    # handles a server disconnect or other socket error
    def _connection_lost(self, error: str) -> None:

        # records the connection error
        self.log("warning", f"connection closed: {error}")

        # closes the socket without adding a second log entry
        self.disconnect(log_message=False)

    # enables or disables controls based on connection state
    def _set_connected(self, connected: bool) -> None:

        # stores current connection state
        self.connected = connected

        # selects state for connection fields
        config_state = "disabled" if connected else "normal"

        # selects state for sending controls
        send_state = "normal" if connected else "disabled"

        # updates connection fields
        for widget in (self.host_entry, self.port_entry, self.password_entry, self.des_radio, self.aes_radio, self.connect_button):
            widget.configure(state=config_state)

        # updates the disconnect button
        self.disconnect_button.configure(state=send_state)

        # updates the sending buttons
        for widget in (self.send_button, self.image_button, self.audio_button, self.file_button):
            widget.configure(state=send_state)

        # displays connected status
        if connected:
            self.status_var.set("Connected")
            self.status_label.configure(foreground=COLORS["success"])

        # displays the disconnected status
        else:
            self.status_var.set("Disconnected")
            self.status_label.configure(foreground=COLORS["error"])

    # safely closes the client socket and resets the gui
    def disconnect(self, log_message: bool = True) -> None:

        # remembers whether the client was connected
        was_connected = self.connected

        # updates connection state
        self.connected = False

        # closes the socket id one exists
        if self.client_socket is not None:

            try:
                # stops sending and receiving
                self.client_socket.shutdown(socket.SHUT_RDWR)

            except OSError:
                # ignores an already closed socket
                pass

            # closes socket
            self.client_socket.close()

            # removes socket reference
            self.client_socket = None

        # restores the disconnected gui state
        self._set_connected(False)

        # records user requested disconnect
        if was_connected and log_message:
            self.log("warning", "connection closed by client")

    # closes the socket before closing the application window
    def close(self) -> None:

        # closes the socket without adding an extra log message
        self.disconnect(log_message=False)

        # closes tkinter window
        self.root.destroy()


# creates and runs the client gui
def main() -> None:
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
