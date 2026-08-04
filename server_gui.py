import os
import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from encryption import open_message, protect_message
from gui_common import COLORS, SecureMessengerWindow
from message_format import create_file_message, create_text_message, parse_message, save_received_file
from msg_handler import receive_data, send_data


# server gui that listens for clients and exchanges encrypted messages
class ServerGUI(SecureMessengerWindow):

    # initializes the listening socket, client socket, and gui state
    def __init__(self, root: tk.Tk) -> None:
        super().__init__(root, "Server")
        # uses 0.0.0.0 so the server can accept connections from any local network interface
        self.host_var = tk.StringVar(value="0.0.0.0")

        # uses port 5001 to match the client configuration
        self.port_var = tk.StringVar(value="5001")

        # stores the socket that listens for new client connections
        self.server_socket: socket.socket | None = None

        # stores the socket used to communicate with the connected client
        self.client_socket: socket.socket | None = None

        # tracks whether the listening socket is currently active
        self.running = False

        # tracks whether a client is currently connected
        self.connected = False

        # prevents two gui actions from writing to the same socket at once
        self.send_lock = threading.Lock()
        self._build_server_panel()
        self._build_buttons()
        self._set_state(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    # creates the host, port, password, and encryption controls
    def _build_server_panel(self) -> None:
        ttk.Label(self.left, text="SERVER & SECURITY", style="Section.TLabel").pack(fill="x")

        # groups all server connection settings inside the left panel
        form = ttk.Frame(self.left, style="Panel.TFrame", padding=14)
        form.pack(fill="both", expand=True)
        ttk.Label(form, text="Listening Host").pack(anchor="w")

        # lets the user choose which local interface the server listens on
        self.host_entry = ttk.Entry(form, textvariable=self.host_var)
        self.host_entry.pack(fill="x", pady=(4, 12))
        ttk.Label(form, text="Port").pack(anchor="w")

        # lets the user choose the tcp listening port
        self.port_entry = ttk.Entry(form, textvariable=self.port_var)
        self.port_entry.pack(fill="x", pady=(4, 12))
        ttk.Label(form, text="Shared Password").pack(anchor="w")

        # hides the shared password while it is entered
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, show="•")
        self.password_entry.pack(fill="x", pady=(4, 12))
        ttk.Label(form, text="Encryption Mode").pack(anchor="w", pady=(2, 4))

        # allows the server to use the des-56 encryption option
        self.des_radio = ttk.Radiobutton(form, text="DES-56", value="DES-56", variable=self.mode_var)

        # allows the server to use the aes-128 encryption option
        self.aes_radio = ttk.Radiobutton(form, text="AES-128", value="AES-128", variable=self.mode_var)
        self.des_radio.pack(anchor="w", pady=2)
        self.aes_radio.pack(anchor="w", pady=2)
        self.start_button = ttk.Button(form, text="Start Server", style="Accent.TButton", command=self.start_server)
        self.start_button.pack(fill="x", pady=(16, 6))
        self.stop_button = ttk.Button(form, text="Stop Server", style="Danger.TButton", command=self.stop_server)
        self.stop_button.pack(fill="x")
        ttk.Label(
            form,
            text="Encryption: selected mode\nIntegrity: HMAC-SHA256\nTransport: TCP\nKey derivation: PBKDF2",
            style="Muted.TLabel",
            justify="left",
        ).pack(anchor="w", pady=(20, 0))

    # creates buttons for server text and file responses
    def _build_buttons(self) -> None:
        self.send_button = ttk.Button(self.button_row, text="Send Text", style="Accent.TButton", command=self.send_text)
        self.send_button.pack(side="left", padx=(0, 5))
        self.image_button = ttk.Button(self.button_row, text="Attach Image", command=lambda: self.send_file("IMAGE"))
        self.image_button.pack(side="left", padx=5)
        self.audio_button = ttk.Button(self.button_row, text="Attach Audio", command=lambda: self.send_file("AUDIO"))
        self.audio_button.pack(side="left", padx=5)
        self.file_button = ttk.Button(self.button_row, text="Attach File", command=lambda: self.send_file("FILE"))
        self.file_button.pack(side="left", padx=5)
        ttk.Button(self.button_row, text="Clear", command=lambda: self.message_box.delete("1.0", "end")).pack(side="right")

    # validates the settings and starts the tcp listening socket
    def start_server(self) -> None:
        if self.running:
            return

        if not self.password_var.get():
            messagebox.showerror("Missing password", "Enter the shared password.")
            return

        try:
            port = int(self.port_var.get())
            # creates an ipv4 tcp socket for reliable client-server communication
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # allows the same port to be reused after restarting the server
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # attaches the socket to the selected host address and port
            sock.bind((self.host_var.get(), port))

            # waits for one client connection at a time
            sock.listen(1)
            self.server_socket = sock
            self.running = True
            self._set_state(True, False)
            self.log("success", f"server listening on {self.host_var.get()}:{port}")
            threading.Thread(target=self._accept_loop, daemon=True).start()

        except (ValueError, OSError) as error:
            self.log("error", f"could not start server: {error}")

    # waits for incoming clients without freezing the gui
    def _accept_loop(self) -> None:
        while self.running and self.server_socket is not None:
            try:
                # pauses until a client connects, then returns its socket and address
                client, address = self.server_socket.accept()
                self.client_socket = client
                self.connected = True
                self.root.after(0, lambda a=address: self._client_connected(a))
                self._receive_loop()

            except OSError:
                break

    # updates the gui after a client connection is accepted
    def _client_connected(self, address: tuple[str, int]) -> None:
        self._set_state(True, True)
        self.log("success", f"client connected from {address[0]}:{address[1]}")

    # continuously receives and verifies messages from the client
    def _receive_loop(self) -> None:
        while self.running and self.connected and self.client_socket is not None:
            try:
                # receives one length-prefixed protected message from the client
                protected = receive_data(self.client_socket).decode("utf-8")

                # verifies the hmac before decrypting the client message
                message_json, ciphertext = open_message(protected, self.password_var.get(), self.selected_mode())

                # converts the decrypted json into a dictionary for text or file handling
                message = parse_message(message_json)
                self.root.after(0, lambda m=message, c=ciphertext: self._display_received(m, c))

            except (OSError, ConnectionError) as error:
                if self.running:
                    self.root.after(0, lambda e=str(error): self._client_left(e))
                break

            except ValueError as error:
                self.root.after(0, lambda e=str(error): self.log("error", f"security error: {e}"))

    # converts the server response into a json text message
    def send_text(self) -> None:
        text = self.message_box.get("1.0", "end").strip()

        if not text:
            return

        self._send(create_text_message(text), "TEXT", text, None)
        self.message_box.delete("1.0", "end")

    # lets the server user select a file to send to the client
    def send_file(self, message_type: str) -> None:
        path = self.choose_file(message_type)

        if not path:
            return
        try:
            self._send(
                create_file_message(path, message_type),
                message_type,
                self.file_plaintext_label(path, message_type),
                os.path.basename(path),
            )

        except (OSError, ValueError) as error:
            self.log("error", f"file error: {error}")

    # encrypts, authenticates, and transmits one complete response
    def _send(self, message_json: str, message_type: str, plaintext: str, filename: str | None) -> None:
        if not self.connected or self.client_socket is None:
            self.log("warning", "wait for a client before sending")
            return

        try:
            # encrypts the outgoing json and adds an hmac-sha256 tag
            protected = protect_message(message_json, self.password_var.get(), self.selected_mode())

            # separates only the ciphertext portion for the technical display
            ciphertext = protected.rsplit("|", 1)[0]

            with self.send_lock:
                # sends the complete ciphertext and hmac using the length header protocol
                send_data(self.client_socket, protected.encode("utf-8"))
            self.append_conversation("sent", "Server", message_type, plaintext if message_type == "TEXT" else filename or "")
            self.update_details(message_type, filename, plaintext, self._ciphertext_preview(ciphertext), "Generated")
            self.log("success", f"{message_type.lower()} encrypted and sent")

        except (OSError, ConnectionError, ValueError) as error:
            self.log("error", str(error))

    # displays a verified client message and saves received files
    def _display_received(self, message: dict, ciphertext: str) -> None:
        message_type = message["type"]
        filename = message.get("filename")

        if message_type == "TEXT":
            plaintext = message["data"]
            content = plaintext

        else:
            # decodes the base64 file data and saves it in the server receive folder
            saved = save_received_file(message, "server_received_files")
            plaintext = f"<binary {message_type.lower()} data saved to {saved}>"
            content = (
                f"Received: {filename}\n"
                f"Saved to: {saved}"
            )
            self.log("success", f"file saved to {saved}")
        self.append_conversation("received", "Client", message_type, content)
        self.update_details(message_type, filename, plaintext, self._ciphertext_preview(ciphertext), "Verified")
        self.log("success", "hmac verified")

        if message_type == "TEXT" and message["data"].lower() in ("quit", "exit"):
            self._client_left("client requested closure")

    # handles a client disconnect and returns to listening mode
    def _client_left(self, reason: str) -> None:
        self.log("warning", f"client disconnected: {reason}")
        self._close_client()
        self._set_state(self.running, False)

    # safely shuts down the currently connected client socket
    def _close_client(self) -> None:

        # tracks whether a client is currently connected
        self.connected = False

        if self.client_socket is not None:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.client_socket.close()
            except OSError:
                pass
            self.client_socket = None

    # enables or disables controls for each server state
    def _set_state(self, running: bool, connected: bool) -> None:
        self.running = running
        self.connected = connected

        # locks the host, port, password, and mode while the server is running
        config_state = "disabled" if running else "normal"

        for widget in (self.host_entry, self.port_entry, self.password_entry, self.des_radio, self.aes_radio):
            widget.configure(state=config_state)
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")

        # enables message controls only after a client has connected
        send_state = "normal" if connected else "disabled"

        for widget in (self.send_button, self.image_button, self.audio_button, self.file_button):
            widget.configure(state=send_state)

        if connected:
            self.status_var.set("Connected")
            self.status_label.configure(foreground=COLORS["success"])

        elif running:
            self.status_var.set("Listening")
            self.status_label.configure(foreground=COLORS["warning"])

        else:
            self.status_var.set("Stopped")
            self.status_label.configure(foreground=COLORS["error"])

    # closes both server sockets and resets the gui
    def stop_server(self) -> None:

        # tracks whether the listening socket is currently active
        self.running = False
        self._close_client()

        if self.server_socket is not None:
            try:
                self.server_socket.close()
            except OSError:
                pass
            self.server_socket = None
        self._set_state(False, False)
        self.log("warning", "server stopped")

    # stops the server before closing the application window
    def close(self) -> None:
        self.stop_server()
        self.root.destroy()


# creates and runs the server gui
def main() -> None:
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()