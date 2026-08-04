import os
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk

COLORS = {
    "bg": "#080d15",
    "panel": "#0d1420",
    "panel_alt": "#121b29",
    "text": "#e5e7eb",
    "muted": "#94a3b8",
    "accent": "#5285c6",
    "success": "#3fa86b",
    "warning": "#d79a3a",
    "error": "#d1565b",
}

# shared gui class used by both the client and server windows
class SecureMessengerWindow:

    # initializes the shared window settings and variables
    def __init__(self, root: tk.Tk, role: str) -> None:
        self.root = root
        self.role = role
        self.root.title(f"Secure Messenger - {role}")
        self.root.geometry("1180x740")
        self.root.minsize(980, 650)
        self.root.configure(bg=COLORS["bg"])

        # stores the password shared by the client and server
        self.password_var = tk.StringVar()

        # defaults the interface to aes-128 encryption
        self.mode_var = tk.StringVar(value="AES-128")

        # stores the connection status shown in the top-right corner
        self.status_var = tk.StringVar(value="Disconnected")

        # stores the type of the message selected in the technical panel
        self.message_type_var = tk.StringVar(value="—")

        # stores the filename for image, audio, and general file messages
        self.filename_var = tk.StringVar(value="n/a")

        # stores whether the hmac was generated or verified
        self.hmac_var = tk.StringVar(value="—")

        # stores the encryption mode shown with the selected message
        self.detail_mode_var = tk.StringVar(value="AES-128")

        self._configure_style()
        self._build_shell()

    # creates the dark color theme used throughout the gui
    def _configure_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Panel.TFrame", background=COLORS["panel"], relief="solid", borderwidth=1)
        style.configure("TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Arial", 10))
        style.configure("Header.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Arial", 17, "bold"))
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Arial", 9))
        style.configure("Section.TLabel", background=COLORS["panel_alt"], foreground=COLORS["text"], font=("Arial", 10, "bold"), padding=(8, 7))
        style.configure("TButton", font=("Arial", 10), padding=(10, 7))
        style.configure("Accent.TButton", background=COLORS["accent"], foreground="white")
        style.map("Accent.TButton", background=[("active", "#3f6cb4"), ("disabled", "#212d40")])
        style.configure("Danger.TButton", background=COLORS["panel_alt"], foreground=COLORS["error"])
        style.configure("TRadiobutton", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("TEntry", fieldbackground=COLORS["bg"], foreground=COLORS["text"], insertcolor=COLORS["text"])

    # creates the main header and three-column window layout
    def _build_shell(self) -> None:

        # creates the top bar containing the application title and connection status
        header = ttk.Frame(self.root, style="Panel.TFrame", padding=14)
        header.pack(fill="x", padx=8, pady=(8, 4))

        # groups the application name and client or server role
        title = ttk.Frame(header, style="Panel.TFrame")
        title.pack(side="left")
        ttk.Label(title, text="Secure Messenger", style="Header.TLabel").pack(anchor="w")
        ttk.Label(title, text=f"Encrypted Client–Server Communication · {self.role}", style="Muted.TLabel").pack(anchor="w")

        # groups the status heading and its colored value
        status = ttk.Frame(header, style="Panel.TFrame")
        status.pack(side="right")
        ttk.Label(status, text="STATUS", style="Muted.TLabel").pack(anchor="e")
        self.status_label = ttk.Label(status, textvariable=self.status_var, font=("Arial", 11, "bold"))
        self.status_label.pack(anchor="e")

        # creates the main area containing the settings, chat, and technical panels
        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True, padx=8, pady=4)
        body.columnconfigure(0, minsize=255)
        body.columnconfigure(1, weight=1)
        body.columnconfigure(2, minsize=320)
        body.rowconfigure(0, weight=1)

        # reserves the left column for connection and security controls
        self.left = ttk.Frame(body, style="Panel.TFrame")
        self.left.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        # reserves the center column for conversation history and message entry
        self.center = ttk.Frame(body, style="Panel.TFrame")
        self.center.grid(row=0, column=1, sticky="nsew", padx=5)

        # reserves the right column for plaintext, ciphertext, and activity logs
        self.right = ttk.Frame(body, style="Panel.TFrame")
        self.right.grid(row=0, column=2, sticky="nsew", padx=(5, 0))

        self._build_conversation()
        self._build_details()

    # creates the conversation history and message-entry area
    def _build_conversation(self) -> None:
        ttk.Label(self.center, text="CONVERSATION", style="Section.TLabel").pack(fill="x")

        # creates a read-only history box for sent and received messages
        self.conversation = tk.Text(
            self.center,
            bg=COLORS["bg"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            wrap="word",
            font=("Arial", 10),
            padx=12,
            pady=12,
            state="disabled",
        )

        self.conversation.pack(fill="both", expand=True, padx=10, pady=10)
        self.conversation.tag_configure("sent", foreground="#a9c8f2", spacing1=8, spacing3=8)
        self.conversation.tag_configure("received", foreground="#dbeafe", spacing1=8, spacing3=8)
        self.conversation.tag_configure("system", foreground=COLORS["muted"], spacing1=6, spacing3=6)

        # creates the area where the user types messages and chooses attachments
        composer = ttk.Frame(self.center, style="Panel.TFrame", padding=10)
        composer.pack(fill="x")
        ttk.Label(composer, text="Message").pack(anchor="w")

        # creates the editable box used to type a new text message
        self.message_box = tk.Text(
            composer,
            height=4,
            bg=COLORS["bg"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="solid",
            borderwidth=1,
            wrap="word",
            font=("Arial", 10),
        )

        self.message_box.pack(fill="x", pady=(4, 8))

        # provides a shared row for the client or server send buttons
        self.button_row = ttk.Frame(composer, style="Panel.TFrame")
        self.button_row.pack(fill="x")

    # creates the plaintext, ciphertext, and activity-log panel
    def _build_details(self) -> None:
        ttk.Label(self.right, text="PLAINTEXT / CIPHERTEXT", style="Section.TLabel").pack(fill="x")

        # groups the message metadata, plaintext, ciphertext, and log boxes
        box = ttk.Frame(self.right, style="Panel.TFrame", padding=10)
        box.pack(fill="both", expand=True)

        info = ttk.Frame(box, style="Panel.TFrame")
        info.pack(fill="x")

        # defines the message metadata displayed above the plaintext box
        fields = [
            ("Message type:", self.message_type_var),
            ("Encryption mode:", self.detail_mode_var),
            ("Filename:", self.filename_var),
            ("HMAC-SHA256:", self.hmac_var),
        ]

        for row, (label, variable) in enumerate(fields):
            ttk.Label(info, text=label).grid(row=row, column=0, sticky="w")
            ttk.Label(info, textvariable=variable).grid(row=row, column=1, sticky="e")
        info.columnconfigure(1, weight=1)

        ttk.Label(box, text="Plaintext").pack(anchor="w", pady=(12, 4))

        # displays the readable message or a description of received binary data
        self.plaintext_box = self._detail_text(box, 7)
        ttk.Label(box, text="Ciphertext (Base64)").pack(anchor="w", pady=(12, 4))

        # displays a shortened base64 ciphertext preview
        self.ciphertext_box = self._detail_text(box, 9)
        ttk.Label(box, text="Activity & Error Log").pack(anchor="w", pady=(12, 4))

        # displays connection, security, transfer, and error events
        self.log_box = self._detail_text(box, 12)
        self.log_box.tag_configure("info", foreground="#7ea6dd")
        self.log_box.tag_configure("success", foreground=COLORS["success"])
        self.log_box.tag_configure("warning", foreground=COLORS["warning"])
        self.log_box.tag_configure("error", foreground=COLORS["error"])

    # creates a read-only text box for technical information
    def _detail_text(self, parent: ttk.Frame, height: int) -> tk.Text:
        widget = tk.Text(
            parent,
            height=height,
            bg=COLORS["bg"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="solid",
            borderwidth=1,
            wrap="word",
            font=("Courier New", 9),
            state="disabled",
        )

        widget.pack(fill="both", expand=False)
        return widget

    # converts the gui encryption label into the mode used by encryption.py
    def selected_mode(self) -> str:

        # converts the gui label into the mode values expected by encryption.py
        return "1" if self.mode_var.get() == "DES-56" else "2"

    # opens a file-selection window for the selected message type
    def choose_file(self, message_type: str) -> str:

        # limits each attachment dialog to the file types expected by that button
        options = {
            "IMAGE": [("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"), ("All files", "*.*")],
            "AUDIO": [("Audio files", "*.wav *.mp3 *.m4a *.aac"), ("All files", "*.*")],
            "FILE": [("All files", "*.*")]
        }

        return filedialog.askopenfilename(title=f"Select {message_type.lower()}", filetypes=options[message_type])

    # adds sent or received message to the conversation history
    def append_conversation(self, direction: str, peer: str, message_type: str, content: str) -> None:
        # creates the time shown beside each message or log entry
        timestamp = datetime.now().strftime("%H:%M:%S")

        # combines the message metadata and content into one conversation entry
        value = f"[{timestamp}] {peer} · {message_type} · {self.mode_var.get()}\n{content}\n"
        self.conversation.configure(state="normal")
        self.conversation.insert("end", value, direction)
        self.conversation.configure(state="disabled")
        self.conversation.see("end")

    def _ciphertext_preview(self, ciphertext: str, maximum_length: int = 2000) -> str:

        # displays only part of large ciphertext values in the gui
        if len(ciphertext) <= maximum_length:
            return ciphertext

        # calculates how much ciphertext is hidden from the interface preview
        hidden_characters = len(ciphertext) - maximum_length

        return (
                ciphertext[:maximum_length]
                + f"\n\n... {hidden_characters:,} additional characters hidden ..."
                + "\n\nfull ciphertext was still transmitted"
        )

    # updates the technical panel with the selected message information
    def update_details(self, message_type: str, filename: str | None, plaintext: str, ciphertext: str, hmac_status: str) -> None:
        self.message_type_var.set(message_type)
        self.filename_var.set(filename or "n/a")
        self.hmac_var.set(hmac_status)
        self.detail_mode_var.set(self.mode_var.get())

        # replaces the old plaintext display with the selected message content
        self._replace(self.plaintext_box, plaintext)

        # replaces the old ciphertext display with the selected message preview
        self._replace(self.ciphertext_box, ciphertext)

    # replaces the contents of a read-only text widget
    @staticmethod
    def _replace(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    # writes a timestamped message to the activity and error log
    def log(self, level: str, message: str) -> None:

        # creates the time shown beside each message or log entry
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{timestamp} [{level.upper()}] {message}\n", level)
        self.log_box.configure(state="disabled")
        self.log_box.see("end")

    # updates the connection-status text and color
    def set_status(self, text: str, color: str) -> None:
        self.status_var.set(text)
        self.status_label.configure(foreground=color)

    # creates a readable plaintext description for a binary file
    def file_plaintext_label(self, path: str, message_type: str) -> str:

        # reads the file size so the gui can describe the binary plaintext
        size = os.path.getsize(path)
        return f"<binary {message_type.lower()} data — {size:,} bytes>"