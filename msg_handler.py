import socket
import struct

HEADER_SIZE = 4

def send_data(sock: socket.socket, data: bytes) -> None:
    # converts the message length into a 4-byte header
    header = struct.pack("!I", len(data))

    # sends the header followed by the complete message
    sock.sendall(header + data)

def receive_exact(sock: socket.socket, size: int) -> bytes:
    # stores data until the complete message is received
    data = bytearray()

    while len(data) < size:
        packet = sock.recv(size - len(data))

        if not packet:
            raise ConnectionError("connection closed before all data was received")

        data.extend(packet)

    return bytes(data)

def receive_data(sock: socket.socket) -> bytes:
    # receives the 4-byte message-length header
    header = receive_exact(sock, HEADER_SIZE)
    message_length = struct.unpack("!I", header)[0]

    # receives the complete message body
    return receive_exact(sock, message_length)
