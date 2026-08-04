from encryption import protect_message, open_message
from message_format import create_text_message, parse_message, save_received_file
from msg_handler import send_data, receive_data
import socket

HOST = "0.0.0.0"
PORT = 5001

def start_server() -> None:
    password = input("enter shared password: ")

    # ask server user which encryption mode to use
    print("choose encryption mode: ")
    print("1. des-56")
    print("2. aes-128")

    mode = input("selection mode: ").strip()

    # stops program if selection is invalid
    if mode not in ("1", "2"):
        print("invalid mode")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # allows the server to restart without waiting for the port to be released
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"server is listening on port {PORT}")
    print("waiting for a connection...")

    client_socket, client_address = server_socket.accept()

    print(f"connected to {client_address[0]}:{client_address[1]}")

    try:
        while True:
            # receives one complete encrypted message
            received_data = receive_data(client_socket)

            if not received_data:
                print("connection closed")
                break

            # converts received bytes to text
            protected_message = received_data.decode("utf-8")

            # verifies hmac and decrypts message
            message_json, encrypted_message = open_message(protected_message, password, mode)

            # converts json string into a dictionary
            message = parse_message(message_json)

            print(f"cipher message: {encrypted_message}")

            message_type = message["type"]

            if message_type == "TEXT":
                # display received message
                text = message["data"]
                print(f"client text: {text}")

                if text.lower() in ("quit", "exit"):
                    print("the client closed the connection")
                    break

            else:
                # saves received image, audio recording, or file
                saved_path = save_received_file(message)

                print(f"received type: {message_type}")
                print(f"received filename: {message['filename']}")
                print(f"saved to: {saved_path}")

            # asks the server user for response
            response = input("server: ")

            # creates a json text response
            response_json = create_text_message(response)

            # encrypts and authenticates response
            protected_response = protect_message(response_json, password, mode)

            # separates the ciphertext for display
            encrypted_response = protected_response.rsplit("|", 1)[0]

            print(f"cipher sent: {encrypted_response}")

            # sends ciphertext and authentication tag
            send_data(client_socket, protected_response.encode("utf-8"))

            # closes when server sends quit or exit
            if response.lower() in ("quit", "exit"):
                print("closing connection...")
                break

    except ConnectionResetError:
        print("the client unexpectedly disconnected")

    except ConnectionError:
        # handles a client that closes the connection normally
        print("the client closed the connection")

    except FileNotFoundError as error:
        # handles a missing selected file
        print(f"file error: {error}")

    except PermissionError:
        # handles a file that cannot be read or written
        print("file error: permission was denied")

    except ValueError as error:
        # handles incorrect passwords or modified messages
        print(f"security error: {error}")

    except KeyboardInterrupt:
        print("\nserver stopped")

    finally:
        client_socket.close()
        server_socket.close()

if __name__ == "__main__":
    start_server()