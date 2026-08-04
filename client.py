from encryption import protect_message, open_message
from message_format import create_text_message, create_file_message, parse_message
from msg_handler import send_data, receive_data
import socket


HOST = "127.0.0.1"
PORT = 5001


def start_client() -> None:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    password = input("enter shared password: ")

    #ask client user which encryption mode to use
    print("choose encryption mode: ")
    print("1. des-56")
    print("2. aes-128")

    mode = input("selection: ").strip()

    # stops program id selection is invalid
    if mode not in ("1", "2"):
        print("invalid mode")
        return

    try:
        client_socket.connect((HOST, PORT))
        print(f"connected to the server at {HOST}:{PORT}")
        print("type 'exit' to close the connection.")

        while True:
            print("\nchoose message type:")
            print("1. text")
            print("2. image")
            print("3. audio")
            print("4. general file")
            print("5. exit")

            message_type = input("selection: ").strip()

            if message_type == "1":
                # creates a text json message
                text = input("client: ")
                message_json = create_text_message(text)

            elif message_type == "2":
                # creates an image json message
                file_path = input("enter image path: ").strip()
                message_json = create_file_message(file_path, "IMAGE")

            elif message_type == "3":
                # creates an audio json message
                file_path = input("enter audio path: ").strip()
                message_json = create_file_message(file_path, "AUDIO")

            elif message_type == "4":
                # creates a general file json message
                file_path = input("enter file path: ").strip()
                message_json = create_file_message(file_path, "FILE")

            elif message_type == "5":
                # sends an exit text message before closing
                message_json = create_text_message("exit")

            else:
                print("invalid message selection")
                continue

            # encrypts and authenticates playtext message
            protected_message = protect_message(message_json, password, mode)

            # separates ciphertext for display
            encrypted_message = protected_message.rsplit("|", 1)[0]

            # displays ciphertext
            print(f"ciphertext sent: {encrypted_message}")

            # sends ciphertext and hmac tag message using length of header
            send_data(client_socket, protected_message.encode("utf-8"))

            if message_type.lower() == "5":
                print("closing connection...")
                break

            # receives one complete encrypted response
            received_data = receive_data(client_socket)

            # converts received bytes into a text
            protected_response = received_data.decode("utf-8")

            # verifies hmac and decrypts server's response
            response_json, encrypted_response = open_message(protected_response, password, mode)

            # converts json response into a dictionary
            response_message = parse_message(response_json)

            print(f"ciphertext received: {encrypted_response}")

            if response_message["type"] == "TEXT":
                # displays server text response
                response_text = response_message["data"]
                print(f"server: {response_text}")

            if response_text.lower() in ("quit", "exit"):
                print("the server closed the connection.")
                break
        else:
            print(f"received unexpected response type: {response_message['type']}")

    except ConnectionRefusedError:
        print("could not connect to the server.")
        print("make sure server.py is running first.")

    except ConnectionError:
        # handles the server closing the connection
        print("the server closed the connection")

    except ValueError as error:
        # handles incorrect passwords or modified messages
        print(f"security error: {error}")

    except KeyboardInterrupt:
        print("\nclient stopped.")

    finally:
        client_socket.close()


if __name__ == "__main__":
    start_client()