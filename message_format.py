import base64
import json
import os
from pathlib import Path


VALID_MESSAGE_TYPES = {"TEXT", "IMAGE", "AUDIO", "FILE"}
MAX_FILE_SIZE = 10 * 1024 * 1024


def create_text_message(text: str) -> str:
    # creates a json message containing plaintext
    message = {
        "type": "TEXT",
        "filename": None,
        "data": text,
    }

    # converts the dictionary into a json string
    return json.dumps(message)


def create_file_message(
        file_path: str,
        message_type: str,
) -> str:
    # converts the selected type to uppercase
    message_type = message_type.upper()

    # verifies that the message type is supported
    if message_type not in {"IMAGE", "AUDIO", "FILE"}:
        raise ValueError("invalid file message type")

    path = Path(file_path)

    # verifies that the selected file exists
    if not path.is_file():
        raise FileNotFoundError("the selected file does not exist")

    # prevents extremely large files from being loaded into memory
    file_size = path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        raise ValueError("the selected file is larger than 10 mb")

    # reads the selected file as binary bytes
    with path.open("rb") as file:
        file_data = file.read()

    # converts the binary data into base64 text for json
    encoded_data = base64.b64encode(file_data).decode("utf-8")

    message = {
        "type": message_type,
        "filename": path.name,
        "data": encoded_data,
    }

    # converts the dictionary into a json string
    return json.dumps(message)


def parse_message(message_json: str) -> dict:
    # converts the received json string into a dictionary
    try:
        message = json.loads(message_json)
    except json.JSONDecodeError as error:
        raise ValueError("received message is not valid json") from error

    # verifies that all required fields are present
    required_fields = {"type", "filename", "data"}

    if not required_fields.issubset(message):
        raise ValueError("received message is missing required fields")

    message_type = message["type"]

    # verifies that the message type is supported
    if message_type not in VALID_MESSAGE_TYPES:
        raise ValueError("received an unsupported message type")

    return message


def save_received_file(
        message: dict,
        output_directory: str = "received_files",
) -> str:
    message_type = message["type"]

    # prevents text messages from being saved as files
    if message_type == "TEXT":
        raise ValueError("text messages cannot be saved as files")

    filename = message.get("filename")

    if not filename:
        raise ValueError("received file does not have a filename")

    # removes directory information from the received filename
    safe_filename = os.path.basename(filename)

    # creates the received-files folder when it does not exist
    os.makedirs(output_directory, exist_ok=True)

    output_path = os.path.join(
        output_directory,
        safe_filename,
    )

    # converts the base64 text back into binary bytes
    try:
        file_data = base64.b64decode(
            message["data"],
            validate=True,
        )
    except (ValueError, TypeError) as error:
        raise ValueError("received file data is invalid") from error

    # saves the recovered binary file
    with open(output_path, "wb") as file:
        file.write(file_data)

    return output_path

if __name__ == "__main__":
    test_files = [
        ("test_files/images/test_image_waterfull.png", "IMAGE"),
        ("test_files/audio/v2_owo.m4a", "AUDIO"),
        ("test_files/general/test_data.json", "FILE"),
        ("test_files/general/test_table.csv", "FILE"),
        ("test_files/general/test_binary.bin", "FILE"),
    ]

    for file_path, message_type in test_files:
        print(f"\ntesting: {file_path}")

        # creates and parses the file message
        file_json = create_file_message(
            file_path,
            message_type,
        )
        parsed_file = parse_message(file_json)

        # recreates the file in received_files
        saved_path = save_received_file(parsed_file)

        print("type:", parsed_file["type"])
        print("filename:", parsed_file["filename"])
        print("saved to:", saved_path)