import struct


def send_msg(socket, data):
    # Prefix each message with a 4-byte length (network byte order)
    size_header = len(data).to_bytes(4, 'big')
    socket.sendall(size_header)

    # Send the actual data
    socket.sendall(data)

def recv_msg(socket):
    # Receive the size of incoming packets (assuming a 4-byte header
    packet_size_header = recv_all(socket, 4)

    if not packet_size_header:
        return None

    # Convert the packet size to an integer
    packet_size = int.from_bytes(packet_size_header, 'big')

    #Receive the actual packet data
    packet_data = recv_all(socket, packet_size)

    return packet_data

def recv_all(socket, size):
    # Helper function to recieve all bytes of a given size
    data = b''
    while len(data) < size:
        packet = socket.recv(size - len(data))
        if not packet:
            raise ConnectionError("Connection closed by the other end")
        data += packet
    return data