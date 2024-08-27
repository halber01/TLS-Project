import time
from kemTLS_halber.client import perform_handshake


def main():
    total_time = 0
    successful_handshakes = 0
    num_handshakes = 1000

    for _ in range(num_handshakes):
        start_time = time.time()
        perform_handshake()
        end_time = time.time()
        total_time += (end_time - start_time)
        successful_handshakes += 1

    if successful_handshakes > 0:
        average_time = total_time / successful_handshakes
        print(f"Average time for {successful_handshakes} successful handshakes: {average_time:.4f} seconds")
    else:
        print("No successful handshakes")


if __name__ == "__main__":
    main()