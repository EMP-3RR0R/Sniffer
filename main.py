from utils import parse_arguments
from sniffer import start_sniffer

if __name__ == "__main__":
    args = parse_arguments()
    start_sniffer(args.interface)