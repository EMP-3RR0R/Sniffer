from utils import parse_arguments, list_interfaces
from sniffer import start_sniffer

if __name__ == "__main__":
    args = parse_arguments()
    if args.interface == "list":
        list_interfaces()
    else:
        start_sniffer(args.interface)