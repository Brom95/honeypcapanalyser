import argparse
from pcapfile import savefile
import os


def get_pcaps_list(path):
    if os.path.isdir(path):
        result = []
        for file in os.listdir(path):
            if os.path.isfile(
                os.path.join(path, file)
            ) and "pcap" in os.path.splitext(
                os.path.join(path, file)
            )[1]:
                result.append(os.path.join(path, file))
    elif os.path.isfile(path):
        result.append(path)
    return result


def main(args):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create simple honeypot report from pcap files')
    parser.add_argument('-i', "--input", help="pcap file or dirrectory with files", required=True)
    args = parser.parse_args()
    main(args)
