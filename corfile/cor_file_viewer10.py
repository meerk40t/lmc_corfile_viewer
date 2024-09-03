"""
This tool was created by tatarize in 2023
"""
import argparse
import math
import struct
import sys

import matplotlib.pyplot as plt
import numpy

APPLICATION_NAME = "Cor Tools"
APPLICATION_VERSION = "0.0.7"

parser = argparse.ArgumentParser()
parser.add_argument(
    "-V", "--version", action="store_true", help="Display cor tools version"
)
parser.add_argument("input", nargs="*", type=str, help="input file")
parser.add_argument("-v", "--vert", action="store_true")
parser.add_argument(
    "-c",
    "--computer",
    help="Specify the computer-type (intel, mac, m1). (default intel)",
    default="intel",
)


def parse_pcap_packet(packet):
    if args.computer == "intel":
        data = packet[27:]
        endpoint = packet[21] & 0x7F
        direction = packet[21] & 0xF0
        return endpoint, direction, data
    elif args.computer == "mac":
        data = packet[32:]
        endpoint = packet[30] & 0x7F
        direction = packet[30] & 0xF0
        return endpoint, direction, data
    else:  # M1
        data = packet[40:]
        endpoint = packet[30] & 0x7F
        direction = packet[30] & 0xF0
        return endpoint, direction, data


def _read_table_from_pcap(filename):
    """
    Reads a core file from a saved pcap.

    :param filename:
    :return:
    """
    x_list = []
    y_list = []
    import dpkt

    with open(filename, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            endpoint, direction, data = parse_pcap_packet(buf)
            if endpoint != 2:
                continue
            if direction != 0:
                continue
            if len(data) != 12:
                continue
            if data[0:2] != b"\x10\x00":
                continue
            x = struct.unpack("<H", data[2:4])[0]
            y = struct.unpack("<H", data[4:6])[0]
            if x >= 0x8000:
                x = 0x8000 - x
            if y >= 0x8000:
                y = 0x8000 - y
            x_list.append(x)
            y_list.append(y)
    return _fancy_table(x_list, y_list)


def _read_correction_file(filename):
    """
    Reads a standard .cor file and builds a table from that.

    @param filename:
    @return:
    """
    x_list = []
    y_list = []

    with open(filename, "rb") as f:
        label = f.read(0x16)
        print(f"{filename} .cor file creator listed as: {label}")
        header = f.read(0xE)
        print("Unknown Header remaining:")
        print(header.hex(sep=" ", bytes_per_sep=2))
        for j in range(65):
            for k in range(65):
                dx = int.from_bytes(f.read(4), "little", signed=True)
                # dx = dx if dx >= 0 else -dx + 0x8000
                dy = int.from_bytes(f.read(4), "little", signed=True)
                # dy = dy if dy >= 0 else -dy + 0x8000
                x_list.append(-dx)
                y_list.append(-dy)

    return _fancy_table(x_list, y_list)


def _fancy_table(x_list, y_list):
    """
    Provides info and generic whistles to data from either cor file or pcap data.

    :param x_list:
    :param y_list:
    :return:
    """
    min_x = min(x_list)
    min_y = min(y_list)
    max_x = max(x_list)
    max_y = max(y_list)

    range_x = max_x - min_x
    range_y = max_y - min_y
    if range_y == 0:
        range_y = 1
    if range_x == 0:
        range_x = 1
    x_scale = 255.0 / range_x
    y_scale = 255.0 / range_y
    distances = [abs(complex(x_list[i], y_list[i])) for i in range(len(x_list))]
    max_distance = max(distances)
    min_distance = min(distances)
    try:
        dist_scale = 1.0 / (max_distance - min_distance)
    except ZeroDivisionError:
        dist_scale = 1.0

    def normalize_distance(x, y):
        return (abs(complex(x, y)) - min_distance) * dist_scale

    print(
        f"min-x,y: {min_x} {min_y}. max x,y: {max_x} {max_y}. range-xy={range_x},{range_y} sxy: {x_scale:03f},{y_scale:03f}"
    )
    # ax = []
    # ay = []
    # ax.append(j * 1024 - dx)
    # ay.append(k * 1024 - dy)
    # print(
    #     f"absolute-end-positions: min-ax,ay values: {min(ax)} {min(ay)}. max ax,ay values: {max(ax)} {max(ay)}"
    # )
    print("")

    from matplotlib import colors

    colors = [
        colors.hsv_to_rgb(
            (
                math.atan2(y_list[i], x_list[i]) / math.tau,
                normalize_distance(x_list[i], x_list[i]),
                0.5,
            )
        )
        for i in range(len(y_list))
    ]
    for c in colors:
        r,g,b = c
        c[0] = abs(r)
        if c[0] > 1.0:
            c[0] = 1.0
        c[1] = abs(g)
        if c[1] > 1.0:
            c[1] = 1.0
        c[2] = abs(b)
        if c[2] > 1.0:
            c[2] = 1.0

    return (
        x_list,
        y_list,
        colors,
    )


argv = sys.argv[1:]
args = parser.parse_args(argv)


def run():
    if args.version:
        print("%s %s" % (APPLICATION_NAME, APPLICATION_VERSION))
        return

    print(args.input)
    count = len(args.input)
    if not count:
        print("No files were requested to be viewed.")
        return
    if args.vert:
        fig, ax = plt.subplots(count, 1)
    else:
        fig, ax = plt.subplots(1, count)
    for i, filename in enumerate(args.input):
        if filename.endswith(".pcap"):
            u, v, c = _read_table_from_pcap(filename)
        else:
            u, v, c = _read_correction_file(filename)

        x, y = numpy.mgrid[0:65, 0:65]
        if count > 1:
            ax[i].quiver(x, y, u, v, color=c)
        else:
            ax.quiver(x, y, u, v, color=c)

    plt.tight_layout()

    plt.show()
    plt.close()


if __name__ == "__main__":
    sys.exit(run())
