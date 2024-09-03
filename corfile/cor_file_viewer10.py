"""
This tool was created by tatarize in 2023. 
It reads in the correction file of a LMC based fibre laser and displays the displacement map
"""

import argparse
import math
import os
import struct
import sys

import matplotlib.pyplot as plt
import numpy

APPLICATION_NAME = "Cor Tools"
APPLICATION_VERSION = "0.0.7"

COR_V1 = b"LMC1COR_1.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
COR_V2 = b"JCZ_COR_2_1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

parser = argparse.ArgumentParser()
parser.add_argument(
    "-V", "--version", action="store_true", help="Display cor tools version"
)
parser.add_argument("input", nargs="*", type=str, help="input file(s), either a valid .cor-file or a pcap recording")
parser.add_argument("-v", "--vert", action="store_true", help="rotate display by 90°")
parser.add_argument("-w", "--write", action="store_true", help="write an empty corfile")
# parser.add_argument("-w", "--write", action="store_true", help="write an empty corfile")
parser.add_argument(
    "-c",
    "--computer",
    help="Specify the computer-type for pcap analysis (intel, mac, m1). (default intel)",
    default="intel",
)
parser.add_argument(
    "-l",
    "--lens",
    help="specify the lens-size in mm for the output. (default 150)",
    default="150",
)


def parse_pcap_packet(packet):
    """ parse pcap data (depending on the machine origin) """
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
        print(f"{filename} .cor file creator listed as: {label} ({len(label)} bytes)")
        if label[:12] == COR_V1[:12]:
            version = 1
        elif label[:12] == COR_V2[:12]:
            version = 2
        else:
            print("Unsupported format")
            return None, None, None
        ct = 0
        if version == 1:
            print (f"Version 1")
            header = f.read(2)
            print(f"Unknown Header remaining: {header.hex(sep=' ', bytes_per_sep=2)}")
            scale = struct.unpack("63d", f.read(0x1F8))[43]
            print(f"Scale according to file : {scale:.3f} - lens-size={65536.0 / scale:.1f}mm")
            for j in range(65):
                for k in range(65):
                    dx = int(round(struct.unpack("d", f.read(8))[0]))
                    dx = dx if dx >= 0 else -dx + 0x8000
                    dy = int(round(struct.unpack("d", f.read(8))[0]))
                    dy = dy if dy >= 0 else -dy + 0x8000
                    dx = dx & 0xFFFF
                    dy = dy & 0xFFFF
                    x_list.append(dx)
                    y_list.append(dy)
                    ct += 2
        if version == 2:
            print (f"Version 2")
            header = f.read(6)
            print(f"Unknown Header remaining: {header.hex(sep=' ', bytes_per_sep=2)}")
            scalebytes = f.read(8)
            scale = struct.unpack("d", scalebytes)[0]
            print(f"Scale according to file : {scale:.3f} - lens-size={65536.0 / scale:.1f}mm")
            # print (f"To float from {scalebytes.hex(sep=' ', bytes_per_sep=2)}: {struct.unpack('d', scalebytes)}, float={scale}")
            for j in range(65):
                s = f"{j:2d}:"
                for k in range(65):
                    dx = int.from_bytes(f.read(4), "little", signed=True)
                    # dx = dx if dx >= 0 else -dx + 0x8000
                    dy = int.from_bytes(f.read(4), "little", signed=True)
                    # dy = dy if dy >= 0 else -dy + 0x8000
                    x_list.append(-dx)
                    y_list.append(-dy)
                    ct += 2
                    # s += f" ({dx:.0f},{dy:.0f})"
                # print (s)
        # remaining = f.read(256)
        print(f"Entries read            : {ct}")

    return _fancy_table(x_list, y_list)


def write_ideal_cor_file(filename, lens_size):
    ct = 0
    lines = []
    # Scale is arbitrary?!
    scale = 65536 / lens_size
    print(f"Scale: {scale:.3f} - lens-size={lens_size:.1f}mm")

    # scale = float(0x6666)
    for lidx in range(65):
        data = []
        for cidx in range(65):
            dx = 0
            dy = 0
            data.append((dx, dy))
        lines.append(data)
    # So let's write a testfile...
    with open(filename, "wb") as f:
        r = f.write(COR_V2)
        # print(f"Label written: {r} bytes")
        header = [0] * 6
        r = f.write(bytearray(header))
        # print(f"Header written: {r} bytes")
        r = f.write(struct.pack("d", scale))

        # print(f"Scale written: {r} bytes")
        for data in lines:
            for dx, dy in data:
                f.write(int(dx).to_bytes(4, "little", signed=True))
                f.write(int(dy).to_bytes(4, "little", signed=True))
                ct += 2
        r = f.write(bytearray([0]*4))
        # print (f"Trailer written: {r} bytes")
    print(f"Corfile written: {filename}, entries={ct}, scale={scale:.3f}")


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

    print (
        f"min-x,y                 : {min_x}, {min_y}\n" + 
        f"max x,y                 : {max_x}, {max_y}\n" +
        f"range-xy                : {range_x}, {range_y}\n" +
        f"scale-xy                : {x_scale:03f}, {y_scale:03f}"
    )
    # ax = []
    # ay = []
    # ax.append(j * 1024 - dx)
    # ay.append(k * 1024 - dy)
    # print(
    #     f"absolute-end-positions: min-ax,ay values: {min(ax)} {min(ay)}. max ax,ay values: {max(ax)} {max(ay)}"
    # )
    print ("")

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
        r, g, b = c
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
    if args.write:
        lens_size = 150.0
        if args.lens:
            try:
                ls = float(args.lens)
                if ls > 0:
                    lens_size = ls
            except ValueError:
                pass
        
        write_ideal_cor_file("test.cor", lens_size)
        return
    count = len(args.input)
    if not count:
        print("No files were requested to be viewed.")
        return

    # print(args.input)
    if args.vert:
        fig, ax = plt.subplots(count, 1)
    else:
        fig, ax = plt.subplots(1, count)
    for i, filename in enumerate(args.input):
        if not os.path.exists(filename):
            print(f"File {filename} does not exist.")
            continue
        if filename.endswith(".pcap"):
            u, v, c = _read_table_from_pcap(filename)
        else:
            u, v, c = _read_correction_file(filename)
        if u is None:
            # Unknown format
            continue
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
