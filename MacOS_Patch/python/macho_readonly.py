import argparse
import bisect
import json
import struct
from pathlib import Path


def inspect_layout(path):
    with path.open("rb") as stream:
        header = stream.read(32)
        if len(header) != 32 or struct.unpack_from("<I", header)[0] != 0xFEEDFACF:
            raise ValueError("需要小端 64 位 Mach-O 文件")
        command_count, command_size = struct.unpack_from("<II", header, 16)
        if command_size > 10 * 1024 * 1024:
            raise ValueError("加载命令尺寸超出分析上限")
        commands = stream.read(command_size)
        segments = []
        sections = []
        starts_info = None
        offset = 0
        for _ in range(command_count):
            command, size = struct.unpack_from("<II", commands, offset)
            if size < 8 or offset + size > len(commands):
                raise ValueError("加载命令边界无效")
            if command == 0x19:
                name = commands[offset + 8:offset + 24].split(b"\0")[0].decode("ascii")
                address, virtual_size, file_offset, file_size = struct.unpack_from("<QQQQ", commands, offset + 24)
                segments.append((name, address, virtual_size, file_offset, file_size))
                count = struct.unpack_from("<I", commands, offset + 64)[0]
                for index in range(count):
                    section = offset + 72 + index * 80
                    section_name = commands[section:section + 16].split(b"\0")[0].decode("ascii")
                    section_address, section_size, section_offset = struct.unpack_from("<QQI", commands, section + 32)
                    sections.append((section_name, section_address, section_size, section_offset))
            elif command == 0x26:
                starts_info = struct.unpack_from("<II", commands, offset + 8)
            offset += size
        if starts_info is None:
            raise ValueError("未发现 LC_FUNCTION_STARTS")
        base = next(segment[1] for segment in segments if segment[0] == "__TEXT")
        stream.seek(starts_info[0])
        address = base
        starts = []
        value = shift = 0
        for _ in range(starts_info[1]):
            raw = stream.read(1)
            if not raw:
                raise ValueError("函数起始表被截断")
            byte = raw[0]
            value |= (byte & 127) << shift
            if byte & 128:
                shift += 7
                if shift > 63:
                    raise ValueError("函数起始表整数过长")
                continue
            if value == 0:
                break
            address += value
            starts.append(address)
            value = shift = 0
    return segments, sections, starts


def file_offset_for(segments, address):
    for _, start, _, offset, size in segments:
        if start <= address < start + size:
            return offset + address - start
    raise ValueError("地址没有对应的文件数据")


def main():
    parser = argparse.ArgumentParser(description="只读解析 Mach-O 函数边界与指令")
    parser.add_argument("path", type=Path)
    parser.add_argument("--bounds", nargs="*", default=[])
    parser.add_argument("--disassemble")
    parser.add_argument("--callers")
    args = parser.parse_args()
    segments, sections, starts = inspect_layout(args.path)
    for value in args.bounds:
        address = int(value, 0)
        index = bisect.bisect_right(starts, address) - 1
        if index < 0 or index + 1 >= len(starts):
            raise ValueError("无法确定函数边界")
        print(json.dumps({"query": hex(address), "start": hex(starts[index]), "end_exclusive": hex(starts[index + 1]), "file_offset": hex(file_offset_for(segments, address))}))
    if args.disassemble:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        address = int(args.disassemble, 0)
        index = bisect.bisect_right(starts, address) - 1
        start, end = starts[index:index + 2]
        if end - start > 1024 * 1024:
            raise ValueError("单函数尺寸超出分析上限")
        with args.path.open("rb") as stream:
            stream.seek(file_offset_for(segments, start))
            data = stream.read(end - start)
        for instruction in Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(data, start):
            print(f"{instruction.address:08x} {instruction.bytes.hex()} {instruction.mnemonic} {instruction.op_str}")
    if args.callers:
        target = int(args.callers, 0)
        _, address, size, offset = next(section for section in sections if section[0] == "__text")
        with args.path.open("rb") as stream:
            stream.seek(offset)
            consumed = 0
            while consumed < size:
                data = stream.read(min(1024 * 1024, size - consumed))
                if not data:
                    raise ValueError("代码节被截断")
                for index in range(0, len(data) - 3, 4):
                    opcode = struct.unpack_from("<I", data, index)[0]
                    if opcode & 0x7C000000 != 0x14000000:
                        continue
                    displacement = opcode & 0x3FFFFFF
                    if displacement & 0x2000000:
                        displacement -= 0x4000000
                    source = address + consumed + index
                    if source + displacement * 4 == target:
                        function_index = bisect.bisect_right(starts, source) - 1
                        print(json.dumps({"source": hex(source), "function": hex(starts[function_index]), "kind": "bl" if opcode & 0x80000000 else "b"}))
                consumed += len(data)


if __name__ == "__main__":
    main()
