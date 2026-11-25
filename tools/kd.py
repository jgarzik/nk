#!/usr/bin/env python3
"""A kernel debugger that only ever says "go".

Windows booted with debugging enabled stops at a breakpoint and waits
for its debugger. The reference machine has nobody at a debugger, so the
oracle plays one over the machine's serial port, speaking just enough of
Windows' kernel-debugger serial protocol (KDCOM) to do what a person
would: acknowledge what the kernel reports, step over a hard-coded
breakpoint, and continue.

Packets. Every packet starts with a 16-byte header, little endian:

    leader     4 bytes, all 0x30 (a data packet) or all 0x69 (control)
    type       u16
    byte count u16   length of the data that follows the header
    id         u32
    checksum   u32   sum of the data bytes

A data packet's data is followed by one trailing byte, 0xAA. A control
packet (acknowledge, resend, reset) has no data and no trailer.

Each side numbers the data packets it sends; the low bit alternates,
and a packet is repeated until the other side acknowledges it with a
control packet carrying the same id.

When it loads a driver, the kernel asks its debugger whether it has a
file to use in the driver's place (type 11); this debugger answers that
it has not.

What the kernel sends that matters here: a state change (type 7) when it
stops, saying why. A newly loaded image's symbols: continue. An
exception: if it is a breakpoint, fetch the processor's context, move
its instruction pointer past the one-byte breakpoint instruction, store
it back, and continue (what a debugger does on "go" at a hard-coded
breakpoint; without it the breakpoint would be executed again for
ever); any other exception is left unhandled, as with no debugger.
"""

import struct

DATA_LEADER = b"\x30" * 4
CONTROL_LEADER = b"\x69" * 4
TRAILER = b"\xAA"

TYPE_STATE_MANIPULATE = 2
TYPE_DEBUG_IO = 3
TYPE_ACKNOWLEDGE = 4
TYPE_RESEND = 5
TYPE_RESET = 6
TYPE_STATE_CHANGE64 = 7
TYPE_FILE_IO = 11

INITIAL_ID = 0x80800000
SYNC_ID = 0x00000800

# State changes.
STATE_EXCEPTION = 0x3030
STATE_LOAD_SYMBOLS = 0x3031
# Manipulate APIs.
API_GET_CONTEXT = 0x3132
API_SET_CONTEXT = 0x3133
API_CONTINUE2 = 0x313C
# Debug I/O.
API_PRINT_STRING = 0x3230

STATUS_UNSUCCESSFUL = 0xC0000001
FILE_IO_SIZE = 64

STATUS_BREAKPOINT = 0x80000003
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

MANIPULATE_SIZE = 56
# x86-64 `CONTEXT`: where Rip is.
CONTEXT_RIP = 0xF8


def checksum(data):
    return sum(data) & 0xFFFFFFFF


def data_packet(kind, packet_id, data):
    header = struct.pack("<4sHHII", DATA_LEADER, kind, len(data), packet_id, checksum(data))
    return header + data + TRAILER


def control_packet(kind, packet_id=0):
    return struct.pack("<4sHHII", CONTROL_LEADER, kind, 0, packet_id, 0)


def manipulate(api, processor, body=b"", extra=b""):
    """A state-manipulate message: the fixed part, padded, then `extra`."""
    head = struct.pack("<IHHI4x", api, 0, processor, 0) + body
    return head.ljust(MANIPULATE_SIZE, b"\0") + extra


class Stream:
    """Cuts a byte stream into packets. `feed` returns the packets that
    are now complete, as (control?, type, id, data); a data packet whose
    checksum or trailer is wrong comes back with data None."""

    def __init__(self):
        self.buffer = b""

    def feed(self, received):
        self.buffer += received
        packets = []
        while True:
            # A header starts where four equal leader bytes are.
            starts = [i for i in (self.buffer.find(DATA_LEADER), self.buffer.find(CONTROL_LEADER))
                      if i >= 0]
            if not starts:
                # Keep a tail that may be the start of a leader.
                self.buffer = self.buffer[-3:]
                return packets
            self.buffer = self.buffer[min(starts):]
            if len(self.buffer) < 16:
                return packets
            leader, kind, count, packet_id, check = struct.unpack("<4sHHII", self.buffer[:16])
            if leader == CONTROL_LEADER:
                self.buffer = self.buffer[16:]
                packets.append((True, kind, packet_id, b""))
                continue
            if count > 0x4000:
                # Not a header after all: step past and look again.
                self.buffer = self.buffer[1:]
                continue
            if len(self.buffer) < 16 + count + 1:
                return packets
            data = self.buffer[16:16 + count]
            trailer = self.buffer[16 + count:16 + count + 1]
            self.buffer = self.buffer[16 + count + 1:]
            ok = trailer == TRAILER and checksum(data) == check
            packets.append((False, kind, packet_id, data if ok else None))


class Debugger:
    """The debugger's side of the conversation, free of any I/O: give it
    what arrived with `receive`, and send what it returns."""

    def __init__(self):
        self.stream = Stream()
        self.next_id = INITIAL_ID
        self.unacknowledged = None
        self.queue = []
        self.pending_continue = None
        self.breakpoints = []
        self.printed = []

    def _send(self, message, kind=TYPE_STATE_MANIPULATE):
        """Queue a message; returns the bytes to send now."""
        self.queue.append((kind, message))
        return self._pump()

    def _pump(self):
        if self.unacknowledged is None and self.queue:
            kind, message = self.queue.pop(0)
            self.unacknowledged = data_packet(kind, self.next_id, message)
            return self.unacknowledged
        return b""

    def receive(self, received):
        out = b""
        for control, kind, packet_id, data in self.stream.feed(received):
            if control:
                if kind == TYPE_ACKNOWLEDGE and self.unacknowledged is not None:
                    self.unacknowledged = None
                    self.next_id ^= 1
                    out += self._pump()
                elif kind == TYPE_RESEND and self.unacknowledged is not None:
                    out += self.unacknowledged
                elif kind == TYPE_RESET:
                    self.next_id = INITIAL_ID
                    self.unacknowledged = None
                    self.queue.clear()
                    out += control_packet(TYPE_RESET)
                continue
            if data is None:
                out += control_packet(TYPE_RESEND)
                continue
            out += control_packet(TYPE_ACKNOWLEDGE, packet_id & ~SYNC_ID)
            out += self._message(kind, data)
        return out

    def _message(self, kind, data):
        if kind == TYPE_DEBUG_IO:
            api, = struct.unpack_from("<I", data)
            if api == API_PRINT_STRING:
                self.printed.append(data[16:].decode(errors="replace"))
            return b""
        if kind == TYPE_FILE_IO:
            # When it loads a driver, the kernel asks its debugger
            # whether to use a file of the debugger's instead. This one
            # has none to offer.
            api, = struct.unpack_from("<I", data)
            reply = struct.pack("<II", api, STATUS_UNSUCCESSFUL).ljust(FILE_IO_SIZE, b"\0")
            return self._send(reply, TYPE_FILE_IO)
        if kind == TYPE_STATE_CHANGE64:
            state, _, processor = struct.unpack_from("<IHH", data)
            if state == STATE_EXCEPTION:
                code, = struct.unpack_from("<I", data, 0x20)
                address, = struct.unpack_from("<Q", data, 0x30)
                if code == STATUS_BREAKPOINT:
                    # Step over it: fetch the context first.
                    self.breakpoints.append(address)
                    self.pending_continue = processor
                    return self._send(manipulate(API_GET_CONTEXT, processor))
                return self._send(manipulate(API_CONTINUE2, processor,
                                             struct.pack("<I", DBG_EXCEPTION_NOT_HANDLED)))
            return self._send(manipulate(API_CONTINUE2, processor, struct.pack("<I", DBG_CONTINUE)))
        if kind == TYPE_STATE_MANIPULATE and self.pending_continue is not None:
            api, = struct.unpack_from("<I", data)
            processor = self.pending_continue
            if api == API_GET_CONTEXT:
                context = bytearray(data[MANIPULATE_SIZE:])
                rip, = struct.unpack_from("<Q", context, CONTEXT_RIP)
                struct.pack_into("<Q", context, CONTEXT_RIP, rip + 1)
                return self._send(manipulate(API_SET_CONTEXT, processor, extra=bytes(context)))
            if api == API_SET_CONTEXT:
                self.pending_continue = None
                return self._send(manipulate(API_CONTINUE2, processor,
                                             struct.pack("<I", DBG_CONTINUE)))
        return b""
