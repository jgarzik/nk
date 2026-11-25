"""Checks on tools/kd.py, the debugger that says go. Run by `make test`."""

import struct
import unittest

import kd


def state_change(state, processor=0, code=0, address=0):
    data = bytearray(240)
    struct.pack_into("<IHH", data, 0, state, 0, processor)
    struct.pack_into("<I", data, 0x20, code)
    struct.pack_into("<Q", data, 0x30, address)
    return bytes(data)


def sent(raw):
    """The packets in what the debugger sent, as Stream sees them."""
    return kd.Stream().feed(raw)


class Packets(unittest.TestCase):
    def test_a_data_packet_survives_the_wire(self):
        packet = kd.data_packet(7, 0x80800001, b"hello")
        self.assertEqual(len(packet), 16 + 5 + 1)
        self.assertEqual(sent(packet), [(False, 7, 0x80800001, b"hello")])
        # In pieces, and with noise in front.
        stream = kd.Stream()
        self.assertEqual(stream.feed(b"\x00\x30junk" + packet[:9]), [])
        self.assertEqual(stream.feed(packet[9:]), [(False, 7, 0x80800001, b"hello")])

    def test_a_damaged_packet_is_noticed(self):
        packet = bytearray(kd.data_packet(7, 1, b"hello"))
        packet[17] ^= 1
        self.assertEqual(sent(bytes(packet)), [(False, 7, 1, None)])
        bad_trailer = kd.data_packet(7, 1, b"hello")[:-1] + b"\x00"
        self.assertEqual(sent(bad_trailer), [(False, 7, 1, None)])

    def test_control_packets_have_no_data(self):
        packet = kd.control_packet(kd.TYPE_ACKNOWLEDGE, 0x80800000)
        self.assertEqual(len(packet), 16)
        self.assertEqual(sent(packet + packet),
                         [(True, kd.TYPE_ACKNOWLEDGE, 0x80800000, b"")] * 2)


class Conversation(unittest.TestCase):
    def kernel_says(self, debugger, kind, packet_id, data):
        return sent(debugger.receive(kd.data_packet(kind, packet_id, data)))

    def ack(self, debugger):
        return sent(debugger.receive(kd.control_packet(kd.TYPE_ACKNOWLEDGE)))

    def test_a_loaded_image_is_acknowledged_and_continued(self):
        debugger = kd.Debugger()
        out = self.kernel_says(debugger, kd.TYPE_STATE_CHANGE64, kd.INITIAL_ID | kd.SYNC_ID,
                               state_change(kd.STATE_LOAD_SYMBOLS, processor=2))
        # The acknowledgement carries the id without the sync bit.
        self.assertEqual(out[0], (True, kd.TYPE_ACKNOWLEDGE, kd.INITIAL_ID, b""))
        control, kind, packet_id, data = out[1]
        self.assertEqual((control, kind, packet_id), (False, kd.TYPE_STATE_MANIPULATE, kd.INITIAL_ID))
        self.assertEqual(len(data), kd.MANIPULATE_SIZE)
        api, _, processor = struct.unpack_from("<IHH", data)
        status, = struct.unpack_from("<I", data, 16)
        self.assertEqual((api, processor, status), (kd.API_CONTINUE2, 2, kd.DBG_CONTINUE))
        # Acknowledged, the next packet has the other id.
        self.assertEqual(self.ack(debugger), [])
        out = self.kernel_says(debugger, kd.TYPE_STATE_CHANGE64, kd.INITIAL_ID ^ 1,
                               state_change(kd.STATE_LOAD_SYMBOLS))
        self.assertEqual(out[1][2], kd.INITIAL_ID ^ 1)

    def test_a_breakpoint_is_stepped_over(self):
        debugger = kd.Debugger()
        out = self.kernel_says(debugger, kd.TYPE_STATE_CHANGE64, kd.INITIAL_ID,
                               state_change(kd.STATE_EXCEPTION, code=kd.STATUS_BREAKPOINT,
                                            address=0xFFFFF80000007028))
        api, = struct.unpack_from("<I", out[1][3])
        self.assertEqual(api, kd.API_GET_CONTEXT)
        self.assertEqual(debugger.breakpoints, [0xFFFFF80000007028])
        self.ack(debugger)
        # The kernel answers with the context; Rip is at the breakpoint.
        context = bytearray(1232)
        struct.pack_into("<Q", context, kd.CONTEXT_RIP, 0xFFFFF80000007028)
        reply = kd.manipulate(kd.API_GET_CONTEXT, 0, extra=bytes(context))
        out = self.kernel_says(debugger, kd.TYPE_STATE_MANIPULATE, kd.INITIAL_ID ^ 1, reply)
        api, = struct.unpack_from("<I", out[1][3])
        self.assertEqual(api, kd.API_SET_CONTEXT)
        rip, = struct.unpack_from("<Q", out[1][3], kd.MANIPULATE_SIZE + kd.CONTEXT_RIP)
        self.assertEqual(rip, 0xFFFFF80000007029, "one byte on, past the breakpoint")
        self.assertEqual(len(out[1][3]), kd.MANIPULATE_SIZE + 1232)
        self.ack(debugger)
        out = self.kernel_says(debugger, kd.TYPE_STATE_MANIPULATE, kd.INITIAL_ID,
                               kd.manipulate(kd.API_SET_CONTEXT, 0))
        api, = struct.unpack_from("<I", out[1][3])
        status, = struct.unpack_from("<I", out[1][3], 16)
        self.assertEqual((api, status), (kd.API_CONTINUE2, kd.DBG_CONTINUE))

    def test_any_other_exception_is_left_unhandled(self):
        debugger = kd.Debugger()
        out = self.kernel_says(debugger, kd.TYPE_STATE_CHANGE64, kd.INITIAL_ID,
                               state_change(kd.STATE_EXCEPTION, code=0xC0000005))
        api, = struct.unpack_from("<I", out[1][3])
        status, = struct.unpack_from("<I", out[1][3], 16)
        self.assertEqual((api, status), (kd.API_CONTINUE2, kd.DBG_EXCEPTION_NOT_HANDLED))
        self.assertEqual(debugger.breakpoints, [])

    def test_prints_are_kept_and_only_acknowledged(self):
        debugger = kd.Debugger()
        text = b"EVENT.SYS: hello\n"
        io = struct.pack("<IHHI4x", kd.API_PRINT_STRING, 0, 0, len(text)) + text
        out = self.kernel_says(debugger, kd.TYPE_DEBUG_IO, kd.INITIAL_ID, io)
        self.assertEqual(out, [(True, kd.TYPE_ACKNOWLEDGE, kd.INITIAL_ID, b"")])
        self.assertEqual(debugger.printed, ["EVENT.SYS: hello\n"])

    def test_no_file_is_offered_in_a_drivers_place(self):
        debugger = kd.Debugger()
        name = "\\??\\E:\\event.sys".encode("utf-16-le")
        request = struct.pack("<II", 0x3430, 0).ljust(kd.FILE_IO_SIZE, b"\0") + name
        out = self.kernel_says(debugger, kd.TYPE_FILE_IO, kd.INITIAL_ID, request)
        self.assertEqual(out[0], (True, kd.TYPE_ACKNOWLEDGE, kd.INITIAL_ID, b""))
        control, kind, packet_id, data = out[1]
        self.assertEqual((control, kind, len(data)), (False, kd.TYPE_FILE_IO, kd.FILE_IO_SIZE))
        self.assertEqual(struct.unpack_from("<II", data), (0x3430, kd.STATUS_UNSUCCESSFUL))

    def test_resend_and_reset(self):
        debugger = kd.Debugger()
        first = debugger.receive(kd.data_packet(kd.TYPE_STATE_CHANGE64, kd.INITIAL_ID,
                                                state_change(kd.STATE_LOAD_SYMBOLS)))
        ours = first[16:]
        self.assertEqual(debugger.receive(kd.control_packet(kd.TYPE_RESEND)), ours)
        # A damaged packet from the kernel is asked for again.
        damaged = kd.data_packet(kd.TYPE_STATE_CHANGE64, kd.INITIAL_ID, b"abc")[:-1] + b"\x00"
        self.assertEqual(sent(debugger.receive(damaged)), [(True, kd.TYPE_RESEND, 0, b"")])
        # A reset is answered with a reset, and numbering starts over.
        self.assertEqual(sent(debugger.receive(kd.control_packet(kd.TYPE_RESET))),
                         [(True, kd.TYPE_RESET, 0, b"")])
        out = self.kernel_says(debugger, kd.TYPE_STATE_CHANGE64, kd.INITIAL_ID,
                               state_change(kd.STATE_LOAD_SYMBOLS))
        self.assertEqual(out[1][2], kd.INITIAL_ID)


if __name__ == "__main__":
    unittest.main()
