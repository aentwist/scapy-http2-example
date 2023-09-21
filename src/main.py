import socket
import ssl
import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import scapy.config
import zlib


DEST = "www.google.com"
DEST_PATH = "/"
UA = "Scapy HTTP/2 Module"


# Get the IP address of an HTTPS endpoint for `DEST`.
l = socket.getaddrinfo(
    DEST, 443, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP
)
assert len(l) > 0, "No address found :("

s = socket.socket(l[0][0], l[0][1], l[0][2])
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if hasattr(socket, "SO_REUSEPORT"):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
ip_and_port = l[0][4]

# Testing support for ALPN
assert ssl.HAS_ALPN

# Building the SSL context
ssl_ctx = ssl.create_default_context()
# See https://httpwg.org/specs/rfc7540.html#versioning
ssl_ctx.set_alpn_protocols(["h2"])
ssl_sock = ssl_ctx.wrap_socket(s, server_hostname=DEST)

ssl_sock.connect(ip_and_port)
assert "h2" == ssl_sock.selected_alpn_protocol()

scapy.config.conf.debug_dissector = True
ss = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)

# Send the HTTP/2 connection preface.
# See https://httpwg.org/specs/rfc7540.html#ConnectionHeader
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
ss.send(PREFACE)

# Receive the server connection preface (a SETTINGS frame).
srv_set = ss.recv()
srv_set.show()

# Process and acknowledge the SETTINGS frame.
srv_max_frm_sz = 1 << 14
srv_hdr_tbl_sz = 4096
srv_max_hdr_tbl_sz = 0
srv_global_window = 1 << 14
for setting in srv_set.payload.settings:
    if setting.id == h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE:
        srv_hdr_tbl_sz = setting.value
    elif setting.id == h2.H2Setting.SETTINGS_MAX_HEADER_LIST_SIZE:
        srv_max_hdr_lst_sz = setting.value
    elif setting.id == h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE:
        srv_global_window = setting.value

# We verify that the server window is large enough for us to send some data.
srv_global_window -= len(h2.H2_CLIENT_CONNECTION_PREFACE)
assert srv_global_window >= 0

set_ack = h2.H2Frame(flags={"A"}) / h2.H2SettingsFrame()
set_ack.show()

own_set = h2.H2Frame() / h2.H2SettingsFrame()
max_frm_sz = (1 << 24) - 1
max_hdr_tbl_sz = (1 << 16) - 1
win_sz = (1 << 31) - 1
own_set.settings = [
    h2.H2Setting(id=h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
    h2.H2Setting(id=h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
    h2.H2Setting(id=h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
    h2.H2Setting(id=h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
]

h2seq = h2.H2Seq()
h2seq.frames = [set_ack, own_set]
# We verify that the server window is large enough for us to send our frames.
srv_global_window -= len(str(h2seq))
assert srv_global_window >= 0
ss.send(h2seq)

# Loop until an acknowledgement for our settings is received
new_frame = None
while isinstance(new_frame, type(None)) or not (
    new_frame.type == h2.H2SettingsFrame.type_id and "A" in new_frame.flags
):
    if not isinstance(new_frame, type(None)):
        # If we received a frame about window management
        if new_frame.type == h2.H2WindowUpdateFrame.type_id:
            # For this tutorial, we don't care about stream-specific windows, but we should :)
            if new_frame.stream_id == 0:
                srv_global_window += new_frame.payload.win_size_incr
        # If we received a Ping frame, we acknowledge the ping,
        # just by setting the ACK flag (A), and sending back the query
        elif new_frame.type == h2.H2PingFrame.type_id:
            new_flags = new_frame.getfieldval("flags")
            new_flags.add("A")
            new_frame.flags = new_flags
            srv_global_window -= len(str(new_frame))
            assert srv_global_window >= 0
            ss.send(new_frame)
        else:
            assert (
                new_frame.type != h2.H2ResetFrame.type_id
                and new_frame.type != h2.H2GoAwayFrame.type_id
            ), "Error received; something is not right!"
    try:
        new_frame = ss.recv()
        new_frame.show()
    except:
        import time

        time.sleep(1)
        new_frame = None

tblhdr = h2.HPackHdrTable()
qry_frontpage = tblhdr.parse_txt_hdrs(
    # See https://github.com/secdev/scapy/issues/4130
    bytes(
        f""":method GET
:path {DEST_PATH}
:authority {DEST}
:scheme https
accept-encoding: gzip, deflate
accept-language: en-US
accept: text/html
user-agent: {UA}
""",
        "UTF-8",
    ),
    stream_id=1,
    max_frm_sz=srv_max_frm_sz,
    max_hdr_lst_sz=srv_max_hdr_lst_sz,
    is_sensitive=lambda hdr_name, hdr_val: hdr_name in ["cookie"],
    should_index=lambda x: x
    in [
        "x-requested-with",
        "user-agent",
        "accept-language",
        ":authority",
        "accept",
    ],
)
qry_frontpage.show()

h2seq = h2.H2Seq()
h2seq.frames = [qry_frontpage.frames[0]]
srv_global_window -= len(str(h2seq))
assert srv_global_window >= 0
ss.send(h2seq)

# The stream variable will contain all read frames; we will read on until stream 1 and stream 3 are closed by the server.
stream = h2.H2Seq()
# Number of streams closed by the server
closed_stream = 0

new_frame = None
while True:
    if not isinstance(new_frame, type(None)):
        if new_frame.stream_id in [1, 3]:
            stream.frames.append(new_frame)
            if "ES" in new_frame.flags:
                closed_stream += 1
        # If we read a PING frame, we acknowledge it by sending the same frame back, with the ACK flag set.
        elif new_frame.stream_id == 0 and new_frame.type == h2.H2PingFrame.type_id:
            new_flags = new_frame.getfieldval("flags")
            new_flags.add("A")
            new_frame.flags = new_flags
            ss.send(new_frame)

        # If one stream was closed, we don't need to perform the next operations
        if closed_stream >= 1:
            break
    try:
        new_frame = ss.recv()
        new_frame.show()
    except:
        import time

        time.sleep(1)
        new_frame = None

stream.show()

srv_tblhdr = h2.HPackHdrTable(
    dynamic_table_max_size=max_hdr_tbl_sz, dynamic_table_cap_size=max_hdr_tbl_sz
)

# Structure used to store textual representation of the stream headers
stream_txt = {}
# Structure used to store data from each stream
stream_data = {}

# For each frame we previously received
for frame in stream.frames:
    # If this frame is a header
    if frame.type == h2.H2HeadersFrame.type_id:
        # Convert this header block into its textual representation.
        # For the sake of simplicity of this tutorial, we assume
        # that the header block is not large enough to require a Continuation frame
        stream_txt[frame.stream_id] = srv_tblhdr.gen_txt_repr(frame)
    # If this frame is data
    if frame.type == h2.H2DataFrame.type_id:
        if frame.stream_id not in stream_data:
            stream_data[frame.stream_id] = []
        stream_data[frame.stream_id].append(frame)

print(stream_txt[1])

data = b""
for frgmt in stream_data[1]:
    data += frgmt.payload.data

print(zlib.decompress(data, 16 + zlib.MAX_WBITS).decode("UTF-8", "ignore"))
