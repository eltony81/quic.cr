import asyncio
import os
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

class MyH3ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3_conn = H3Connection(self._quic)
        self.headers_received = {}
        self.body_received = {}
        self.responded_streams = set()

    def quic_event_received(self, event):
        print(f"[SERVER] Event: {type(event).__name__}")
        # Skip super() for StreamDataReceived: the parent creates asyncio
        # StreamWriter objects that get GC'd and accidentally send FIN on
        # bidi streams before our H3 response is sent.
        from aioquic.quic.events import StreamDataReceived as _SDR
        if not isinstance(event, _SDR):
            super().quic_event_received(event)

        h3_events = self.h3_conn.handle_event(event)
        for h3_event in h3_events:
            if isinstance(h3_event, HeadersReceived):
                print(f"[SERVER] Received headers on stream {h3_event.stream_id}")
                self.headers_received[h3_event.stream_id] = h3_event.headers
                self.body_received[h3_event.stream_id] = bytearray()
                if h3_event.stream_ended and h3_event.stream_id not in self.responded_streams:
                    self.responded_streams.add(h3_event.stream_id)
                    self.send_response(h3_event.stream_id)
            elif isinstance(h3_event, DataReceived):
                print(f"[SERVER] Received {len(h3_event.data)} bytes data on stream {h3_event.stream_id}")
                if h3_event.stream_id in self.body_received:
                    self.body_received[h3_event.stream_id].extend(h3_event.data)
                if h3_event.stream_ended and h3_event.stream_id not in self.responded_streams:
                    self.responded_streams.add(h3_event.stream_id)
                    self.send_response(h3_event.stream_id)

    def send_response(self, stream_id):
        headers_dict = {k.decode(): v.decode() for k, v in self.headers_received.get(stream_id, [])}
        body = self.body_received.get(stream_id, b"")
        
        path = headers_dict.get(":path", "/")
        method = headers_dict.get(":method", "GET")
        print(f"[SERVER] Sending response for {method} {path} on stream {stream_id}")
        
        resp_headers = [
            (b":status", b"200"),
            (b"content-type", b"text/plain"),
            (b"server", b"aioquic-server"),
        ]
        
        if path == "/":
            resp_body = b"Python aioquic server"
        elif path == "/echo_headers":
            lines = [f"{k}: {v}" for k, v in headers_dict.items()]
            resp_body = "\n".join(lines).encode()
        elif path == "/echo" and method == "POST":
            resp_body = bytes(body)
        elif path == "/large" and method == "POST":
            resp_body = f"Received {len(body)} bytes".encode()
        else:
            resp_headers = [
                (b":status", b"404"),
                (b"content-type", b"text/plain"),
                (b"server", b"aioquic-server"),
            ]
            resp_body = b"Not Found"
            
        self.h3_conn.send_headers(
            stream_id=stream_id,
            headers=resp_headers,
        )
        self.h3_conn.send_data(
            stream_id=stream_id,
            data=resp_body,
            end_stream=True,
        )
        self.transmit()

async def main():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["h3"],
    )
    # Load certificates
    configuration.load_cert_chain(
        certfile="cert.pem",
        keyfile="key.pem",
    )

    print("Python HTTP/3 Server listening on udp://127.0.0.1:4434")
    
    await serve(
        "127.0.0.1",
        4434,
        configuration=configuration,
        create_protocol=MyH3ServerProtocol,
    )
    # Keep running
    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
