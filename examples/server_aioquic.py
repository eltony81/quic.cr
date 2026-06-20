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

    def quic_event_received(self, event):
        # Let superclass process reader/writer streams if needed, or process directly
        super().quic_event_received(event)
        
        # Handle H3 events
        h3_events = self.h3_conn.handle_event(event)
        for h3_event in h3_events:
            if isinstance(h3_event, HeadersReceived):
                headers = [
                    (b":status", b"200"),
                    (b"content-type", b"text/plain"),
                    (b"server", b"aioquic-server"),
                ]
                self.h3_conn.send_headers(
                    stream_id=h3_event.stream_id,
                    headers=headers,
                )
                self.h3_conn.send_data(
                    stream_id=h3_event.stream_id,
                    data=b"Hello from mature Python aioquic server!\n",
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
