import asyncio
import sys
import logging
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

logging.basicConfig(level=logging.DEBUG)

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3_conn = H3Connection(self._quic)
        self.h3_events = []
        self.h3_stream_ended = set()

    def quic_event_received(self, event):
        for h3_event in self.h3_conn.handle_event(event):
            self.h3_events.append(h3_event)
            # Both HeadersReceived and DataReceived have stream_ended
            if hasattr(h3_event, "stream_ended") and h3_event.stream_ended:
                self.h3_stream_ended.add(h3_event.stream_id)
        from aioquic.quic.events import StreamDataReceived as _SDR
        if not isinstance(event, _SDR):
            super().quic_event_received(event)

async def main():
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
    )
    configuration.verify_mode = False # Skip cert verification for local test

    async with connect(
        "127.0.0.1",
        4433,
        configuration=configuration,
        create_protocol=H3ClientProtocol,
    ) as client:
        # Send GET request headers
        stream_id = client._quic.get_next_available_stream_id()
        client.h3_conn.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"127.0.0.1"),
                (b":path", b"/"),
                (b"user-agent", b"aioquic-client"),
            ],
            end_stream=True
        )
        client.transmit()

        # Wait until the stream has ended (response is complete)
        start_time = asyncio.get_event_loop().time()
        while stream_id not in client.h3_stream_ended:
            await asyncio.sleep(0.05)
            if asyncio.get_event_loop().time() - start_time > 5.0:
                print("Timeout waiting for response")
                sys.exit(1)

        print("\n--- RECEIVED EVENTS ---")
        for h3_event in client.h3_events:
            if h3_event.stream_id == stream_id:
                if isinstance(h3_event, HeadersReceived):
                    print("\n[Headers Received]:")
                    for k, v in h3_event.headers:
                        print(f"  {k.decode()}: {v.decode()}")
                elif isinstance(h3_event, DataReceived):
                    print("\n[Body Received]:")
                    print(h3_event.data.decode())

        print("\nVALIDATION SUCCESSFUL!")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
