import asyncio
import sys
import logging
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

logging.basicConfig(level=logging.DEBUG)
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

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
    ) as client:
        # Perform HTTP/3 request using H3Connection
        h3_conn = H3Connection(client._quic)
        
        # Send GET request headers
        stream_id = client._quic.get_next_available_stream_id()
        h3_conn.send_headers(
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

        # Wait for events on the connection
        done = False
        while not done:
            await asyncio.sleep(0.1)
            # Read incoming events
            while True:
                event = client._quic.next_event()
                if event is None:
                    break
                # Pass events to H3Connection
                h3_events = h3_conn.handle_event(event)
                for h3_event in h3_events:
                    if isinstance(h3_event, HeadersReceived):
                        print("\n[Python Client Received Headers]:")
                        for k, v in h3_event.headers:
                            print(f"{k.decode()}: {v.decode()}")
                    elif isinstance(h3_event, DataReceived):
                        print("\n[Python Client Received Body]:")
                        print(h3_event.data.decode())
                        print("\nVALIDATION SUCCESSFUL!")
                        sys.exit(0)
            client.transmit()

if __name__ == "__main__":
    asyncio.run(main())
