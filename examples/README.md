# Examples

This directory contains executable examples demonstrating how to use the `quic.cr` library.

## HTTP/3 Server

A basic HTTP/3 Server that listens on UDP port 4433 and serves static content (`Hello from the quic.cr HTTP/3 Server!`) on the root path `/`. It uses hardcoded dummy certificates (`cert.pem` and `key.pem`) located in the repository root.

### How to Run

1. **Start the Server:**
   You can run the server directly using the Crystal compiler. Note that `crystal run` takes a few seconds to compile before the server starts.
   ```bash
   crystal run examples/http3_server.cr
   ```
   **Important:** Wait until you see the message `🚀 HTTP/3 Server listening on udp://127.0.0.1:4433` before attempting to connect.

   *Alternatively, pre-compile for instant startup:*
   ```bash
   crystal build examples/http3_server.cr
   ./http3_server
   ```

2. **Test with `curl`:**
   Open a second terminal and use `curl` to make HTTP/3 requests. You must pass `--http3` to force the protocol and `--insecure` to bypass the self-signed certificate warning.

   **GET Request** (Basic fetch):
   ```bash
   curl -v --http3 "https://127.0.0.1:4433" --insecure
   ```

   **POST Request** (Sending data):
   ```bash
   curl -v --http3 -X POST -d '{"name": "quic.cr"}' -H "Content-Type: application/json" "https://127.0.0.1:4433" --insecure
   ```

   **PUT Request** (Replacing data):
   ```bash
   curl -v --http3 -X PUT -d '{"updated": true}' -H "Content-Type: application/json" "https://127.0.0.1:4433/resource" --insecure
   ```

   **PATCH Request** (Partial update):
   ```bash
   curl -v --http3 -X PATCH -d '{"patched": true}' -H "Content-Type: application/json" "https://127.0.0.1:4433/resource" --insecure
   ```

   **DELETE Request** (Removing a resource):
   ```bash
   curl -v --http3 -X DELETE "https://127.0.0.1:4433/resource/1" --insecure
   ```

3. **Stop the Server:**
   Press `Ctrl+C` in the terminal where the server is running to stop it.

## HTTP/3 Client

(To be added) A basic HTTP/3 Client that can connect to any HTTP/3 enabled server to fetch resources.
