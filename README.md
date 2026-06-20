# quic

TODO: Write a description here

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     quic:
       github: your-github-user/quic.cr
   ```

2. Run `shards install`

## Usage

```crystal
require "quic"
```

To test the library, you can run the example HTTP/3 Server:

```bash
crystal run examples/http3_server.cr
```

Then, from another terminal, use `curl` to make HTTP/3 requests:

**GET Request:**
```bash
curl -v --http3 "https://127.0.0.1:4433" --insecure
```

**POST Request:**
```bash
curl -v --http3 -X POST -d '{"name": "quic.cr"}' -H "Content-Type: application/json" "https://127.0.0.1:4433/api/data" --insecure
```

**PUT Request:**
```bash
curl -v --http3 -X PUT -d '{"updated": true}' -H "Content-Type: application/json" "https://127.0.0.1:4433/api/data" --insecure
```

**PATCH Request:**
```bash
curl -v --http3 -X PATCH -d '{"patched": true}' -H "Content-Type: application/json" "https://127.0.0.1:4433/api/data" --insecure
```

**DELETE Request:**
```bash
curl -v --http3 -X DELETE "https://127.0.0.1:4433/api/data/1" --insecure
```
## Development

TODO: Write development instructions here

## Contributing

1. Fork it (<https://github.com/your-github-user/quic.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [tony](https://github.com/your-github-user) - creator and maintainer
