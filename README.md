# Stacks Blockchain Codec

This project provides a Go implementation of the transaction wire format for the Stacks blockchain. It includes functionality for decoding various Stacks blockchain data structures, including transactions, addresses, and Clarity values.

## Features

- Decode Stacks blockchain transactions
- Convert between different address formats
- Decode Clarity values
- Support for various payload types including token transfers, contract calls, and coinbase transactions

## Installation

To use this package in your Go project, you can install it using:

```bash
go get github.com/stxpub/codec
```

## Usage

Here's a basic example of how to use the transaction decoder:

```go
package main

import (
    "bytes"
    "encoding/hex"
    "fmt"
    "log"

    "github.com/yourusername/stacks-codec/codec"
)

func main() {
    // Example transaction hex
    txHex := "00000000010400c1c66bdc612ebf90fd9b343f31f7f1750e50a13b000000000000333b00000000000000c8..."

    data, err := hex.DecodeString(txHex)
    if err != nil {
        log.Fatal(err)
    }

    var tx codec.Transaction
    err = tx.Decode(bytes.NewReader(data))
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("%+v\n", tx)
}
```

For more detailed usage examples, please refer to the tests in the `codec` package.

## Testing

To run the tests, use the following command in the project root directory:

```bash
go test ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [Unlicense](LICENSE).

## Known issues

Encoding of transactions is not yet supported.
