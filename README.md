# Signature scanner

This is an extremely simple implementation of a pattern scanner for game hacking purposes

## Example

```rust
use signature_scanner::Signature;

// Creation of a IDA byte signature:
let ida_sig = Signature::ida("12 34");
let string_sig = Signature::string("lo, wor", /*include_terminator: */false);

// Search inside u8 slice:
ida_sig.next(&[0x00u8, /*matches here*/0x12, 0x34, 0x56, 0x12, 0x54, 0x12, 0x34, 0x00, 0x55, 0xAA]); // == Some(1)
string_sig.next("Hello, world!".as_bytes()); // == Some(3)
```
