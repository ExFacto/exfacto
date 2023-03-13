# ExFacto

A pure Elixir library for pure Schnorr & Taproot DLCs on Bitcoin. 

This is nowhere near ready to be used, much less secure enough for real money. Use at your own risk. 

## Standards Compliance

For several reasons, we chose not to fully implement the DLC spec being worked on [here](https://github.com/discreetlogcontracts/dlcspecs). 
- They use ECDSA for the parties and Schnorr only for the Oracle. 
- Schnorr and ECDSA have different data requirements for Adaptor Signatures (Schnorr's are much smaller)
- The DLC spec is unnecessarily complex and verbose. We chose to drop the extra TLVs and Negotiation Fields from Offers and Accepts.
- We opted to sort inputs lexicographically by outpoint (txid:vout) and outputs lexicographically by scriptpubkey instead of using `serial_id`s to determine input and output ordering. See: BIP-69
- We will not support P2SH-wrapped SegWit inputs to funding transactions.

With this said, we closely followed this spec as a guideline and significant thanks are owed to the creators of the spec for showing us how to build a DLC platform.
- We used the TLV format for encoding messages.
- Aside from extra TLVs and negotiation fields, we used the same serialization formats. 
- We used the same message types and type identifiers. 
- We used the same flow for setting up contracts. 

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `exfacto` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:exfacto, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/exfacto>.

