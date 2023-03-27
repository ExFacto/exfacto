defmodule ExFacto.Encoder do
  alias ExFacto.{Event, Messaging, Contract, Utils}
  alias ExFacto.Contract.{Offer, Accept, Acknowledge}
  alias ExFacto.Oracle.{Announcement, Attestation}

  @file_extension "bdlc"

  @msg_event 55330
  @msg_announcement 55332
  @msg_attestation 55400
  # TODO UNKNOWN Find in spec
  @msg_contract_info 0
  @msg_offer 42778
  @msg_accept 42780
  # made up. not in DLCSpec
  @msg_acknowledge 42782

  # @msg_event_enum 55302
  # @msg_event_digit 55306

  @doc """
    encode encodes a DLC message or a list of DLC messages to a single binary using TLV.
    Any present messages SHOULD be ordered like so.
    1. Event
    2. Announcement
    3. Attestation
    4. Contract
    5. Offer
    6. Accept
    7. Acknowledge
  """
  @spec encode(list(any) | any) :: binary
  def encode(msgs) when is_list(msgs),
    do: Enum.reduce(msgs, <<>>, fn msg, acc -> acc <> encode_msg(msg) end)

  def encode(msg), do: encode_msg(msg)
  # type <> length <> value
  def encode_msg(e = %Event{}),
    do: Messaging.ser(@msg_event, :u32) <> Utils.with_big_size(Event.serialize(e))

  def encode_msg(a = %Announcement{}),
    do: Messaging.ser(@msg_announcement, :u32) <> Utils.with_big_size(Announcement.serialize(a))

  def encode_msg(a = %Attestation{}),
    do: Messaging.ser(@msg_attestation, :u32) <> Utils.with_big_size(Attestation.serialize(a))

  def encode_msg(c = %Contract{}),
    do: Messaging.ser(@msg_contract_info, :u32) <> Utils.with_big_size(Contract.serialize(c))

  def encode_msg(o = %Offer{}),
    do: Messaging.ser(@msg_offer, :u32) <> Utils.with_big_size(Offer.serialize(o))

  def encode_msg(a = %Accept{}),
    do: Messaging.ser(@msg_accept, :u32) <> Utils.with_big_size(Accept.serialize(a))

  def encode_msg(a = %Acknowledge{}),
    do: Messaging.ser(@msg_acknowledge, :u32) <> Utils.with_big_size(Acknowledge.serialize(a))

  def base64(msg), do: encode(msg) |> Base.encode64()

  @doc """
    decode decodes one or more DLC messages to an ordered list of messages
  """
  @spec decode(binary) :: list
  def decode(msgs), do: decode(msgs, [])
  def decode(<<>>, decoded_items), do: Enum.reverse(decoded_items)

  def decode(msgs, decoded_items) do
    {item, rest} = decode_msg(msgs)
    decode(rest, [item | decoded_items])
  end

  def decode_msg(<<@msg_event::big-size(32), msg::binary>>) do
    {msg, rest} = Utils.parse_compact_size_value(msg)
    {event, <<>>} = Event.parse(msg)
    {event, rest}
  end

  def decode_msg(<<@msg_contract_info::big-size(32), msg::binary>>) do
    {msg, rest} = Utils.parse_compact_size_value(msg)
    {contract_info, <<>>} = Contract.parse(msg)
    {contract_info, rest}
  end

  def decode_msg(<<@msg_announcement::big-size(32), msg::binary>>) do
    {msg, rest} = Utils.parse_compact_size_value(msg)
    {announcement, <<>>} = Announcement.parse(msg)
    {announcement, rest}
  end

  def decode_msg(<<@msg_attestation::big-size(32), msg::binary>>) do
    {msg, rest} = Utils.parse_compact_size_value(msg)
    {attestation, <<>>} = Attestation.parse(msg)
    {attestation, rest}
  end

  def decode_msg(<<@msg_offer::big-size(32), msg::binary>>) do
    {msg, rest} = Utils.parse_compact_size_value(msg)
    {offer, <<>>} = Offer.parse(msg)
    {offer, rest}
  end

  def decode_msg(<<@msg_accept::big-size(32), msg::binary>>) do
    {msg, rest} = Utils.parse_compact_size_value(msg)
    {accept, <<>>} = Accept.parse(msg)
    {accept, rest}
  end

  def decode_msg(<<@msg_acknowledge::big-size(32), msg::binary>>) do
    {msg, rest} = Utils.parse_compact_size_value(msg)
    {acknowledge, <<>>} = Acknowledge.parse(msg)
    {acknowledge, rest}
  end

  def from_base64(msg), do: Base.decode64!(msg) |> decode()
end
