defmodule ExFacto.Event do
  alias ExFacto.{Messaging, Utils}
  alias Bitcoinex.Secp256k1.{PrivateKey, Point}

  @type_oracle_event 55330
  @type_enum_event_descriptor 55302

  @type t :: %__MODULE__{
          id: String.t(),
          # for now, only once nonce point per event
          nonce_points: list(Point.t()),
          # this wrapping is so we can add new event_descriptor types (like numeric events)
          descriptor: event_descriptor(),
          maturity_epoch: non_neg_integer()
        }

  defstruct [
    :id,
    :nonce_points,
    :descriptor,
    :maturity_epoch
  ]

  # @spec new(list(String.t())) :: t()
  def new(event_id, nonce_points, descriptor, maturity_epoch) do
    %__MODULE__{
      id: event_id,
      nonce_points: nonce_points,
      descriptor: descriptor,
      maturity_epoch: maturity_epoch
    }
  end

  def serialize(event) do
    {ct, ser_nonces} = Utils.serialize_with_count(event.nonce_points, &Point.x_bytes/1)

    msg =
      Messaging.ser(ct, :u16) <>
        ser_nonces <>
        Messaging.ser(event.maturity_epoch, :u32) <>
        serialize_event_descriptor(event.descriptor) <>
        Messaging.ser(event.id, :utf8)

    Messaging.to_wire(@type_oracle_event, msg)
  end

  def to_hex(event), do: serialize(event) |> Utils.bin_to_hex()

  def parse_nonce_point(msg) do
    {nonce_pt, msg} = Messaging.par(msg, 32)
    {:ok, nonce_point} = Point.lift_x(nonce_pt)
    {nonce_point, msg}
  end

  def parse(msg) do
    case Utils.hex_to_bin(msg) do
      {:ok, msg} -> do_parse(msg)
      _ -> do_parse(msg)
    end
  end

  def do_parse(msg) do
    {_type, msg, rest} = Messaging.from_wire(msg)
    {nonce_ct, msg} = Messaging.par(msg, :u16)
    {nonce_points, msg} = Messaging.parse_items(msg, nonce_ct, [], &parse_nonce_point/1)
    {maturity_epoch, msg} = Messaging.par(msg, :u32)
    {descriptor, msg} = parse_event_descriptor(msg)
    {event_id, <<>>} = Messaging.par(msg, :utf8)
    event = new(event_id, nonce_points, descriptor, maturity_epoch)
    {event, rest}
  end

  # this will be a more generic type once numeric descriptors
  @type event_descriptor :: %{
          outcomes: list(String.t())
        }

  def new_event_descriptor(outcomes) do
    %{
      outcomes: outcomes
    }
  end

  def serialize_event_descriptor(descriptor) do
    {ct, ser_outcomes} =
      Utils.serialize_with_count(descriptor.outcomes, fn o -> Messaging.ser(o, :utf8) end)

    msg = Messaging.ser(ct, :u16) <> ser_outcomes

    Messaging.to_wire(@type_enum_event_descriptor, msg)
  end

  @spec parse_event_descriptor(binary) :: {%{outcomes: list}, any}
  def parse_event_descriptor(msg) do
    {_type, msg, rest} = Messaging.from_wire(msg)
    {outcome_ct, msg} = Messaging.par(msg, :u16)

    {outcomes, <<>>} =
      Messaging.parse_items(msg, outcome_ct, [], fn msg -> Messaging.par(msg, :utf8) end)

    {%{outcomes: outcomes}, rest}
  end

  # Assuming Enum.
  # returns private nonce key and event
  def new_event_from_enum_event_descriptor(
        descriptor = %{outcomes: _},
        maturity_epoch,
        new_private_key_func
      ) do
    nonce_sec = new_private_key_func.()
    nonce_point = PrivateKey.to_point(nonce_sec)

    event = %__MODULE__{
      id: Utils.new_event_id(),
      nonce_points: [nonce_point],
      descriptor: descriptor,
      maturity_epoch: maturity_epoch
    }

    {nonce_sec, event}
  end

  # OLD

  # @spec calculate_all_signature_points(attestation()) :: list(Point.t())
  # def calculate_all_signature_points(%{pubkey: pk, public_nonce: r_point, outcomes: outcomes}) do
  #   # Enum.map(outcomes, fn outcome -> calculate_all_signature_points(pk, r_point, outcome) end)
  #   []
  # end
end
