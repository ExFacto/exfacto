defmodule ExFacto.Oracle do
  alias ExFacto.Oracle.Announcement
  alias ExFacto.Utils
  # alias ExFacto.Oracle.Announcement
  alias ExFacto.Event
  alias Bitcoinex.Utils, as: BtcUtils
  alias Bitcoinex.Secp256k1.{Schnorr, PrivateKey}

  @type t :: %__MODULE__{
          sk: PrivateKey.t(),
          pk: Point.t()
        }

  @enforce_keys [:sk]

  defstruct [
    :sk,
    :pk
  ]

  def new() do
    sk = Utils.new_private_key()
    pk = PrivateKey.to_point(sk)

    %__MODULE__{
      sk: sk,
      pk: pk
    }
  end

  @type oracle_info :: %{
          announcement: Announcement.t()
        }

  def serialize_oracle_info(o) do
    Announcement.serialize(o.announcement)
  end

  @doc """
    sign_event returns an oracle_announcement
  """
  def sign_event(o = %__MODULE__{}, event) do
    sighash = announcement_sighash(event)
    aux = Utils.new_rand_int()
    {:ok, sig} = Schnorr.sign(o.sk, sighash, aux)

    # TODO make this an Announcement
    %{
      signature: sig,
      public_key: o.pk,
      event: event
    }
  end

  # a single_oracle_info is just a wrapped oracle_announcement
  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#single_oracle_info
  def new_single_oracle_info(o = %__MODULE__{}, event) do
    sign_event(o, event)
  end

  # used for signing events (structs)
  def announcement_sighash(event) do
    event
    |> Event.serialize()
    |> oracle_tagged_hash("announcement/v0")
  end

  # used for signing outcomes (strings)
  def attestation_sighash(outcome), do: oracle_tagged_hash(outcome, "attestation/v0")

  def oracle_tagged_hash(msg, tag) do
    BtcUtils.tagged_hash("DLC/oracle/#{tag}", msg) |> :binary.decode_unsigned()
  end

  def sign_outcome(outcome, sk) do
    aux = Utils.new_rand_int()
    sighash = attestation_sighash(outcome)
    Schnorr.sign(sk, sighash, aux)
  end
end

defmodule ExFacto.Oracle.Announcement do
  @moduledoc """
    an announcement is simply an Event signed by an Oracle
  """
  alias Bitcoinex.Secp256k1.{Signature, Point}
  alias ExFacto.Event

  @type t :: %__MODULE__{
          signature: Signature.t(),
          public_key: Point.t(),
          event: Event.t()
        }

  defstruct [
    :signature,
    :public_key,
    :event
  ]

  def new(sig = %Signature{}, public_key = %Point{}, event = %Event{}) do
    %__MODULE__{
      signature: sig,
      public_key: public_key,
      event: event
    }
  end

  def serialize(a) do
    Signature.serialize_signature(a.signature) <>
      Point.x_bytes(a.public_key) <>
      Event.serialize(a.event)
  end

  def parse(<<sig::binary-size(64), pk::binary-size(32), event::binary>>) do
    signature = Signature.parse_signature(sig)
    {:ok, point} = Point.lift_x(pk)
    {event, rest} = Event.parse(event)

    announcement = new(signature, point, event)

    {announcement, rest}
  end
end

defmodule ExFacto.Oracle.Attestation do
  alias ExFacto.Utils
  alias Bitcoinex.Secp256k1.{Signature, Point}
  alias ExFacto.Messaging

  @type t :: %__MODULE__{
          event_id: String.t(),
          public_key: Point.t(),
          signatures: list(Signature.t()),
          outcomes: list(String.t())
        }

  defstruct [
    :event_id,
    :public_key,
    :signatures,
    :outcomes
  ]

  def new(event_id, public_key = %Point{}, signatures, outcomes)
      when length(signatures) == length(outcomes) do
    %__MODULE__{
      event_id: event_id,
      public_key: public_key,
      signatures: signatures,
      outcomes: outcomes
    }
  end

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#oracle_attestation
  # @oracle_attestation_type 55400
  def serialize(event_id, pubkey, signatures, outcomes) do
    {sig_ct, ser_sigs} = Utils.serialize_with_count(signatures, &Signature.serialize_signature/1)
    # ensure same number of sigs as outcomes
    {^sig_ct, ser_outcomes} = Utils.serialize_with_count(outcomes, &Messaging.serialize_outcome/1)

    Messaging.ser(event_id, :utf8) <>
      Point.x_bytes(pubkey) <>
      Messaging.ser(sig_ct, :u16) <>
      ser_sigs <>
      ser_outcomes
  end

  def parse(msg) do
    {event_id, msg} = Utils.parse_compact_size_value(msg)
    {pk, msg} = Messaging.par(msg, 32)
    {:ok, pubkey} = Point.lift_x(pk)
    {sig_ct, msg} = Utils.get_counter(msg)
    # TODO make these 2 functions generic
    {sigs, msg} = Messaging.parse_signatures(msg, sig_ct, [])
    {outcomes, msg} = Messaging.parse_outcomes(msg, sig_ct, [])
    attestation = new(event_id, pubkey, sigs, outcomes)
    {attestation, msg}
  end
end
