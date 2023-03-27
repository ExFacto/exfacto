defmodule ExFacto.Oracle do
  alias ExFacto.Oracle.{Announcement, Attestation}
  alias ExFacto.{Event, Utils, Messaging}
  alias Bitcoinex.Secp256k1.{Schnorr, Signature, PrivateKey}

  @type t :: %__MODULE__{
          sk: PrivateKey.t(),
          pk: Point.t()
        }

  @enforce_keys [:sk, :pk]

  defstruct [
    :sk,
    :pk
  ]

  @spec new(PrivateKey.t()) :: t()
  def new(sk = %PrivateKey{}) do
    pk = PrivateKey.to_point(sk)

    %__MODULE__{
      sk: sk,
      pk: pk
    }
  end

  # currently unused until there are multiple types or fields.
  @type oracle_info :: %{
          announcement: Announcement.t()
        }

  @spec serialize_oracle_info(oracle_info()) :: binary
  def serialize_oracle_info(o), do: Announcement.serialize(o.announcement)

  @spec parse_oracle_info(binary) :: {oracle_info(), binary}
  def parse_oracle_info(msg) do
    {announcement, msg} = Announcement.parse(msg)

    oracle_info = %{
      announcement: announcement
    }

    {oracle_info, msg}
  end

  @doc """
    sign_event returns an announcement
  """
  def sign_event(o = %__MODULE__{}, event) do
    # {oracle, index} = increment_next_index(o)
    sighash = Announcement.sighash(event)
    aux = Utils.new_rand_int()
    {:ok, sig} = Schnorr.sign(o.sk, sighash, aux)

    %{announcement: Announcement.new(sig, o.pk, event)}
  end

  # a single_oracle_info is just a wrapped oracle_announcement
  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#single_oracle_info
  @spec new_single_oracle_info(t(), Event.t()) :: oracle_info()
  def new_single_oracle_info(o = %__MODULE__{}, event), do: sign_event(o, event)

  @spec sign_outcome(PrivateKey.t() | t(), binary) :: {:error, String.t()} | {:ok, Signature.t()}
  def sign_outcome(%__MODULE__{sk: sk}, outcome), do: sign_outcome(sk, outcome)

  def sign_outcome(sk = %PrivateKey{}, outcome) do
    aux = Utils.new_rand_int()
    sighash = Attestation.sighash(outcome) |> :binary.decode_unsigned()
    Schnorr.sign(sk, sighash, aux)
  end
end

defmodule ExFacto.Oracle.Announcement do
  @moduledoc """
    an announcement is simply an Event signed by an Oracle
  """
  alias Bitcoinex.Secp256k1.{Signature, Point, Schnorr}
  alias ExFacto.{Event, Utils, Messaging}

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

  @spec new(Signature.t(), Point.t(), Event.t()) :: t()
  def new(sig = %Signature{}, public_key = %Point{}, event = %Event{}) do
    %__MODULE__{
      signature: sig,
      public_key: public_key,
      event: event
    }
  end

  @spec verify(t()) :: boolean | {:error, String.t()}
  def verify(a = %__MODULE__{}) do
    sighash = sighash(a.event)
    Schnorr.verify_signature(a.public_key, sighash, a.signature)
  end

  @spec serialize(t()) :: binary
  def serialize(a) do
    Messaging.ser(a.signature, :signature) <>
      Messaging.ser(a.public_key, :pk) <>
      Event.serialize(a.event)
  end

  # used for signing events (structs)
  @spec sighash(Event.t()) :: non_neg_integer()
  def sighash(event) do
    event
    |> Event.serialize()
    |> Utils.oracle_tagged_hash("announcement/v0")
  end

  @spec parse(binary) :: {t(), binary}
  def parse(msg) do
    {signature, msg} = Messaging.par(msg, :signature)
    {point, msg} = Messaging.par(msg, :pk)
    {event, msg} = Event.parse(msg)

    announcement = new(signature, point, event)

    {announcement, msg}
  end
end

defmodule ExFacto.Oracle.Attestation do
  alias ExFacto.Utils
  alias Bitcoinex.Secp256k1.{Signature, Point}
  alias ExFacto.Messaging

  @type t :: %__MODULE__{
          event_id: String.t(),
          public_key: Point.t(),
          # currently only one of each per attestation
          signatures: list(Signature.t()),
          outcomes: list(String.t())
        }

  defstruct [
    :event_id,
    :public_key,
    :signatures,
    :outcomes
  ]

  @doc """
    new creates a new Attestation
  """
  @spec new(String.t(), Point.t(), list(Signature.t()), list(String.t())) :: Attestation.t()
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
  @spec serialize(t()) :: binary
  def serialize(a = %__MODULE__{}) do
    {sig_ct, ser_sigs} =
      Utils.serialize_with_count(a.signatures, fn sig -> Messaging.ser(sig, :signature) end)

    # ensure same number of sigs as outcomes
    {^sig_ct, ser_outcomes} =
      Utils.serialize_with_count(a.outcomes, fn o -> Messaging.ser(o, :utf8) end)

    Messaging.ser(a.event_id, :utf8) <>
      Messaging.ser(a.public_key, :pk) <>
      Messaging.ser(sig_ct, :u16) <>
      ser_sigs <>
      ser_outcomes
  end

  @spec parse(nonempty_binary) :: {t(), binary}
  def parse(msg) do
    {event_id, msg} = Messaging.par(msg, :utf8)
    {pubkey, msg} = Messaging.par(msg, :pk)
    {sig_ct, msg} = Utils.get_counter(msg)
    {sigs, msg} = Messaging.parse_items(msg, sig_ct, [], &Messaging.parse_signature/1)

    {outcomes, msg} =
      Messaging.parse_items(msg, sig_ct, [], fn msg -> Messaging.par(msg, :utf8) end)

    attestation = new(event_id, pubkey, sigs, outcomes)
    {attestation, msg}
  end

  def sighash(outcome),
    do: Utils.oracle_tagged_hash(outcome, "attestation/v0") |> :binary.encode_unsigned()
end
