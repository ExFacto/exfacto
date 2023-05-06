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

  @spec verify_oracle_info(oracle_info()) :: boolean() | {:error, String.t()}
  def verify_oracle_info(%{announcement: a}), do: Announcement.verify(a)

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
    sighash = Announcement.sighash(event)
    aux = Utils.new_rand_int()
    {:ok, sig} = Schnorr.sign(o.sk, sighash, aux)

    %{announcement: Announcement.new(sig, o.pk, event)}
  end

  def attest(o = %__MODULE__{}, announcement, outcome_idx) do
    outcome = Enum.at(announcement.event.descriptor.outcomes, outcome_idx)
    {:ok, sig} = sign_outcome(o.sk, outcome)
    Attestation.new(announcement.event.id, o.pk, [sig], [outcome])
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

  @type_oracle_announcement 55332

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
    msg =
      Messaging.ser(a.signature, :signature) <>
        Messaging.ser(a.public_key, :pk) <>
        Event.serialize(a.event)

    Messaging.to_wire(@type_oracle_announcement, msg)
  end

  def to_hex(a), do: serialize(a) |> Utils.bin_to_hex()

  # used for signing events (structs)
  @spec sighash(Event.t()) :: non_neg_integer()
  def sighash(event) do
    event
    |> Event.serialize()
    |> Utils.oracle_tagged_hash("announcement/v0")
  end

  @spec parse(binary) :: {t(), binary}
  def parse(msg) do
    case Utils.hex_to_bin(msg) do
      {:ok, msg} -> do_parse(msg)
      {:error, _} -> do_parse(msg)
    end
  end
  def do_parse(msg) do
    {_type, msg, rest} = Messaging.from_wire(msg)
    {signature, msg} = Messaging.par(msg, :signature)
    {point, msg} = Messaging.par(msg, :pk)
    {event, <<>>} = Event.parse(msg)

    announcement = new(signature, point, event)

    {announcement, rest}
  end

  @spec calculate_signature_point(t(), non_neg_integer(), String.t()) :: any()
  def calculate_signature_point(a = %__MODULE__{}, nonce_idx, outcome) do
    nonce_point = Enum.at(a.event.nonce_points, nonce_idx)
    z = sighash(outcome)
    Schnorr.calculate_signature_point(nonce_point, a.public_key, z)
  end
end

defmodule ExFacto.Oracle.Attestation do
  alias ExFacto.Utils
  alias ExFacto.Messaging
  alias ExFacto.Oracle.Announcement
  alias Bitcoinex.Secp256k1.{Signature, PrivateKey, Point, Schnorr}

  @type_oracle_attestation 55400

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

  @doc """
    verify checks that the attestation is valid for the given announcement
  """
  def verify(announcement = %Announcement{}, attestation = %__MODULE__{}) do
    with {_, true} <- {:verify_announcement, Announcement.verify(announcement)},
         {_, true} <-
           {:verify_match, verify_announcement_attestation_match(announcement, attestation)},
         {_, true} <- {:verify_signatures, verify_outcome_signatures(attestation)} do
      true
    else
      {:verify_announcement, {:error, msg}} ->
        {:error, "invalid announcement: #{msg}"}

      {:verify_match, {:error, msg}} ->
        {:error, "attestation does not match announcement: #{msg}"}

      {:verify_signatures, {:error, msg}} ->
        {:error, "invalid attestation signatures: #{msg}"}
    end
  end

  @doc """
    verify_announcement_attestation_match checks that the announcement and attestation match
    1. event_id
    2. public_key
    3. attestation outcomes are in announcement
  """
  def verify_announcement_attestation_match(
        announcement = %Announcement{},
        attestation = %__MODULE__{}
      ) do
    cond do
      attestation.event_id != announcement.event.id ->
        {:error, "announcement and attestation event ids do not match"}

      attestation.public_key != announcement.public_key ->
        {:error, "announcement and attestation public keys do not match"}

      # check all outcomes are in announcement. This only works for enum
      !Enum.all?(attestation.outcomes, fn outcome ->
        Enum.member?(announcement.event.outcomes, outcome)
      end) ->
        {:error, "attestation outcome not in announcement"}

      true ->
        true
    end
  end

  @doc """
    verify_outcome_signatures checks all signatures are valid for the respective outcome
  """
  def verify_outcome_signatures(attestation = %__MODULE__{}) do
    outcomes_signatures = Enum.zip(attestation.outcomes, attestation.signatures)
    cond do
      # check signature is valid for outcome
      !Enum.all?(outcomes_signatures, fn {outcome, signature} ->
        # check signature is valid for outcome
        sighash = sighash(outcome) |> :binary.decode_unsigned()
        Schnorr.verify_signature(attestation.public_key, sighash, signature)
      end) ->
        {:error, "invalid attestation signature"}

      true -> true
    end
  end

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#oracle_attestation
  @spec serialize(t()) :: binary
  def serialize(a = %__MODULE__{}) do
    {sig_ct, ser_sigs} =
      Utils.serialize_with_count(a.signatures, fn sig -> Messaging.ser(sig, :signature) end)

    # ensure same number of sigs as outcomes
    {^sig_ct, ser_outcomes} =
      Utils.serialize_with_count(a.outcomes, fn o -> Messaging.ser(o, :utf8) end)

    msg =
      Messaging.ser(a.event_id, :utf8) <>
        Messaging.ser(a.public_key, :pk) <>
        Messaging.ser(sig_ct, :u16) <>
        ser_sigs <>
        ser_outcomes

    Messaging.to_wire(@type_oracle_attestation, msg)
  end

  def to_hex(a = %__MODULE__{}), do: serialize(a) |> Utils.bin_to_hex()

  @spec parse(nonempty_binary) :: {t(), binary}
  def parse(msg) do
    # parse either hex or binary
    case Utils.hex_to_bin(msg) do
      {:ok, msg} -> do_parse(msg)
      _ -> do_parse(msg)
    end
  end

  defp do_parse(msg) do
    {_type_oracle_attestation, msg, rest} = Messaging.from_wire(msg)
    {event_id, msg} = Messaging.par(msg, :utf8)
    {pubkey, msg} = Messaging.par(msg, :pk)
    {sig_ct, msg} = Messaging.par(msg, :u16)
    {sigs, msg} = Messaging.parse_items(msg, sig_ct, [], &Messaging.parse_signature/1)

    {outcomes, <<>>} =
      Messaging.parse_items(msg, sig_ct, [], fn msg -> Messaging.par(msg, :utf8) end)

    attestation = new(event_id, pubkey, sigs, outcomes)
    {attestation, rest}
  end

  @spec sighash(String.t()) :: binary
  def sighash(outcome) do
    outcome
    |> String.normalize(:nfc)
    |> Utils.oracle_tagged_hash("attestation/v0")
    |> :binary.encode_unsigned()
  end

  @spec extract_decryption_key(t()) :: PrivateKey.t()
  def extract_decryption_key(attestation = %__MODULE__{}) do
    %Signature{s: tweak} = Enum.at(attestation.signatures, 0)
    {:ok, sk} = PrivateKey.new(tweak)
    sk
  end
end
