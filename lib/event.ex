defmodule ExFacto.Event do
  alias ExFacto.Messaging

  @type t :: %__MODULE__{
          id: String.t(),
          nonce_points: list(Point.t()),
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
    {ct, ser_nonces} = Utils.serialize_with_count(event.nonces, &Point.x_bytes/1)

    Messaging.ser(ct, :u16) <>
      ser_nonces <>
      Messaging.ser(event.maturity_epoch, :u32) <>
      serialize_event_descriptor(event.descriptor) <>
      Messaging.ser(event.id, :utf8)
  end

  @type event_descriptor :: %{
    outcomes: list(String.t())
  }

  def new_event_descriptor(outcomes) do
    %{
      outcomes: outcomes
    }
  end

  def serialize_event_descriptor(descriptor) do
    {ct, ser_outcomes} = Utils.serialize_with_count(descriptor.outcomes, &Messaging.serialize_outcome/1)
    Messaging.ser(ct, :u16) <> ser_outcomes
  end

  # Assuming Enum.
  # returns private nonce key and event
  def new_event_from_enum_event_descriptor(o = %__MODULE__{}, descriptor = %{outcomes: _}, maturity_epoch) do
    nonce_sec = Utils.new_private_key()
    {:ok, nonce_point} = PrivateKey.to_point(nonce_sec)
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

  # @spec calculate_signature_point(Point.t(), Point.t(), String.t()) :: any()
  # def calculate_signature_point(pk, r_point, outcome) do
  #   z = Bitcoinex.Utils.double_sha256(outcome)
  #   Schnorr.calculate_signature_point(r_point, pk, z)
  # end

  # def get_outcome_sighash(%__MODULE__{outcomes: outcomes}, idx) do
  #   outcomes
  #   |> Enum.at(idx)
  #   |> ExFacto.Oracle.attestation_sighash()
  #   |> :binary.decode_unsigned()
  # end

  # def resolve(event, outcome_idx, oracle, signature) do
  #   %{
  #     pubkey: oracle.pk,
  #     signature: signature,
  #     outcome: Enum.at(event, outcome_idx)
  #   }
  # end

  # def get_secret_from_resolution(%{signature: %{s: s}}), do: PrivateKey.new(s)
end
