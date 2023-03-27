defmodule ExFacto.Contract do
  # import Bitwise

  alias ExFacto.{Utils, Oracle, Messaging}

  @default_contract_flags 0
  @spec default_contract_flags :: 0
  def default_contract_flags(), do: @default_contract_flags

  @type t :: %__MODULE__{
          total_collateral: non_neg_integer(),
          # For now, no numerics
          descriptor: contract_descriptor_enum(),
          oracle_info: Oracle.oracle_info()
        }

  defstruct [
    :total_collateral,
    :descriptor,
    :oracle_info
  ]

  def new(total_collateral, descriptor, oracle_info) do
    %__MODULE__{
      total_collateral: total_collateral,
      descriptor: descriptor,
      oracle_info: oracle_info
    }
  end

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#single_contract_info
  def serialize(c) do
    Messaging.ser(c.total_collateral, :u64) <>
      serialize_contract_descriptor(c.descriptor) <>
      Oracle.serialize_oracle_info(c.oracle_info)
  end

  # @type contract_descriptor :: contract_descriptor_enum

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#enumerated_contract_descriptor
  @type contract_descriptor_enum :: list({String.t(), non_neg_integer()})

  def serialize_contract_descriptor(descriptor) do
    {ct, ser_outcomes} = Utils.serialize_with_count(descriptor, &serialize_outcome_payout/1)
    Utils.big_size(ct) <> ser_outcomes
  end

  def serialize_outcome_payout({outcome, payout}) do
    Messaging.ser(outcome, :utf8) <> Messaging.ser(payout, :u64)
  end

  def parse(msg) do
    {total_collateral, msg} = Messaging.par(msg, :u64)
    {contract_descriptor, msg} = parse_contract_descriptor(msg)
    {oracle_info, msg} = Oracle.parse_oracle_info(msg)
    contract_info = new(total_collateral, contract_descriptor, oracle_info)
    {contract_info, msg}
  end

  @spec parse_contract_descriptor(nonempty_binary) :: {list, any}
  def parse_contract_descriptor(msg) do
    {outcome_ct, msg} = Utils.get_counter(msg)
    Messaging.parse_items(msg, outcome_ct, [], &parse_outcome_payout/1)
  end

  def parse_outcome_payout(msg) do
    {outcome, msg} = Messaging.par(msg, :utf8)
    {payout, msg} = Messaging.par(msg, :u64)
    {{outcome, payout}, msg}
  end

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#numeric_outcome_contract_descriptor
  # @type numeric_descriptor :: %{
  #   num_digits: non_neg_integer(),
  #   payout_func: payout_func(),
  #   rounding_intervals: list(any()),
  # }

  def calculate_contract_id(
        <<funding_txid::big-size(256)>>,
        funding_vout,
        <<offer_id::big-size(256)>>
      ) do
    # why does the spec say the vout will only affect the last 2 bytes of the txid XOR temp_id when vout is 4 bytes
    # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Protocol.md#definition-of-contract_id
    # vout_binary = Bitwise.band(funding_vout, 0xFFFF)

    Bitwise.bxor(funding_txid, offer_id)
    |> Bitwise.bxor(funding_vout)
    |> :binary.encode_unsigned()
  end
end

defmodule ExFacto.Contract.Offer do
  alias ExFacto.Oracle.Announcement
  alias ExFacto.{Messaging, Utils, Contract}
  alias Bitcoinex.Secp256k1.{Point, Signature}
  alias Bitcoinex.Script

  @type t :: %__MODULE__{
          version: non_neg_integer(),
          contract_flags: non_neg_integer(),
          chain_hash: <<_::256>>,
          offer_id: <<_::256>>,
          contract_info: Contract.t(),
          funding_pubkey: Point.t(),
          payout_script: Script.t(),
          collateral_amount: non_neg_integer(),
          # funding_input type
          funding_inputs: list(),
          change_script: Script.t(),
          fee_rate: non_neg_integer(),
          cet_locktime: non_neg_integer(),
          refund_locktime: non_neg_integer(),
          tlvs: list()
        }

  defstruct [
    :version,
    :contract_flags,
    :chain_hash,
    :offer_id,
    :contract_info,
    :funding_pubkey,
    :payout_script,
    :collateral_amount,
    :funding_inputs,
    :change_script,
    :fee_rate,
    :cet_locktime,
    :refund_locktime,
    :tlvs
  ]

  def new(
        chain_hash,
        contract_info,
        offer_collateral_amount,
        funding_inputs,
        funding_pubkey,
        payout_script,
        change_script,
        fee_rate,
        cet_locktime,
        refund_locktime
      ) do
    version = Utils.get_protocol_version()
    contract_flags = Contract.default_contract_flags()

    offer = %__MODULE__{
      version: version,
      contract_flags: contract_flags,
      chain_hash: chain_hash,
      contract_info: contract_info,
      funding_pubkey: funding_pubkey,
      payout_script: payout_script,
      collateral_amount: offer_collateral_amount,
      funding_inputs: funding_inputs,
      change_script: change_script,
      fee_rate: fee_rate,
      cet_locktime: cet_locktime,
      refund_locktime: refund_locktime
      # TODO TLVs
    }

    # set offer_id
    %{offer | offer_id: calculate_offer_id(offer)}
  end

  def verify(o = %__MODULE__{}) do
    calculate_offer_id(o) == o.offer_id &&
      Announcement.verify(contract_info.oracle_info.announcement)
  end

  def calculate_offer_id(o = %__MODULE__{}) do
    %{o | offer_id: <<>>}
    |> serialize()
    |> Utils.contractor_tagged_hash("offer/v0")
  end

  def serialize(o = %__MODULE__{}) do
    # <>
    Messaging.ser(o.version, :u32) <>
      Messaging.ser(o.contract_flags, :u8) <>
      o.chain_hash <>
      o.offer_id <>
      Contract.serialize(o.contract_info) <>
      Point.x_bytes(o.funding_pubkey) <>
      Utils.script_with_big_size(o.payout_script) <>
      Messaging.ser(o.collateral_amount, :u64) <>
      Messaging.serialize_funding_inputs(o.funding_inputs) <>
      Utils.script_with_big_size(o.change_script) <>
      Messaging.ser(o.fee_rate, :u64) <>
      Messaging.ser(o.cet_locktime, :u32) <>
      Messaging.ser(o.refund_locktime, :u32)

    # serialize_offer_tlvs(o.tlvs)
  end

  @spec parse(binary) :: t()
  def parse(msg) do
    {version, msg} = Messaging.par(msg, :u32)
    {contract_flags, msg} = Messaging.par(msg, :u8)
    {chain_hash, msg} = Messaging.par(msg, 32)
    {offer_id, msg} = Messaging.par(msg, 32)
    {contract_info, msg} = Contract.parse(msg)
    {funding_pubkey, msg} = Messaging.parse_point(msg)
    {payout_script, msg} = Messaging.par(msg, :script)
    {collateral_amount, msg} = Messaging.par(msg, :u64)
    {funding_inputs, msg} = Messaging.parse_funding_inputs(msg)
    {change_script, msg} = Messaging.par(msg, :script)
    {fee_rate, msg} = Messaging.par(msg, :u64)
    {cet_locktime, msg} = Messaging.par(msg, :u32)
    {refund_locktime, msg} = Messaging.par(msg, :u32)
    # {tlvs, _msg} = parse_offer_tlvs(msg)
    # TODO verify msg is blank

    offer = %__MODULE__{
      version: version,
      contract_flags: contract_flags,
      chain_hash: chain_hash,
      offer_id: offer_id,
      contract_info: contract_info,
      funding_pubkey: funding_pubkey,
      payout_script: payout_script,
      collateral_amount: collateral_amount,
      funding_inputs: funding_inputs,
      change_script: change_script,
      fee_rate: fee_rate,
      cet_locktime: cet_locktime,
      refund_locktime: refund_locktime
      # tlvs: tlvs
    }

    {offer, msg}
  end

  # unimplemented
  def serialize_offer_tlvs(_), do: <<>>
end

defmodule ExFacto.Contract.Accept do
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Secp256k1.{Point, Signature}
  alias ExFacto.{Utils, Messaging}

  # BREAK with DLC Spec: add dummy_tapkey_tweak
  @type t :: %__MODULE__{
          version: non_neg_integer(),
          chain_hash: <<_::256>>,
          contract_id: <<_::256>>,
          offer_id: <<_::256>>,
          funding_pubkey: Point.t(),
          dummy_tapkey_tweak: non_neg_integer(),
          payout_script: Script.t(),
          change_script: Script.t(),
          collateral_amount: non_neg_integer(),
          funding_inputs: list(Messaging.funding_input_info()),
          # TODO: Barrier Oracle info
          cet_adaptor_signatures: list(cet_adaptor_signature()),
          refund_signature: Signature.t()
          # negotiation_fields: list(),
          # tlvs: list()
        }

  defstruct [
    :version,
    :chain_hash,
    :contract_id,
    :offer_id,
    :funding_pubkey,
    :dummy_tapkey_tweak,
    :payout_script,
    :change_script,
    :collateral_amount,
    :funding_inputs,
    :cet_adaptor_signatures,
    :refund_signature
    # :negotiation_fields,
    # :tlvs
  ]

  def new(
        chain_hash,
        contract_id,
        offer_id,
        funding_pubkey,
        dummy_tapkey_tweak,
        payout_script,
        change_script,
        collateral_amount,
        funding_inputs,
        cet_adaptor_signatures,
        refund_signature
      ) do
    version = Utils.get_protocol_version()

    %__MODULE__{
      version: version,
      chain_hash: chain_hash,
      contract_id: contract_id,
      offer_id: offer_id,
      funding_pubkey: funding_pubkey,
      dummy_tapkey_tweak: dummy_tapkey_tweak,
      payout_script: payout_script,
      change_script: change_script,
      collateral_amount: collateral_amount,
      funding_inputs: funding_inputs,
      cet_adaptor_signatures: cet_adaptor_signatures,
      refund_signature: refund_signature
      # TODO: negotiation_fields
      # TODO: TLVs
    }
  end

  def serialize(a = %__MODULE__{}) do
    # <>
    Messaging.ser(a.version, :u32) <>
      a.chain_hash <>
      a.contract_id <>
      a.offer_id <>
      Messaging.ser(a.collateral_amount, :u64) <>
      Messaging.ser(a.funding_pubkey, :pk) <>
      Messaging.ser(a.dummy_tapkey_tweak, :u256) <>
      Utils.script_with_big_size(a.payout_script) <>
      Messaging.serialize_funding_inputs(a.funding_inputs) <>
      Utils.script_with_big_size(a.change_script) <>
      Messaging.serialize_cet_adaptor_signatures(a.cet_adaptor_signatures) <>
      Messaging.ser(a.refund_signature, :signature)

    # Messaging.serialize_negotiation_fields(a.negotiation_fields) <>
    # Messaging.serialize_tlvs(a.tlvs)
  end

  def parse(msg) do
    {version, msg} = Messaging.par(msg, :u32)
    {chain_hash, msg} = Messaging.par(msg, 32)
    {contract_id, msg} = Messaging.par(msg, 32)
    {offer_id, msg} = Messaging.par(msg, 32)
    {collateral_amount, msg} = Messaging.par(msg, :u64)
    {funding_pubkey, msg} = Messaging.par(msg, :pk)
    {dummy_tapkey_tweak, msg} = Messaging.par(msg, :u256)
    {payout_script, msg} = Messaging.par(msg, :script)
    {funding_inputs, msg} = Messaging.parse_funding_inputs(msg)
    {change_script, msg} = Messaging.par(msg, :script)
    {cet_adaptor_signatures, msg} = Messaging.parse_cet_adaptor_signatures(msg)
    {refund_signature, msg} = Messaging.parse_signature(msg)

    accept = %__MODULE__{
      version: version,
      chain_hash: chain_hash,
      contract_id: contract_id,
      offer_id: offer_id,
      funding_pubkey: funding_pubkey,
      dummy_tapkey_tweak: dummy_tapkey_tweak,
      payout_script: payout_script,
      change_script: change_script,
      collateral_amount: collateral_amount,
      funding_inputs: funding_inputs,
      cet_adaptor_signatures: cet_adaptor_signatures,
      refund_signature: refund_signature
    }

    {accept, msg}
  end

  # CET sigs must be ordered the same as the outcomes
  @type cet_adaptor_signature :: %{
          # BREAK WITH DLC Spec
          # txid: <<_::256>>,
          # pubkey: Point.t(),
          adaptor_signature: Signature.t(),
          was_negated: boolean()
        }

  def new_adaptor_signature(sig, was_negated),
    do: %{adaptor_signature: sig, was_negated: was_negated}

  # unimplemented
  def serialize_negotiation_fields(_), do: <<>>
  def serialize_tlvs(_), do: <<>>
end

defmodule ExFacto.Contract.Acknowledge do
  alias ExFacto.Messaging
  alias Bitcoinex.Transaction.{Witness}
  alias Bitcoinex.Secp256k1.{Signature}

  @type t :: %__MODULE__{
          contract_id: <<_::256>>,
          # TODO: decide to send witness or full tx
          funding_witnesses: list(Witness.t()),
          cet_adaptor_signatures: list(%{adaptor_signature: Signature.t(), was_negated: boolean}),
          refund_signature: Signature.t()
        }

  defstruct [
    :contract_id,
    :funding_witnesses,
    :cet_adaptor_signatures,
    :refund_signature
  ]

  @enforce_keys [
    :contract_id
  ]

  @spec new(
          String.t(),
          list(Witness.t()),
          list(%{adaptor_signature: Signature.t(), was_negated: boolean}),
          Signature.t()
        ) :: t()
  def new(contract_id, funding_witnesses, cet_sigs, refund_sig) do
    %__MODULE__{
      contract_id: contract_id,
      funding_witnesses: funding_witnesses,
      cet_adaptor_signatures: cet_sigs,
      refund_signature: refund_sig
    }
  end

  @spec serialize(t()) :: binary
  def serialize(ack = %__MODULE__{}) do
    ack.contract_id <>
      Messaging.serialize_funding_witnesses(ack.funding_witnesses) <>
      Messaging.serialize_cet_adaptor_signatures(ack.cet_adaptor_signatures) <>
      Messaging.ser(ack.refund_signature, :signature)
  end

  @spec parse(binary) :: {t(), binary}
  def parse(msg) do
    {contract_id, msg} = Messaging.par(msg, 32)
    {funding_witnesses, msg} = Messaging.parse_funding_witnesses(msg)
    {cet_adaptor_sigs, msg} = Messaging.parse_cet_adaptor_signatures(msg)
    {refund_sig, msg} = Messaging.par(msg, :signature)

    ack = %__MODULE__{
      contract_id: contract_id,
      funding_witnesses: funding_witnesses,
      cet_adaptor_signatures: cet_adaptor_sigs,
      refund_signature: refund_sig
    }

    {ack, msg}
  end
end
