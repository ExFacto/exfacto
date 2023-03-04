defmodule ExFacto.Contract do
  # import Bitwise

  alias ExFacto.{Utils, Oracle, Messaging}

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

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#single_contract_info
  def serialize(c) do
    Messaging.ser(c.total_collateral, :u64) <>
    serialize_contract_descriptor(c.descriptor) <>
    Oracle.serialize_oracle_info(c.oracle_info)
  end

  # @type contract_descriptor :: contract_descriptor_enum

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#enumerated_contract_descriptor
  @type contract_descriptor_enum :: %{ String.t() => non_neg_integer() }

  def serialize_contract_descriptor(e) do
    {ct, ser_outcomes} =
      e
      |> Map.to_list()
      |> Utils.serialize_with_count(&serialize_outcome_payout/1)
    Utils.big_size(ct) <> ser_outcomes
  end

  def serialize_outcome_payout({outcome, payout}) do
    Messaging.serialize_outcome(outcome) <> Messaging.ser(payout, :u64)
  end

  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#numeric_outcome_contract_descriptor
  # @type numeric_descriptor :: %{
  #   num_digits: non_neg_integer(),
  #   payout_func: payout_func(),
  #   rounding_intervals: list(any()),
  # }


  def calculate_contract_id(<<funding_txid::big-size(256)>>, funding_vout, <<contract_temp_id::big-size(256)>>) do
    # why does the spec say the vout will only affect the last 2 bytes of the txid XOR temp_id when vout is 4 bytes
    # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Protocol.md#definition-of-contract_id
    vout_binary = Bitwise.band(funding_vout, 0xFFFF)
    Bitwise.bxor(funding_txid, contract_temp_id)
    |> Bitwise.bxor(vout_binary)
    |> :binary.encode_unsigned()
  end
end

defmodule ExFacto.Contract.Offer do
  alias ExFacto.{Messaging, Utils, Contract}
  alias Bitcoinex.Secp256k1.{Point, Signature }
  alias Bitcoinex.Script

  @offer_dlc_type 42778

  @type t :: %__MODULE__{
          version: non_neg_integer(),
          contract_flags: non_neg_integer(),
          chain_hash: <<_::256>>,
          temp_contract_id: <<_::256>>,
          contract_info: Contract.t(), # TODO type?
          funding_pubkey: Point.t(),
          payout_script: Script.t(),
          payout_serial_id: non_neg_integer(),
          offer_collateral_amount: non_neg_integer(),
          funding_inputs: list(), # funding_input type
          change_script: Script.t(),
          change_serial_id: non_neg_integer(),
          fund_output_serial_id: non_neg_integer(),
          feerate: non_neg_integer(),
          cet_locktime: non_neg_integer(),
          refund_locktime: non_neg_integer(),
          tlvs: list()
        }

  defstruct [
    :version,
    :contract_flags,
    :chain_hash,
    :temp_contract_id,
    :contract_info,
    :funding_pubkey,
    :payout_script,
    :payout_serial_id,
    :offer_collateral_amount,
    :funding_inputs,
    :change_script,
    :change_serial_id,
    :fund_output_serial_id,
    :feerate,
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
        offer_collateral_amount,
        funding_inputs,
        feerate,
        cet_locktime,
        refund_locktime
      ) do
    version = Utils.get_protocol_version()
    contract_flags = 0

    temp_contract_id = new_temp_contract_id()
    payout_serial_id = Utils.new_serial_id()
    change_serial_id = Utils.new_serial_id()
    fund_output_serial_id = Utils.new_serial_id()

    %__MODULE__{
      version: version,
      contract_flags: contract_flags,
      chain_hash: chain_hash,
      temp_contract_id: temp_contract_id,
      contract_info: contract_info,
      funding_pubkey: funding_pubkey,
      payout_script: payout_script,
      payout_serial_id: payout_serial_id,
      offer_collateral_amount: offer_collateral_amount,
      funding_inputs: funding_inputs,
      change_script: change_script,
      change_serial_id: change_serial_id,
      fund_output_serial_id: fund_output_serial_id,
      feerate: feerate,
      cet_locktime: cet_locktime,
      refund_locktime: refund_locktime
      # TODO TLVs
    }
  end

  def serialize(o = %__MODULE__{}) do
    Messaging.ser(o.version, :u32) <>
      Messaging.ser(o.contract_flags, :u8) <>
      o.chain_hash <>
      o.temp_contract_id <>
      Contract.serialize(o.contract_info) <>
      Point.x_bytes(o.funding_pubkey) <>
      Utils.script_with_big_size(o.payout_script) <>
      Messaging.ser(o.payout_serial_id, :u64) <>
      Messaging.ser(o.offer_collateral_amount, :u64) <>
      Messaging.serialize_funding_inputs(o.funding_inputs) <>
      Utils.script_with_big_size(o.change_script) <>
      Messaging.ser(o.change_serial_id, :u64) <>
      Messaging.ser(o.fund_output_serial_id, :u64) <>
      Messaging.ser(o.feerate, :u64) <>
      Messaging.ser(o.cet_locktime, :u32) <>
      Messaging.ser(o.refund_locktime, :u32) <>
      serialize_offer_tlvs(o.tlvs)
  end

  # unimplemented
  def serialize_offer_tlvs(nil), do: <<>>

  # TODO fix. should be sha256 of offer
  def new_temp_contract_id(), do: <<0x00::little-size(256)>>
end

defmodule ExFacto.Contract.Accept do
  alias Bitcoinex.Secp256k1.{Point, Signature}
  alias ExFacto.{Utils, Messaging}

  @accept_dlc_type 42780

  @type t :: %__MODULE__{
    version: non_neg_integer(),
    chain_hash: <<_::256>>,
    temp_contract_id: String.t(),
    funding_pubkey: Point.t(),
    payout_script: Script.t(),
    payout_serial_id: non_neg_integer(),
    change_script: Script.t(),
    change_serial_id: non_neg_integer(),
    collateral_amount: non_neg_integer(),
    funding_inputs: list(Messaging.funding_input_info()),
    cet_adaptor_signatures: list({Signature.t(), bool}),
    refund_signature: Signature.t(),
    negotiation_fields: list(), # unused
    tlvs: list(), # unused
  }

  defstruct [
    :version,
    :chain_hash,
    :temp_contract_id,
    :funding_pubkey,
    :payout_script,
    :payout_serial_id,
    :change_script,
    :change_serial_id,
    :collateral_amount,
    :funding_inputs,
    :cet_adaptor_signatures,
    :refund_signature,
    :negotiation_fields,
    :tlvs
  ]

  def new(chain_hash, temp_contract_id, funding_pubkey, payout_script, change_script, collateral_amount, funding_inputs, cet_adaptor_signatures, refund_signature) do
    version = Utils.get_protocol_version()

    payout_serial_id = Utils.new_serial_id()

    change_serial_id = Utils.new_serial_id()

    %__MODULE__{
      version: version,
      chain_hash: chain_hash,
      temp_contract_id: temp_contract_id,
      funding_pubkey: funding_pubkey,
      payout_script: payout_script,
      payout_serial_id: payout_serial_id,
      change_script: change_script,
      change_serial_id: change_serial_id,
      collateral_amount: collateral_amount,
      funding_inputs: funding_inputs,
      cet_adaptor_signatures: cet_adaptor_signatures,
      refund_signature: refund_signature,
      # TODO: negotiation_fields
      # TODO: TLVs
    }
  end

  def serialize(a = %__MODULE__{}) do
    Messaging.ser(a.version, :u32) <>
      a.chain_hash <>
      a.temp_contract_id <>
      Messaging.ser(a.collateral_amount, :u64) <>
      Point.x_bytes(a.funding_pubkey) <>
      Utils.script_with_big_size(a.payout_script) <>
      Messaging.ser(a.payout_serial_id, :u64) <>
      Messaging.serialize_funding_inputs(a.funding_inputs) <>
      Utils.script_with_big_size(a.change_script) <>
      Messaging.ser(a.change_serial_id, :u64) <>
      serialize_cet_adaptor_signatures(a.cet_adaptor_signatures) <>
      Signature.serialize_signature(a.refund_signature) <>
      serialize_negotiation_fields(a.negotiation_fields) <>
      serialize_tlvs(a.tlvs)
  end

  @type cet_adaptor_signature :: %{
    # BREAK WITH DLC Spec
    txid: <<_::256>>,
    pubkey: Point.t(),
    adaptor_signature: Signature.t(),
    was_negated: boolean()
  }

def serialize_cet_adaptor_signatures(cet_adaptor_signatures) do
{ct, ser_sigs} = Utils.serialize_with_count(cet_adaptor_signatures, &serialize_cet_adaptor_signature/1)
Utils.big_size(ct) <> ser_sigs
end

# BREAK WITH DLC SPEC to use Schnorr Adaptor Sigs
def serialize_cet_adaptor_signature(cas) do
cas.txid <>
Point.x_bytes(cas.pubkey) <>
Signature.serialize_signature(cas.adaptor_signature) <>
Messaging.ser(cas.was_negated, :bool)
end

  # unimplemented
  def serialize_negotiation_fields(_), do: <<>>
  def serialize_tlvs(_), do: <<>>
end
