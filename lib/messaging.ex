defmodule ExFacto.Messaging do
  alias ExFacto.{Utils, Contract}
  alias Bitcoinex.{Script, Transaction}
  alias Bitcoinex.Secp256k1.{Point, Signature}

  def ser(false, :bool), do: <<0x00>>
  def ser(true, :bool), do: <<0x01>>
  def ser(i, :u8), do: <<i::big-size(8)>>
  def ser(i, :u16), do: <<i::big-size(16)>>
  def ser(i, :u32), do: <<i::big-size(32)>>
  def ser(i, :u64), do: <<i::big-size(64)>>
  def ser(utf8_str, :utf8), do: utf8_str |> String.normalize(:nfc) |> Utils.with_big_size()
  def ser(nil, :script), do: <<0x00>>

  def ser(script, :script) do
    Utils.script_with_big_size(script)
  end

  @type sha256 :: <<_::256>>

  @type outcome :: %{
          data: String.t(),
          payout: non_neg_integer()
        }

  def ser_enumerated_contract_descriptor(outcomes) do
    {ct, ser_outcomes} = Utils.serialize_with_count(outcomes, &serialize_enumerated_outcome/1)
    Utils.big_size(ct) <> ser_outcomes
  end

  defp serialize_enumerated_outcome(%{data: data, payout: payout}) do
    ser(data, :utf8) <> ser(payout, :u64)
  end

  # @type numeric_outcome_contract :: %{
  #         num_digits: non_neg_integer(),
  #         payout_function: payout_function(),
  #         rounding_intervals: rounding_intervals()
  #       }

  # def ser_numeric_outcome_contract_descriptor(contract) do
  #   ser(contract.num_digits, :u16) <>
  #     serialize_payout_function(contract.payout_function) <>
  #     serialize_rouding_intervals(contract.rounding_intervals)
  # end

  # def ser_single_oracle_info(announcement) do
  #   Announcement.serialize(announcement)
  # end

  # SKIP: multi_oracle_info

  @type funding_input_info :: %{
          prev_tx: Transaction.t(),
          prev_vout: non_neg_integer(),
          sequence: non_neg_integer(),
          max_witness_len: non_neg_integer(),
          redeem_script: Script.t()
        }

  @spec new_funding_input_info(Transaction.t(), non_neg_integer(), non_neg_integer(), non_neg_integer(), Script.t() | nil) :: funding_input_info()
  def new_funding_input_info(prev_tx, prev_vout, sequence, max_witness_len, redeem_script) do
    %{
      prev_tx: prev_tx,
      prev_vout: prev_vout,
      sequence: sequence,
      max_witness_len: max_witness_len,
      redeem_script: redeem_script
    }
  end

  def serialize_funding_inputs(inputs) do
    {ct, ser_inputs} = Utils.serialize_with_count(inputs, &ser_funding_input/1)
    Utils.big_size(ct) <> ser_inputs
  end

  def ser_funding_input(input) do
    prev_tx_bytes = Transaction.Utils.serialize(input.prev_tx)

    Utils.with_big_size(prev_tx_bytes) <>
      ser(input.prev_vout, :u32) <>
      ser(input.sequence, :u32) <>
      ser(input.max_witness_len, :u16) <>
      ser(input.redeem_script, :script)
  end

  def serialize_outcome(outcome), do: ser(outcome, :utf8)

  def serialize_funding_signatures(_funding_signatures) do
    # TODO
  end

  @type enum_event_descriptor :: list(String.t())

  def ser_enum_event_descriptor(outcomes) do
    {ct, ser_outcomes} = Utils.serialize_with_count(outcomes, &serialize_outcome/1)
    ser(ct, :u16) <> ser_outcomes
  end

  # @type numeric_event_descriptor(%{
  #         base: integer(),
  #         signed: boolean(),
  #         unit: String.t(),
  #         precision: integer(),
  #         digit_count: integer()
  #       })

  # def numeric_event_descriptor(event) do
  #   Utils.big_size(event.base) <>
  #     ser(event.is_signed, :bool) <>
  #     ser(event.unit, :utf8) <>
  #     ser(event.precision, :i32) <>
  #     ser(event.digit_count, :u16)
  # end

  #### TYPES ####
  def msg_types(),
    do: %{
      42778 => :offer_dlc,
      42780 => :accept_dlc,
      55400 => :oracle_attestation,
      55332 => :oracle_announcement,
      55330 => :oracle_event
    }

  def event_descriptor_types(),
    do: %{
      55302 => :enum_event_descriptor,
      55306 => :digit_decomposition_event_descriptor
    }

  def contract_info_types(),
    do: %{
      0 => :single_contract_info,
      1 => :disjoint_contract_info
    }

  def contract_descriptor_types(),
    do: %{
      0 => :enumerated_contract_descriptor,
      1 => :numeric_outcome_contract_descriptor
    }

  def oracle_info_types(),
    do: %{
      0 => :single_oracle_info,
      1 => :multi_oracle_info
    }

  def negotiation_field_types(),
    do: %{
      0 => :single_negotiation_fields,
      1 => :disjoint_negotiation_fields
    }

  #### PARSER ####
  #
  ################

  # TODO maybe switch arg order?
  def par(<<0x00, rest::binary>>, :bool), do: {false, rest}
  def par(<<0x01, rest::binary>>, :bool), do: {true, rest}
  def par(<<data::big-size(8), rest::binary>>, :u8), do: {data, rest}
  def par(<<data::big-size(16), rest::binary>>, :u16), do: {data, rest}
  def par(<<data::big-size(32), rest::binary>>, :u32), do: {data, rest}
  def par(<<data::big-size(64), rest::binary>>, :u64), do: {data, rest}
  def par(bin, :utf8), do: Utils.parse_compact_size_value(bin)
  def par(<<0x00, rest::binary>>, :script), do: {nil, rest}

  def par(msg, :script) do
    {script_bin, msg} = Utils.parse_compact_size_value(msg)
    {:ok, script} = Script.parse_script(script_bin)
    {script, msg}
  end

  def par(bin, len) when is_integer(len) do
    <<bin::binary-size(len), rest::binary>> = bin
    {bin, rest}
  end

  def parse_items(msg, 0, items, _), do: {Enum.reverse(items), msg}
  def parse_items(msg, ct, items, parse_func) do
    {item, msg} = parse_func.(msg)
    parse_items(msg, ct-1, [item | items], parse_func)
  end

  def parse_signature(<<sig::binary-size(64), msg::binary>>) do
    {:ok, sig} = Signature.parse_signature(sig)
    {sig, msg}
  end

  def parse(msg) do
    {type, msg} = Utils.parse_compact_size_value(msg)
    type_atom = Map.fetch!(msg_types(), :binary.decode_unsigned(type))
    parser(type_atom, msg)
  end

  # TODO make defp

  def parser(:offer_dlc, msg) do
    {version, msg} = par(msg, :u32)
    {contract_flags, msg} = par(msg, :u8)
    {chain_hash, msg} = par(msg, 32)
    {temp_contract_id, msg} = par(msg, 32)
    {contract_info, msg} = parser(:contract_info, msg)
    {funding_pk_bin, msg} = par(msg, 32)
    {:ok, funding_pubkey} = Point.lift_x(funding_pk_bin)
    {payout_script_bin, msg} = Utils.parse_compact_size_value(msg)
    {:ok, payout_script} = Script.parse_script(payout_script_bin)
    {offer_collateral_amount, msg} = par(msg, :u64)
    {funding_inputs, msg} = parser(:funding_inputs, msg)
    {change_script_bin, msg} = Utils.parse_compact_size_value(msg)
    {:ok, change_script} = Script.parse_script(change_script_bin)
    {fee_rate, msg} = par(msg, :u64)
    {cet_locktime, msg} = par(msg, :u32)
    {refund_locktime, _msg} = par(msg, :u32)
    # TODO: TLVs

    # TODO: use new
    %Contract.Offer{
      version: version,
      contract_flags: contract_flags,
      chain_hash: chain_hash,
      temp_contract_id: temp_contract_id,
      contract_info: contract_info,
      funding_pubkey: funding_pubkey,
      payout_script: payout_script,
      collateral_amount: offer_collateral_amount,
      funding_inputs: funding_inputs,
      change_script: change_script,
      fee_rate: fee_rate,
      cet_locktime: cet_locktime,
      refund_locktime: refund_locktime
    }
  end

  def parser(:accept_dlc, msg) do
    {version, msg} = par(msg, :u32)
    {chain_hash, msg} = par(msg, 32)
    {temp_contract_id, msg} = par(msg, 32)
    {collateral_amount, msg} = par(msg, :u64)
    {funding_pk_bin, msg} = par(msg, 32)
    {:ok, funding_pubkey} = Point.lift_x(funding_pk_bin)
    {payout_script_bin, msg} = Utils.parse_compact_size_value(msg)
    {:ok, payout_script} = Script.parse_script(payout_script_bin)
    {funding_inputs, msg} = parser(:funding_inputs, msg)
    {change_script_bin, msg} = Utils.parse_compact_size_value(msg)
    {:ok, change_script} = Script.parse_script(change_script_bin)
    {cet_adaptor_signatures, msg} = parser(:cet_adaptor_signatures, msg)
    {refund_signature, _msg} = parse_signature(msg)
    # TODO: negotation_fields
    # TODO: tlvs

    %Contract.Accept{
      version: version,
      chain_hash: chain_hash,
      temp_contract_id: temp_contract_id,
      funding_pubkey: funding_pubkey,
      payout_script: payout_script,
      change_script: change_script,
      collateral_amount: collateral_amount,
      funding_inputs: funding_inputs,
      cet_adaptor_signatures: cet_adaptor_signatures,
      refund_signature: refund_signature
    }
  end

  # def parser(:oracle_announcement, msg), do: Announcement.parse(msg)

  # def parser(:oracle_attestation, msg), do: Attestation.parse(msg)

  # def parser(:oracle_event, msg), do: Event.parse(msg)

  # def parser(:funding_inputs, msg) do
  # end

  # def parser(:cet_adaptor_signatures, msg) do
  # end

  # def parser(:contract_info, msg) do
  # end

  # unused
  # def parse_outcomes(0, msg, outcomes), do: {Enum.reverse(outcomes), msg}

  # def parse_outcomes(ct, msg, outcomes) do
  #   {outcome, msg} = par(msg, :utf8)
  #   parse_outcomes(ct - 1, msg, [outcome | outcomes])
  # end

  def parse_funding_inputs(0, msg, inputs), do: {Enum.reverse(inputs), msg}

  def parse_funding_inputs(ct, msg, inputs) do
    {input, msg} = parse_funding_input(msg)
    parse_funding_inputs(ct - 1, msg, [input | inputs])
  end

  def parse_funding_input(msg) do
    {prev_tx, msg} = Utils.parse_compact_size_value(msg)
    {:ok, tx} = Transaction.decode(prev_tx)
    {prev_vout, msg} = par(msg, :u32)
    {sequence, msg} = par(msg, :u32)
    {max_witness_len, msg} = par(msg, :u16)
    {redeem_script, msg} = par(msg, :script)

    {%{
       prev_tx: tx,
       prev_vout: prev_vout,
       sequence: sequence,
       max_witness_len: max_witness_len,
       redeem_script: redeem_script
     }, msg}
  end
end
