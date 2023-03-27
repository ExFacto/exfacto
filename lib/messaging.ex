defmodule ExFacto.Messaging do
  alias ExFacto.{Utils}
  # alias ExFacto.Oracle.{Announcement, Attestation}
  alias Bitcoinex.{Script, Transaction}
  alias Bitcoinex.Transaction.{Witness}
  alias Bitcoinex.Secp256k1.{Point, Signature}

  def ser(false, :bool), do: <<0x00>>
  def ser(true, :bool), do: <<0x01>>
  def ser(i, :u8), do: <<i::big-size(8)>>
  def ser(i, :u16), do: <<i::big-size(16)>>
  def ser(i, :u32), do: <<i::big-size(32)>>
  def ser(i, :u64), do: <<i::big-size(64)>>
  def ser(i, :u256), do: <<i::big-size(256)>>
  def ser(nil, :utf8), do: <<0x00>>
  def ser(utf8_str, :utf8), do: utf8_str |> String.normalize(:nfc) |> Utils.with_big_size()
  def ser(nil, :script), do: <<0x00>>
  def ser("", :script), do: <<0x00>>

  def ser(script, :script) do
    Utils.script_with_big_size(script)
  end

  def ser(pk, :pk), do: Point.x_bytes(pk)
  def ser(sig, :signature), do: Signature.serialize_signature(sig)

  @type sha256 :: <<_::256>>

  @type outcome :: %{
          data: String.t(),
          payout: non_neg_integer()
        }

  def serialize_enumerated_contract_descriptor(outcomes) do
    {ct, ser_outcomes} = Utils.serialize_with_count(outcomes, &serialize_enumerated_outcome/1)
    Utils.big_size(ct) <> ser_outcomes
  end

  defp serialize_enumerated_outcome(%{data: data, payout: payout}) do
    ser(data, :utf8) <> ser(payout, :u64)
  end

  def serialize_cet_adaptor_signatures(cet_adaptor_signatures) do
    {ct, ser_sigs} =
      Utils.serialize_with_count(cet_adaptor_signatures, &serialize_cet_adaptor_signature/1)

    Utils.big_size(ct) <> ser_sigs
  end

  # BREAK WITH DLC SPEC to use Schnorr Adaptor Sigs
  def serialize_cet_adaptor_signature(cas) do
    # cas.txid <>
    # Point.x_bytes(cas.pubkey) <>
    ser(cas.adaptor_signature, :signature) <>
      ser(cas.was_negated, :bool)
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
          redeem_script: Script.t(),
          amount: non_neg_integer()
        }

  @spec new_funding_input_info(
          Transaction.t(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          Script.t() | nil,
          non_neg_integer()
        ) :: funding_input_info()
  def new_funding_input_info(prev_tx, prev_vout, sequence, max_witness_len, redeem_script, amount) do
    %{
      prev_tx: prev_tx,
      prev_vout: prev_vout,
      sequence: sequence,
      max_witness_len: max_witness_len,
      redeem_script: redeem_script,
      amount: amount
    }
  end

  @spec serialize_funding_inputs(list(funding_input_info())) :: binary
  def serialize_funding_inputs(inputs) do
    {ct, ser_inputs} = Utils.serialize_with_count(inputs, &serialize_funding_input/1)
    Utils.big_size(ct) <> ser_inputs
  end

  def serialize_funding_input(input) do
    prev_tx_bytes = Transaction.Utils.serialize(input.prev_tx)

    Utils.with_big_size(prev_tx_bytes) <>
      ser(input.prev_vout, :u32) <>
      ser(input.sequence, :u32) <>
      ser(input.max_witness_len, :u16) <>
      ser(input.redeem_script, :script)
  end

  def serialize_funding_witnesses(witnesses) do
    Utils.big_size(length(witnesses)) <> Witness.serialize_witness(witnesses)
  end

  @type enum_event_descriptor :: list(String.t())

  @spec serialize_enum_event_descriptor(list) :: binary
  def serialize_enum_event_descriptor(outcomes) do
    {ct, ser_outcomes} = Utils.serialize_with_count(outcomes, fn o -> ser(o, :utf8) end)
    ser(ct, :u16) <> ser_outcomes
  end

  @spec parse_cet_adaptor_signatures(nonempty_binary) :: {list(any()), binary}
  def parse_cet_adaptor_signatures(msg) do
    {cet_adaptor_sig_ct, msg} = Utils.get_counter(msg)
    parse_items(msg, cet_adaptor_sig_ct, [], &parse_cet_adaptor_signature/1)
  end

  def parse_cet_adaptor_signature(
        <<sig::binary-size(64), was_negated::binary-size(1), msg::binary>>
      ) do
    {:ok, signature} = Signature.parse_signature(sig)
    {was_negated, _} = par(was_negated, :bool)
    {%{adaptor_signature: signature, was_negated: was_negated}, msg}
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
  #### PARSER ####
  #
  ################

  def par(<<0x00, rest::binary>>, :bool), do: {false, rest}
  def par(<<0x01, rest::binary>>, :bool), do: {true, rest}
  def par(<<data::big-size(8), rest::binary>>, :u8), do: {data, rest}
  def par(<<data::big-size(16), rest::binary>>, :u16), do: {data, rest}
  def par(<<data::big-size(32), rest::binary>>, :u32), do: {data, rest}
  def par(<<data::big-size(64), rest::binary>>, :u64), do: {data, rest}
  def par(<<data::big-size(256), rest::binary>>, :u256), do: {data, rest}
  def par(<<0x00, rest::binary>>, :utf8), do: {"", rest}
  def par(bin, :utf8), do: Utils.parse_compact_size_value(bin)
  def par(<<0x00, rest::binary>>, :script), do: {nil, rest}
  def par(msg, :script), do: parse_script(msg)
  def par(msg, :pk), do: parse_point(msg)
  def par(msg, :signature), do: parse_signature(msg)

  def par(bin, len) when is_integer(len) do
    <<bin::binary-size(len), rest::binary>> = bin
    {bin, rest}
  end

  def parse_script(msg) do
    {script_bin, msg} = Utils.parse_compact_size_value(msg)
    {:ok, script} = Script.parse_script(script_bin)
    {script, msg}
  end

  def parse_signature(<<sig::binary-size(64), msg::binary>>) do
    {:ok, sig} = Signature.parse_signature(sig)
    {sig, msg}
  end

  def parse_point(<<pk::binary-size(32), msg::binary>>) do
    {:ok, point} = Point.lift_x(pk)
    {point, msg}
  end

  def parse_items(msg, 0, items, _), do: {Enum.reverse(items), msg}

  def parse_items(msg, ct, items, parse_func) do
    {item, msg} = parse_func.(msg)
    parse_items(msg, ct - 1, [item | items], parse_func)
  end

  # event EV
  # announcement AN
  # contract_info CI
  # attestation AT
  # offer OF
  # accept AC
  # ack AK

  # def parse(msg) do
  #   {type, msg} = Utils.parse_compact_size_value(msg)
  #   type_atom = Map.fetch!(msg_types(), :binary.decode_unsigned(type))
  #   parse(msg, type_atom)
  # end

  def parse_funding_witnesses(msg) do
    {wit_ct, msg} = Utils.get_counter(msg)
    Transaction.Witness.parse_witness(wit_ct, msg)
  end

  # def parse(msg, :contract_info) do, do: parse_contract_info(msg)

  @spec parse_funding_inputs(nonempty_binary) :: {list(funding_input_info()), binary}
  def parse_funding_inputs(msg) do
    {input_ct, msg} = Utils.get_counter(msg)
    parse_funding_inputs(input_ct, msg, [])
  end

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

    funding_input = %{
      prev_tx: tx,
      prev_vout: prev_vout,
      sequence: sequence,
      max_witness_len: max_witness_len,
      redeem_script: redeem_script
    }

    {funding_input, msg}
  end
end
