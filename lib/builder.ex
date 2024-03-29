defmodule ExFacto.Builder do
  alias ExFacto.Utils
  alias Bitcoinex.{Transaction, Script, Taproot}
  alias Bitcoinex.Secp256k1.{Signature, Point}
  alias Bitcoinex.Transaction.{In, Out}

  @tx_version 2
  @default_sequence 0xFFFFFFFE
  @default_locktime 0
  # sighash default
  @default_cet_hash_type 0x00

  def new_output(value, scriptpubkey),
    do: %Out{value: value, script_pub_key: Script.to_hex(scriptpubkey)}

  def build_funding_tx(inputs, funding_output, change_outputs) when is_list(inputs) do
    # sort outputs and find funding vout
    outputs = Out.lexicographical_sort_outputs([funding_output | change_outputs])
    funding_vout = Enum.find_index(outputs, fn output -> output == funding_output end)
    # build and sort inputs
    inputs =
      inputs
      |> Enum.map(&funding_input_to_txin/1)
      |> In.lexicographical_sort_inputs()

    funding_tx = %Transaction{
      version: @tx_version,
      inputs: inputs,
      outputs: outputs,
      lock_time: @default_locktime
    }

    funding_txid = Transaction.transaction_id(funding_tx)

    # settlement_txin used as single input to CETs & Refund tx
    settlement_txin = build_settlement_txin(funding_txid, funding_vout)

    # TODO: also build and return psbt
    {funding_tx, settlement_txin}
  end

  def funding_input_to_txin(input_info) do
    redeem_script =
      if input_info.redeem_script == nil do
        ""
      else
        input_info.redeem_script
      end

    %In{
      prev_txid: Transaction.transaction_id(input_info.prev_tx),
      prev_vout: input_info.prev_vout,
      script_sig: redeem_script,
      sequence_no: input_info.sequence
    }
  end

  # also verifies that the keyspend path is unspendable
  def build_funding_output(amount, pubkeys, dummy_tapkey_tweak) do
    funding_script = Script.create_tapscript_multisig(length(pubkeys), pubkeys)

    funding_leaf = Taproot.TapLeaf.new(Taproot.bip342_leaf_version(), funding_script)

    # P2TR for funding addr will have no internal key. Only way to spend is to satisfy the 2-of-2
    # TODO: when MuSig is implemented, the KeySpend route can act as 2-of-2 instead, and is cheaper and way more private
    {:ok, funding_scriptpubkey, _r} =
      Script.create_p2tr_script_only(funding_leaf, dummy_tapkey_tweak)

    funding_output = %Out{
      value: amount,
      script_pub_key: Script.to_hex(funding_scriptpubkey)
    }

    valid =
      Script.validate_unsolvable_internal_key(
        funding_scriptpubkey,
        funding_leaf,
        dummy_tapkey_tweak
      )

    if !valid,
      do:
        raise(
          "invalid internal key, keypath spend not provably unspendable. Foul play suspected."
        )

    # nonce r is returned to allow others to verify that the keyspend path is unsolvable
    {funding_output, funding_leaf, dummy_tapkey_tweak}
  end

  def build_refund_tx(
        settlement_txin,
        total_collateral,
        offer_collateral_amount,
        accept_payout_script,
        offer_payout_script,
        locktime
      ) do
    accept_collateral = total_collateral - offer_collateral_amount
    accept_refund_output = Builder.new_output(accept_collateral, accept_payout_script)
    offer_refund_output = Builder.new_output(offer_collateral_amount, offer_payout_script)

    # sort outputs
    outputs =
      [accept_refund_output, offer_refund_output]
      |> Out.lexicographical_sort_outputs()

    %Transaction{
      version: @tx_version,
      inputs: [settlement_txin],
      outputs: outputs,
      witnesses: nil,
      lock_time: locktime
    }

    # TODO also build PSBT
  end

  # returns list({outcome, cet_tx})
  def build_all_cets(
        settlement_txin,
        total_collateral,
        offer_script,
        accept_script,
        contract_descriptor,
        locktime
      ) do
    build_cet = fn {outcome, payout} ->
      build_cet_tx(
        settlement_txin,
        total_collateral,
        offer_script,
        accept_script,
        {outcome, payout},
        locktime
      )
    end

    Enum.map(contract_descriptor, build_cet)
  end

  def build_cet_tx(
        settlement_txin,
        total_collateral,
        offer_script,
        accept_script,
        {outcome, offer_payout},
        locktime
      ) do
    offer_output = new_output(offer_payout, offer_script)

    # fee is the diff of funding_input.prev_amount - total_collateral
    # and is handled when creating funding tx
    accept_payout = total_collateral - offer_payout
    accept_output = new_output(accept_payout, accept_script)

    outputs =
      [
        offer_output,
        accept_output
      ]
      |> Out.lexicographical_sort_outputs()

    {outcome,
     %Transaction{
       version: @tx_version,
       inputs: [settlement_txin],
       outputs: outputs,
       lock_time: locktime
     }}
  end

  def build_txin(txid, vout, sequence) do
    %In{
      prev_txid: txid,
      prev_vout: vout,
      script_sig: "",
      sequence_no: sequence
    }
  end

  def build_settlement_txin(funding_txid, funding_vout),
    do: build_txin(funding_txid, funding_vout, @default_sequence)

  def funding_control_block(funding_pubkey, funding_leaf) do
    # funding output script tree only has 1 leaf, so index must be 0
    control_block = Taproot.build_control_block(funding_pubkey, funding_leaf, 0)
    control_block_hex = control_block |> Base.encode16(case: :lower)

    funding_script_hex = Script.to_hex(funding_leaf.script)

    {funding_script_hex, control_block_hex}
  end

  # list of funding_input_infos
  @spec sum_input_amounts(list(any)) :: non_neg_integer()
  def sum_input_amounts(funding_input_infos) do
    Enum.reduce(funding_input_infos, 0, fn info, sum ->
      prev_out = Enum.at(info.prev_tx.outputs, info.prev_vout)
      sum + prev_out.value
    end)
  end

  # TX Size & Fee calculations
  @dust_limit 1000
  @wu_per_vbyte 4
  @wu_per_vbyte_f 4.0

  @doc """
  p2wpkh witness: 108 bytes (non-Low R)
  - number_of_witness_elements: 1 byte
  - sig_length: 1 byte
  - sig: 72 bytes
  - pub_key_length: 1 byte
  - pub_key: 33 bytes
  """
  @spec max_witness_len_p2wpkh :: 108
  def max_witness_len_p2wpkh(), do: 108

  @doc """
  p2tr-keyspend: 64 bytes
  - sig: 64 bytes
  """
  @spec max_witness_len_p2tr_keyspend :: 64
  def max_witness_len_p2tr_keyspend(), do: 64
  # p2tr-scriptspend: ???
  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
  @spec tx_version_wu :: 16
  def tx_version_wu(), do: 4 * @wu_per_vbyte
  # Assumptions for any reasonably small tx. Maybe update
  @spec tx_in_ct_wu :: 4
  def tx_in_ct_wu(), do: 1 * @wu_per_vbyte
  @spec tx_out_ct_wu() :: 4
  def tx_out_ct_wu(), do: 1 * @wu_per_vbyte
  @spec tx_wit_header_wu :: 2
  def tx_wit_header_wu(), do: 2
  @spec tx_locktime_wu :: 16
  def tx_locktime_wu(), do: 4 * @wu_per_vbyte

  @doc """
  Inputs
  - 32 byte txid
  - 4 byte vout
  - 4 byte sequence
  - 1 + len(script_sig)
  """
  @spec txin_outpoint_wu :: 144
  def txin_outpoint_wu(), do: 36 * @wu_per_vbyte
  @spec txin_sequence_wu :: 16
  def txin_sequence_wu(), do: 4 * @wu_per_vbyte
  @spec txin_empty_scriptsig_wu :: 4
  def txin_empty_scriptsig_wu(), do: 1 * @wu_per_vbyte

  # Witness
  @spec txwit_items_ct_wu :: 1
  def txwit_items_ct_wu(), do: 1
  @spec txwit_schnorr_pubkey_wu :: 32
  def txwit_schnorr_pubkey_wu(), do: 32
  @spec txwit_schnorr_sig_wu :: 64
  def txwit_schnorr_sig_wu(), do: 64
  @spec txwit_sha256_wu :: 32
  def txwit_sha256_wu(), do: 32

  # Outputs
  def txout_value_wu(), do: 8 * @wu_per_vbyte
  # P2TR = sz + [0x01 PUSHDATA32 <32-byte pubkey>]
  def txout_scriptpubkey_p2tr_wu(), do: (1 + 34) * @wu_per_vbyte

  def calculate_fee(tx_vbytes, fee_rate), do: tx_vbytes * fee_rate

  def calculate_funding_tx_amounts(
        offer,
        accept_funding_inputs,
        accept_payout_script,
        accept_change_script
      ) do
    total_collateral = offer.contract_info.total_collateral
    accept_collateral = total_collateral - offer.collateral_amount

    accept_funding_tx_vbytes =
      calculate_singleparty_funding_tx_vbytes(accept_funding_inputs, accept_change_script)

    accept_funding_fee = calculate_fee(accept_funding_tx_vbytes, offer.fee_rate)

    accept_settlement_tx_vbytes = calculate_singleparty_cet_tx_vbytes([accept_payout_script])
    accept_settlement_fee = calculate_fee(accept_settlement_tx_vbytes, offer.fee_rate)

    offer_funding_tx_vbytes =
      calculate_singleparty_funding_tx_vbytes(offer.funding_inputs, offer.change_script)

    offer_funding_fee = calculate_fee(offer_funding_tx_vbytes, offer.fee_rate)

    offer_settlement_tx_vbytes = calculate_singleparty_cet_tx_vbytes([offer.payout_script])
    offer_settlement_fee = calculate_fee(offer_settlement_tx_vbytes, offer.fee_rate)

    # funding output will have the fees necessary to pay for the settlement tx
    funding_amount = total_collateral + accept_settlement_fee + offer_settlement_fee

    accept_input_sats = sum_input_amounts(accept_funding_inputs)
    offer_input_sats = sum_input_amounts(offer.funding_inputs)

    accept_change_amount =
      accept_input_sats - accept_collateral - accept_funding_fee - accept_settlement_fee

    offer_change_amount =
      offer_input_sats - offer.collateral_amount - offer_funding_fee - offer_settlement_fee

    {funding_amount, accept_change_amount, offer_change_amount}
  end

  def calculate_singleparty_funding_tx_vbytes(funding_input_infos, change_script) do
    # fixed cost is shared equally
    # 42
    fixed_wu = tx_fixed_wu()
    # 21
    fixed_wu = Float.ceil(fixed_wu / 2.0)

    {inputs_wu, witness_wu} = calculate_inputs_wu(funding_input_infos)

    # funding output cost is shared equally
    funding_output_wu = half(p2tr_output_wu())

    outputs_wu = calculate_outputs_wu([change_script]) + funding_output_wu

    total_wu = fixed_wu + inputs_wu + outputs_wu + witness_wu

    wu_to_vbyte(total_wu)
  end

  # offer
  # input: 164 = 41 * 4
  # output: 212 = ( 9 + 22 + ceil(43/2) ) +  * 4
  # witness: 109 = 1 + 108
  # 105 = ceil((21 + 164 + 212 + 109) / 4)

  def calculate_singleparty_cet_tx_vbytes(scriptpubkeys) do
    fixed_wu = tx_fixed_wu()

    # fixed cost is shared equally
    fixed_wu = Float.ceil(fixed_wu / 2.0)

    # 1 funding input
    # TODO(BTCRPC): lookup prev_input or get this info from user
    {inputs_wu, witness_wu} =
      calculate_inputs_wu([
        %{
          max_witness_len: calculate_2_of_2_tapscript_spend_wu()
        }
      ])

    # funding input cost is shared equally
    inputs_wu = half(inputs_wu)

    outputs_wu = calculate_outputs_wu(scriptpubkeys)

    total_wu = fixed_wu + inputs_wu + outputs_wu + witness_wu

    wu_to_vbyte(total_wu)
  end

  @spec half(number) :: integer
  def half(wu) do
    ceil(wu / 2.0)
  end

  @spec wu_to_vbyte(number) :: integer
  def wu_to_vbyte(wu) do
    # 4wu = 1vB. round up
    ceil(wu / @wu_per_vbyte_f)
  end

  # correct
  @spec tx_fixed_wu :: 42
  def tx_fixed_wu() do
    tx_version_wu() +
      tx_in_ct_wu() +
      tx_out_ct_wu() +
      tx_wit_header_wu() +
      tx_locktime_wu()
  end

  # correct
  @spec p2tr_output_wu :: 172
  def p2tr_output_wu() do
    # 8 + (1 + 34)
    txout_value_wu() + txout_scriptpubkey_p2tr_wu()
  end

  @spec calculate_inputs_wu(list(%{:max_witness_len => non_neg_integer()})) :: any
  def calculate_inputs_wu(inputs) do
    # witness txs have at least 2 witness bytes for header
    Enum.reduce(inputs, {0, 0}, fn input_info, {input_wu, witness_wu} ->
      {
        # 36
        # 4
        # 1 + script_sig len
        input_wu +
          txin_outpoint_wu() +
          txin_sequence_wu() +
          script_sig_wu(input_info),
        # 1
        witness_wu +
          txwit_items_ct_wu() +
          max_witness_wu(input_info)
      }
    end)
  end

  # 1 + len(redeem_script) bytes
  @spec script_sig_wu(%{:redeem_script => Script.t() | nil}) :: non_neg_integer
  def script_sig_wu(input) do
    redeem_script = Map.get(input, :redeem_script, nil)

    if redeem_script == nil || redeem_script == "" do
      txin_empty_scriptsig_wu()
    else
      byte_size(Utils.script_with_big_size(redeem_script)) * @wu_per_vbyte
    end
  end

  def max_witness_wu(input_info) do
    if input_info.max_witness_len == nil do
      txwit_items_ct_wu()
    else
      input_info.max_witness_len
    end
  end

  def calculate_outputs_wu(scriptpubkeys) do
    Enum.reduce(scriptpubkeys, 0, fn script, wu ->
      # 8
      # 1 + len(script)
      wu +
        txout_value_wu() +
        byte_size(Utils.script_with_big_size(script)) * @wu_per_vbyte
    end)
  end

  @spec calculate_2_of_2_tapscript_spend_wu :: 234
  def calculate_2_of_2_tapscript_spend_wu() do
    txwit_items_ct_wu() + 2 * txwit_schnorr_sig_wu() +
      script_2_of_2_tapscript_len() + single_leaf_control_block_len()
  end

  @spec script_2_of_2_tapscript_len :: 71
  def script_2_of_2_tapscript_len() do
    # sz + OP_PUSHDATA32 <pk> OP_CHECKSIG OP_PUSHDATA32 <pk> OP_CHECKSIGADD OP_N OP_NUMEQUAL
    1 + (1 + txwit_schnorr_pubkey_wu() + 1) * 2 + 2
  end

  # len_control_block <> (q_parity&leaf_version) <> (32-byte Q.x)
  @spec single_leaf_control_block_len :: 34
  def single_leaf_control_block_len(), do: 34

  def filter_dust_outputs(outputs) do
    Enum.filter(outputs, fn %{value: value} -> value > @dust_limit end)
  end

  def add_signatures_to_cet(cet_tx, pk_sigs, funding_tapkey, funding_leaf) do
    sorted_signatures =
      sort_signatures_by_pubkey(pk_sigs)
      |> Enum.map(&Signature.to_hex/1)

    build_cet_witness(cet_tx, sorted_signatures, funding_tapkey, funding_leaf)
  end

  def build_cet_witness(cet_tx, sorted_signatures, funding_tapkey, funding_leaf) do
    control_block =
      Taproot.build_control_block(funding_tapkey, funding_leaf, 0)
      |> Base.encode16(case: :lower)

    script = Script.to_hex(funding_leaf.script)

    cet_tx = %Transaction{
      cet_tx
      | witnesses: [
          %Transaction.Witness{
            txinwitness: sorted_signatures ++ [script, control_block]
          }
        ]
    }

    cet_tx
  end

  @spec sort_signatures_by_pubkey(list({Point.t(), Signature.t()})) :: [Signature.t()]
  def sort_signatures_by_pubkey(pk_sigs) do
    pk_sigs_map =
      Enum.reduce(pk_sigs, %{}, fn {pk, sig}, pk_sigs_map -> Map.put(pk_sigs_map, pk, sig) end)

    sorted_pubkeys =
      pk_sigs_map
      |> Map.keys()
      |> Script.lexicographical_sort_pubkeys()

    sorted_sigs = Enum.map(sorted_pubkeys, fn pk -> Map.fetch!(pk_sigs_map, pk) end)
    # because Script is evaluated as stack, must reverse signatures order
    Enum.reverse(sorted_sigs)
  end

  def build_signed_cet(
        unsigned_cet_tx,
        funding_leaf,
        dummy_tapkey_tweak,
        signatures,
        cet_hash_type \\ @default_cet_hash_type
      ) do
    cet_hash_byte =
      if cet_hash_type == 0x00 do
        <<>>
      else
        <<cet_hash_type>>
      end

    serialized_sigs =
      Enum.map(signatures, fn sig ->
        (sig <> cet_hash_byte) |> Base.encode16(case: :lower)
      end)

    {:ok, funding_script, _r} = Script.create_p2tr_script_only(funding_leaf, dummy_tapkey_tweak)
    # fund_p is the internal taproot key. In this case, it is unsolvable.
    funding_p = Script.calculate_unsolvable_internal_key(dummy_tapkey_tweak)

    funding_script_hex = Script.to_hex(funding_script)

    # We take fund_leaf, the script_tree, and select the index of the script we want to spend.
    # Here, there is only 1 script in the tree, so idx must be 0
    control_block = Taproot.build_control_block(funding_p, funding_leaf, 0)
    control_block_hex = control_block |> Base.encode16(case: :lower)

    # populate the witness
    %Transaction{
      unsigned_cet_tx
      | witnesses: [
          %Transaction.Witness{
            txinwitness: serialized_sigs ++ [funding_script_hex, control_block_hex]
          }
        ]
    }
  end
end
