defmodule ExFacto.Builder do
  alias Bitcoinex.{Transaction, Script, PSBT}
  alias Bitcoinex.Transaction.{In, Out, Utils}

  @tx_version 2
  @default_sequence 0xFFFFFFFE
  @default_locktime 0

  def new_output(value, scriptpubkey), do: %Out{value: value, script_pub_key: scriptpubkey}

  def build_funding_tx(inputs, outputs) do
    # sort outputs and find funding vout
    outputs = Out.lexicographical_sort_outputs(outputs)
    funding_vout = Enum.find_index(outputs, fn output -> output == funding_output end)
    # build and sort inputs
    inputs =
      Enum.map(inputs, &funding_input_to_txin/1)
      |> In.lexicographical_sort_inputs(inputs)

    funding_tx = %Transaction{
      version: @tx_version,
      inputs: inputs,
      outputs: outputs,
      lock_time: @default_locktime
    }

    # TODO: also build and return psbt
    {funding_tx, funding_vout}
  end

  def funding_input_to_txin(input) do
    %In{
      prev_txid: Transaction.transaction_id(input.prev_tx),
      prev_vout: prev_vout,
      # TODO: accept redeem_script from funding_input_info to allow p2sh inputs
      script_sig: "",
      sequence_no: input.sequence
    }
  end

  def build_funding_output(amount, pubkeys) do
    fund_script = Script.create_tapscript_multisig(length(pubkeys), pubkeys)

    fund_leaf = Taproot.TapLeaf.new(Taproot.bip342_leaf_version(), fund_script)

    # P2TR for funding addr will have no internal key. Only way to spend is to satisfy the 2-of-2
    # TODO: when MuSig is implemented, the KeySpend route can act as 2-of-2 instead, and is cheaper.
    {:ok, fund_scriptpubkey, r} = Script.create_p2tr_script_only(fund_leaf, Utils.new_rand_int())

    funding_output = %Out{
      value: amount,
      script_pub_key: Script.to_hex(fund_scriptpubkey)
    }

    # nonce r is returned to allow others to verify that the keyspend path is unsolvable
    {funding_output, r}
  end

  def build_refund_tx(fund_input, outputs, locktime) do
    %Transaction{
      version: @tx_version,
      inputs: [fund_input],
      outputs: outputs,
      lock_time: locktime
    }

    # TODO also build PSBT
  end

  # returns list({outcome, cet_tx})
  def build_all_cets(fund_input, offerer_script, accepter_script, contract_descriptor, locktime) do
    build_cet = fn outcome_payout ->
      build_cet_tx(fund_input, offerer_script, accepter_script, outcome_payout, locktime)
    end

    Enum.map(contract_descriptor, build_cet)
  end

  def build_cet_tx(
        fund_input,
        offerer_script,
        accepter_script,
        {outcome, offerer_payout},
        locktime
      ) do
    offerer_output = new_output(offerer_payout, offerer_script)

    # fee is the diff of fund_input.prev_amount - total_collateral
    # and is handled when creating funding tx
    accepter_payout = total_collateral - offerer_payout
    accepter_output = new_output(accepter_payout, accepter_script)

    outputs = [
      offerer_output,
      accepter_output
    ]

    {outcome,
     %Transaction{
       version: @tx_version,
       inputs: [fund_input],
       outputs: outputs,
       lock_time: locktime
     }}
  end

  def build_outpoint(txid, vout, sequence) do
    %In{
      prev_txid: txid,
      prev_vout: vout,
      script_sig: "",
      sequence_no: sequence
    }
  end

  def build_funding_outpoint(fund_txid, fund_vout),
    do: build_outpoint(fund_txid, fund_vout, @default_sequence)

  def sum_input_amounts(funding_input_infos) do
    Enum.reduce(funding_input_infos, 0, fn info, sum -> sum + info.amount end)
  end

  # TX Size & Fee calculations
  @dust_limit 1000
  @wu_per_vbyte 4
  @wu_per_vbyte_f 4.0

  # p2wpkh witness: 108 bytes (non-Low R)
  # - number_of_witness_elements: 1 byte
  # - sig_length: 1 byte
  # - sig: 72 bytes
  # - pub_key_length: 1 byte
  # - pub_key: 33 bytes
  @max_witness_len_p2wpkh 108
  # p2tr-keyspend: 64 bytes
  # - sig: 64 bytes
  @max_witness_len_p2tr_keyspend 64
  # p2tr-scriptspend: ???
  # https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
  def tx_version_wu(), do: 4 * @wu_per_vbyte
  def tx_locktime_wu(), do: 4 * @wu_per_vbyte
  def tx_wit_header_wu(), do: 2 * @wu_per_vbyte
  # Assumptions for any reasonably small tx. Maybe update
  def tx_in_ct_wu(), do: 1 * @wu_per_vbyte
  def tx_out_ct_wu(), do: 1 * @wu_per_vbyte

  # Inputs
  def txin_outpoint_wu(), do: 36 * @wu_per_vbyte
  def txin_sequence_wu(), do: 4 * @wu_per_vbyte
  def txin_empty_scriptsig_wu(), do: 1 * @wu_per_vbyte

  # Witness
  def txwit_items_ct_wu(), do: 1
  def txwit_schnorr_pubkey_wu(), do: 32
  def txwit_schnorr_sig_wu(), do: 64
  def txwit_sha256_wu(), do: 32

  # Outputs
  def txout_value_wu(), do: 8 * @wu_per_vbyte
  # Assumption for reasonably small script
  def txout_scriptpukey_len_wu(), do: 1 * @wu_per_vbyte
  # P2TR = [0x01 PUSHDATA32 <32-byte pubkey>]
  def txout_scriptpubkey_p2tr_wu(), do: 34 * @wu_per_vbyte

  def calculate_singleparty_funding_tx_vbytes(funding_input_infos) do
    fixed_wu = tx_fixed_wu()

    # fixed cost is shared equally
    fixed_wu = Float.ceil(fixed_wu / 2.0)

    {inputs_wu, witness_wu} = calculate_inputs_wu(funding_input_infos)

    outputs_wu = p2tr_output_wu()

    total_wu = fixed_wu + inputs_wu + outputs_wu + witness_wu

    wu_to_vbyte(total_wu)
  end

  def calculate_singleparty_cet_tx_vbytes(scriptpubkeys) do
    fixed_wu = tx_fixed_wu()

    # fixed cost is shared equally
    fixed_wu = Float.ceil(fixed_wu / 2.0)

    # 1 funding input
    inputs_wu =
      calculate_inputs_wu(%{
        max_witness_len: calculate_2_of_2_tapscript_spend_wu()
      })

    outputs_wu = calculate_outputs_wu(scriptpubkeys)

    total_wu = fixed_wu + inputs_wu + outputs_wu

    wu_to_vbyte(total_wu)
  end

  def wu_to_vbyte(wu) do
    # 4wu = 1vB. round up
    Float.ceil(total_wu / @wu_per_vbyte_f)
  end

  def tx_fixed_wu() do
    # TODO: what is witness header? where is segwit flag?
    tx_version_wu() + tx_locktime_wu() +
      tx_in_ct_wu() + tx_out_ct_wu() +
      tx_wit_header_wu()
  end

  def p2tr_output_wu() do
    txout_value_wu() + txout_scriptpukey_len_wu() + txout_scriptpubkey_p2tr_wu()
  end

  def calculate_inputs_wu(inputs) do
    Enum.reduce(inputs, {0, tx_wit_header_wu()}, fn input_info, {input_wu, witness_wu} ->
      {input_wu + txin_outpoint_wu() + txin_sequence_wu() + txin_empty_scriptsig_wu(),
       witness_wu + input_info.max_witness_len}
    end)
  end

  def calculate_outputs_wu(scriptpubkeys) do
    Enum.reduce(scriptpubkeys, 0, fn script, wt ->
      wt + txout_value_wu() + txout_scriptpukey_len_wu() + Script.byte_length(script)
    end)
  end

  def calculate_2_of_2_tapscript_spend_wu() do
    txwit_items_ct_wu() + 2 * txwit_schnorr_sig_wu() +
      script_2_of_2_tapscript_len() + single_leaf_control_block_len()
  end

  def script_2_of_2_tapscript_len() do
    # <pk> OP_CHECKSIG .... OP_N OP_NUMEQUAL
    (txwit_schnorr_pubkey_wu() + 1) * 2 + 2
  end

  # (q_parity&leaf_version) <> (32-byte Q.x)
  def single_leaf_control_block_len(), do: 33

  def filter_dust_outputs(outputs) do
    Enum.filter(outputs, fn {amount, _script} -> amount > @dust_limit end)
  end

end
