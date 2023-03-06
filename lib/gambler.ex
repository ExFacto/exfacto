defmodule ExFacto.Gambler do
  @moduledoc """
    a Gambler only lives as long as their contract.
    A Gambler struct contains all the private info
    for a single party to a DLC
  """
  alias ExFacto.{Chain, Utils, Contract}
  alias ExFacto.Contract.{Offer, Accept}
  alias Bitcoinex.Script
  alias Bitcoinex.Secp256k1.{PrivateKey, Point}

  @type t :: %__MODULE__{
          network: Bitcoinex.Network.t(),
          funding_inputs: list(),
          fund_sk: PrivateKey.t(),
          fund_pk: Point.t(),
          change_script: Script.t(),
          payout_script: Script.t()

          # Other info Gambler should keep
          # my_outcome
          # their_outcome
          # my outcome sigpoint
          # their outcome sigpoint
          # fund_amount
          # fund_scriptpubkey
          # fund_leaf # can be built from spk
        }

  defstruct [
    :network,
    :funding_inputs,
    :fund_sk,
    :fund_pk,
    :change_script,
    :payout_script
  ]

  def new(funding_inputs, change_address, payout_address) do
    sk = Utils.new_private_key()
    pk = PrivateKey.to_point(sk)

    {:ok, change_script, change_network} = Script.from_address(change_address)
    {:ok, payout_script, dest_network} = Script.from_address(payout_address)

    if change_network != dest_network do
      {:error, "mismatch networks"}
    else
      %__MODULE__{
        network: Bitcoinex.Network.get_network(change_network),
        funding_inputs: funding_inputs,
        fund_sk: sk,
        fund_pk: pk,
        change_script: change_script,
        payout_script: payout_script
      }
    end
  end

  def create_offer(
        g = %__MODULE__{},
        announcement,
        payouts,
        offer_collateral_amount,
        total_collateral,
        refund_locktime_delta,
        fee_rate
      ) do
    contract_descriptor = Enum.zip(announcement.event.descriptor.outcomes, payouts)

    contract_info = %Contract{
      total_collateral: total_collateral,
      descriptor: contract_descriptor,
      oracle_info: announcement
    }

    Offer.new(
      Chain.chain_hash(g.network.name),
      contract_info,
      offer_collateral_amount,
      g.funding_inputs,
      g.fund_pk,
      g.payout_script,
      g.change_script,
      fee_rate,
      announcement.maturity_epoch,
      announcement.maturity_epoch + refund_locktime_delta
    )
  end

  def create_accept(g = %__MODULE__{}, offer = %Offer{}) do
    if Chain.chain_hash(g.network.name) != offer.chain_hash do
      {:error, "mismatch networks"}
    else
      funding_pubkeys = [g.fund_pk, offer.funding_pubkey]

      accept_collateral = total_collateral - offer.collateral

      offer_refund_output = Builder.new_output(offer.collateral, offer.payout_script)
      accept_refund_output = Builder.new_output(accept_collateral, g.payout_script)

      inputs = g.funding_inputs ++ offer.funding_inputs

      # Since the amounts don't affect the tx size, we can use the refund outputs
      accept_funding_tx_vbytes = calculate_singleparty_funding_tx_vbytes(g.funding_inputs)
      accept_funding_fee = calculate_fee(accept_settlement_tx_vbytes, offer.fee_rate)

      accept_settlement_tx_vbytes = calculate_singleparty_cet_tx_vbytes([g.payout_script])
      accept_settlement_fee = calculate_fee(accept_settlement_tx_vbytes, offer.fee_rate)

      offer_funding_tx_vbytes = calculate_singleparty_funding_tx_vbytes(offer.funding_inputs)
      offer_funding_fee = calculate_fee(offer_funding_tx_vbytes, offer.fee_rate)

      offer_settlement_tx_vbytes = calculate_singleparty_cet_tx_vbytes([offer.payout_script])
      offer_settlement_fee = calculate_fee(offer_settlement_tx_vbytes, offer.fee_rate)

      accept_input_sats = sum_input_amounts(g.funding_inputs)
      offer_input_sats = sum_input_amounts(offer.funding_inputs)

      # funding output will have the fees necessary to pay for the settlement tx
      funding_amount = total_collateral + accept_settlement_fee + offer_settlement_fee

      accept_change_amount = accept_input_sats - accept_collateral - accept_funding_fee - accept_settlement_fee
      offer_change_amount = offer_input_sats - offer.collateral - offer_funding_fee - offer_settlement_fee

      # if either change amount is dust, will not be included
      change_outputs = Builder.filter_dust_outputs([
        Builder.new_output(accept_change_amount, g.change_script),
        Builder.new_output(offer_change_amount, offer.change_script)
      ])

      {funding_output, fund_leaf, dummy_tapkey_tweak} =
        build_funding_output(funding_amount, funding_pubkeys)

      # inputs & outputs will be sorted by bip69
      {funding_tx, funding_vout, dummy_tapkey_tweak} =
        Builder.build_funding_tx(
          inputs,
          [funding_output | change_outputs]
        )

      funding_txid = Transaction.transaction_id(fund_tx)

      # fund_outpoint used as single input to CETs & Refund tx
      funding_outpoint = Builder.build_funding_outpoint(funding_txid, funding_vout)

      # Build refund tx
      {refund_tx, refund_sig} =
        build_and_sign_refund_tx(
          funding_outpoint,
          [offer_refund_output, accept_refund_output],
          offer.refund_locktime,
          funding_output,
          fund_leaf
        )

      # build CETs list({outcome, cet_tx})
      outcomes_cet_txs =
        Builder.build_all_cets(
          funding_outpoint,
          offer.payout_script,
          g.payout_script,
          offer.contract_info.descriptor,
          cet_locktime
        )

      # sign all CETs
      outcomes_cet_adaptor_signatures =
        encrypted_sign_all_cets(
          g,
          o.contract_info.oracle_info,
          funding_output,
          fund_leaf,
          outcomes_cet_txs
        )

      cet_adaptor_signatures =
        Enum.map(outcomes_cet_adaptor_signatures, fn {_, adaptor_sig, was_negated} ->
          {adaptor_sig, was_negated}
        end)

      accept =
        Accept.new(
          offer.chain_hash,
          temp_contract_id,
          g.fund_pk,
          g.payout_script,
          g.change_script,
          collateral_amount,
          g.funding_inputs,
          cet_adaptor_signatures,
          refund_signature,
          dummy_tapkey_tweak
        )

      {accept, fund_tx, cet_txs, refund_tx}
    end
  end

  # SIGNER

  # sighash_default (all)
  @sighash_default 0x00
  # CETs use taproot scriptpath spend, so ext_flag = 1
  @ext_flag_script_spend 0x01

  def build_and_sign_refund_tx(
        funding_outpoint,
        refund_outputs,
        offer.refund_locktime,
        funding_output,
        fund_leaf
      ) do
    refund_tx =
      Builder.build_refund_tx(
        funding_outpoint,
        refund_outputs,
        offer.refund_locktime
      )

    {:ok, refund_signature} = sign_refund_tx(g, refund_tx, funding_output, fund_leaf)
  end

  def sign_refund_tx(g = %__MODULE__{}, refund_tx, funding_output, fund_leaf) do
    refund_sighash =
      settlement_sighash(
        refund_tx,
        [funding_output.value],
        [funding_output.script_pub_key],
        fund_leaf
      )

    aux = Utils.new_rand_int()
    Schnorr.sign(g.fund_sk, refund_sighash, aux)
  end

  def encrypted_sign_all_cets(
        g = %__MODULE__{},
        announcement = %Announcement{},
        funding_output,
        fund_leaf,
        cet_txs
      ) do
    oracle_pubkey = anouncement.public_key
    # for now, only 1 nonce_point per event
    nonce_point = Enum.at(announcement.event.nonce_points, 0)

    sign = fn cet_tx ->
      encrypted_sign_cet(g, oracle_pubkey, nonce_point, funding_output, fund_leaf, cet_tx)
    end

    Enum.map(cet_txs, sign)
  end

  def encrypted_sign_cet(
        g,
        oracle_pubkey,
        nonce_point,
        funding_output,
        fund_leaf,
        {outcome, cet_tx}
      ) do
    # funding transactions

    outcome_sighash = Oracle.attestation_sighash(outcome)

    outcome_sig_point =
      Schnorr.calculate_signature_point(nonce_point, oracle_pubkey, outcome_sighash)

    cet_sighash =
      settlement_sighash(
        cet_tx,
        [funding_output.value],
        [funding_output.script_pub_key],
        fund_leaf
      )

    # generate some entropy for this signature
    aux_rand = Utils.new_rand_int()
    # encrypted_sign
    {:ok, adaptor_sig, was_negated} =
      Schnorr.encrypted_sign(sk, cet_sighash, aux_rand, outcome_sig_point)

    {outcome, adaptor_sig, was_negated}
  end

  def funding_control_block() do
    # funding output script tree only has 1 leaf, so index must be 0
    control_block = Taproot.build_control_block(funding_pubkey, fund_leaf, 0)
    control_block_hex = control_block |> Base.encode16(case: :lower)

    fund_script_hex = Script.to_hex(fund_script)

    %Transaction.Witness{
      txinwitness: [sig1_hex, sig2_hex, fund_script_hex, control_block_hex]
    }
  end

  # OLD

  def verify_fund_scriptpubkey(fund_scriptpubkey, r) do
    ## TODO: 2nd arg
    Script.validate_unsolvable_internal_key(fund_scriptpubkey, nil, r)
  end

  def recv_cets(g, cets) do
    my_cet = Map.get(cets, g.my_outcome)
    my_cet_sighash = cet_sighash(my_cet, g.fund_amounts, g.fund_scriptpubkeys, g.fund_leaf)
    # TODO: make better
    new_rand_int = fn -> Enum.random(0..1000) end

    # generate some entropy for this signature
    aux_rand = new_rand_int.()

    ## TODO: last arg
    {:ok, my_cet_adaptor_sig, my_cet_was_negated} =
      Schnorr.encrypted_sign(g.sk, my_cet_sighash, aux_rand, nil)

    their_cet = Map.get(cets, g.their_outcome)
    their_cet_sighash = cet_sighash(their_cet, g.fund_amounts, g.fund_scriptpubkeys, g.fund_leaf)

    # generate some entropy for this signature
    aux_rand = new_rand_int.()

    ## TODO:  their_outcome
    {:ok, their_cet_adaptor_sig, their_cet_was_negated} =
      Schnorr.encrypted_sign(g.sk, their_cet_sighash, aux_rand, nil)

    #  send back to server
    {{my_cet_adaptor_sig, my_cet_was_negated}, {their_cet_adaptor_sig, their_cet_was_negated}}
  end

  defp settlement_sighash(settlement_tx, fund_amounts, fund_scriptpubkeys, fund_leaf) do
    Transaction.bip341_sighash(
      settlement_tx,
      @sighash_default,
      @ext_flag_script_spend,
      # only one input in CET tx
      0,
      # list of amounts for each input being spent
      fund_amounts,
      # list of prev scriptpubkeys for each input being spent
      fund_scriptpubkeys,
      tapleaf: fund_leaf
    )
    |> :binary.decode_unsigned()
  end
end
