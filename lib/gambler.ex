defmodule ExFacto.Gambler do
  @moduledoc """
    a Gambler only lives as long as their contract.
    A Gambler struct contains all the private info
    for a single party to a DLC
  """
  alias ExFacto.{Oracle, Chain, Utils, Contract, Builder}
  alias ExFacto.Contract.{Offer, Accept}
  alias ExFacto.Oracle.Announcement
  alias Bitcoinex.{Script, Transaction, Taproot}
  alias Bitcoinex.Secp256k1.{PrivateKey, Point, Schnorr}

  @type t :: %__MODULE__{
          network: Bitcoinex.Network.t(),
          funding_inputs: list(),
          fund_sk: PrivateKey.t(),
          fund_pk: Point.t(),
          change_script: Script.t(),
          payout_script: Script.t()
        }

  defstruct [
    :network,
    :funding_inputs,
    :fund_sk,
    :fund_pk,
    :change_script,
    :payout_script
  ]

  def new(funding_inputs, change_address, payout_address, get_private_key_func) do
    sk = get_private_key_func.()
    pk = PrivateKey.to_point(sk)

    {:ok, change_script, change_network} = Script.from_address(change_address)
    {:ok, payout_script, payout_network} = Script.from_address(payout_address)

    if change_network != payout_network do
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
      announcement.event.maturity_epoch,
      announcement.event.maturity_epoch + refund_locktime_delta
    )
  end

  @spec create_accept(Gambler.t(), Offer.t()) :: {t(), Transaction.t(), list({String.t(), Transaction.t()}), Transaction.t()} | {:error, <<_::136>>}
  def create_accept(g = %__MODULE__{}, offer = %Offer{}) do
    if Chain.chain_hash(g.network.name) != offer.chain_hash do
      {:error, "mismatch networks"}
    else
      # pubkeys will be sorted so order doesnt matter here
      funding_pubkeys = [offer.funding_pubkey, g.fund_pk]

      total_collateral = offer.contract_info.total_collateral
      accept_collateral = total_collateral - offer.collateral_amount

      inputs = g.funding_inputs ++ offer.funding_inputs

      {funding_amount, accept_change_amount, offer_change_amount} =
        Builder.calculate_funding_tx_outputs(offer, g.funding_inputs, g.payout_script, g.change_script)

      {funding_output, fund_leaf, dummy_tapkey_tweak} =
        Builder.build_funding_output(funding_amount, funding_pubkeys, Utils.new_rand_int())

      # if either change amount is dust, will not be included
      change_outputs = Builder.filter_dust_outputs([
        Builder.new_output(accept_change_amount, g.change_script),
        Builder.new_output(offer_change_amount, offer.change_script)
      ])

      # inputs & outputs will be sorted by bip69
      {funding_tx, funding_outpoint} =
        Builder.build_funding_tx(
          inputs,
          funding_output,
          change_outputs
        )

      # Build refund tx
      {refund_tx, refund_signature} =
        build_and_sign_refund_tx(
          g,
          offer,
          g.payout_script,
          funding_outpoint,
          funding_output,
          fund_leaf
        )

      # build CETs list({outcome, cet_tx})
      {outcomes_cet_txs, cet_adaptor_signatures} = build_and_sign_cets(g, offer, funding_outpoint, funding_output, fund_leaf)

      accept =
        Accept.new(
          offer.chain_hash,
          offer.temp_contract_id,
          g.fund_pk,
          g.payout_script,
          g.change_script,
          accept_collateral,
          g.funding_inputs,
          cet_adaptor_signatures,
          refund_signature,
          dummy_tapkey_tweak
        )

      {accept, funding_tx, outcomes_cet_txs, refund_tx}
    end
  end

  # TODO dedup this code with the above
  # when an offerer receives an accept, they also need to build all the txs and *sign* them
  def offerer_ack_accept(g= %__MODULE__{}, offer = %Offer{}, accept = %Accept{}) do
    # pubkeys will be sorted so order doesnt matter here
    funding_pubkeys = [offer.funding_pubkey, accept.funding_pubkey]

    {funding_amount, accept_change_amount, offer_change_amount} =
      Builder.calculate_funding_tx_outputs(offer, accept.funding_inputs, accept.payout_script, accept.change_script)

    # recreate fund_scriptpubkey and check that internal key is unsolvable
    {funding_output, fund_leaf, _} =
      Builder.build_funding_output(funding_amount, funding_pubkeys, accept.dummy_tapkey_tweak)

    # if either change amount is dust, will not be included
    change_outputs = Builder.filter_dust_outputs([
      Builder.new_output(accept_change_amount, g.change_script),
      Builder.new_output(offer_change_amount, offer.change_script)
    ])

    inputs = accept.funding_inputs ++ offer.funding_inputs

    # inputs & outputs will be sorted by bip69
    {funding_tx, funding_outpoint} =
      Builder.build_funding_tx(
        inputs,
        funding_output,
        change_outputs
      )

    # Build refund tx
    {refund_tx, refund_signature} =
      build_and_sign_refund_tx(
        g,
        offer,
        accept.payout_script,
        funding_outpoint,
        funding_output,
        fund_leaf
      )

    # build CETs list({outcome, cet_tx})
    {outcomes_cet_txs, cet_adaptor_signatures} = build_and_sign_cets(g, offer, funding_outpoint, funding_output, fund_leaf)

    # sign funding tx
    # TODO how is this done?
    signed_funding_tx = sign_funding_tx(funding_tx)

    # the signatures need to go back to the accepter who can then sign the funding tx and broadcast
    # the txs just need to be saved by the client, not shared
    {signed_funding_tx, outcomes_cet_txs, cet_adaptor_signatures, refund_tx, refund_signature}
  end

  def accepter_sign_funding_tx(_g, funding_tx, offer_funding_signature, accept_funding_pubkey, offer_funding_pubkey) do
    # TODO
    fully_signed_funding_tx = sign_funding_tx(funding_tx)

    # broadcast funding_tx
    # BTCRPC.sendrawtransaction()
  end


  # SIGNER

  # sighash_default (all)
  @sighash_default 0x00
  # CETs use taproot scriptpath spend, so ext_flag = 1
  @ext_flag_script_spend 0x01

  def build_and_sign_refund_tx(
        g = %__MODULE__{},
        offer = %Offer{},
        accept_payout_script,
        funding_outpoint,
        funding_output = %Transaction.Out{},
        fund_leaf
      ) do

    accept_collateral = offer.contract_info.total_collateral - offer.collateral_amount
    accept_refund_output = Builder.new_output(accept_collateral, accept_payout_script)
    offer_refund_output = Builder.new_output(offer.collateral_amount, offer.payout_script)

    refund_tx =
      Builder.build_refund_tx(
        funding_outpoint,
        [accept_refund_output, offer_refund_output],
        offer.refund_locktime
      )

    {:ok, refund_signature} =
      sign_settlement_tx(g, refund_tx, funding_output, fund_leaf)
    {refund_tx, refund_signature}
  end

  def build_and_sign_cets(g, offer, funding_outpoint, funding_output, fund_leaf) do
    outcomes_cet_txs =
      Builder.build_all_cets(
        funding_outpoint,
        offer.contract_info.total_collateral,

        offer.payout_script,
        g.payout_script,
        offer.contract_info.descriptor,
        offer.cet_locktime
      )

    # sign all CETs
    outcomes_cet_adaptor_signatures =
      encrypted_sign_all_cets(
        g,
        offer.contract_info.oracle_info,
        funding_output,
        fund_leaf,
        outcomes_cet_txs
      )

      cet_adaptor_signatures =
        Enum.map(outcomes_cet_adaptor_signatures, fn {_, adaptor_sig, was_negated} ->
          {adaptor_sig, was_negated}
        end)


    {outcomes_cet_txs, cet_adaptor_signatures}
  end

  def sign_settlement_tx(g = %__MODULE__{}, settlement_tx = %Transaction{},
    funding_output, fund_leaf) do
    settlement_sighash =
      settlement_sighash(
        settlement_tx,
        [funding_output.value],
        [funding_output.script_pub_key],
        fund_leaf
      )

    aux = Utils.new_rand_int()
    Schnorr.sign(g.fund_sk, settlement_sighash, aux)
  end

  def encrypted_sign_all_cets(
        g = %__MODULE__{},
        announcement = %Announcement{},
        funding_output,
        fund_leaf,
        cet_txs
      ) do
    oracle_pubkey = announcement.public_key
    # for now, only 1 nonce_point per event
    nonce_point = Enum.at(announcement.event.nonce_points, 0)

    sign = fn cet_tx ->
      encrypted_sign_cet(g, oracle_pubkey, nonce_point, funding_output, fund_leaf, cet_tx)
    end

    Enum.map(cet_txs, sign)
  end

  def encrypted_sign_cet(
        g = %__MODULE__{},
        oracle_pubkey = %Point{},
        nonce_point = %Point{},
        funding_output = %Transaction.Out{},
        fund_leaf = %Taproot.TapLeaf{},
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
      Schnorr.encrypted_sign(g.fund_sk, cet_sighash, aux_rand, outcome_sig_point)

    {outcome, adaptor_sig, was_negated}
  end

  def funding_control_block(funding_pubkey, fund_leaf) do
    # funding output script tree only has 1 leaf, so index must be 0
    control_block = Taproot.build_control_block(funding_pubkey, fund_leaf, 0)
    control_block_hex = control_block |> Base.encode16(case: :lower)

    fund_script_hex = Script.to_hex(fund_leaf.script)

    {fund_script_hex, control_block_hex}
  end

  # sign funding tx

  # TODO IMPLEMENT ME!
  def sign_funding_tx(_funding_tx) do
    %Bitcoinex.Secp256k1.Signature{r: 1, s: 1}
  end

  # OLD

  def verify_fund_scriptpubkey(fund_scriptpubkey, r) do
    ## TODO: 2nd arg
    Script.validate_unsolvable_internal_key(fund_scriptpubkey, nil, r)
  end

  # def recv_cets(g, cets) do
  #   my_cet = Map.get(cets, g.my_outcome)
  #   my_cet_sighash = cet_sighash(my_cet, g.fund_amounts, g.fund_scriptpubkeys, g.fund_leaf)
  #   # TODO: make better
  #   new_rand_int = fn -> Enum.random(0..1000) end

  #   # generate some entropy for this signature
  #   aux_rand = new_rand_int.()

  #   ## TODO: last arg
  #   {:ok, my_cet_adaptor_sig, my_cet_was_negated} =
  #     Schnorr.encrypted_sign(g.sk, my_cet_sighash, aux_rand, nil)

  #   their_cet = Map.get(cets, g.their_outcome)
  #   their_cet_sighash = cet_sighash(their_cet, g.fund_amounts, g.fund_scriptpubkeys, g.fund_leaf)

  #   # generate some entropy for this signature
  #   aux_rand = new_rand_int.()

  #   ## TODO:  their_outcome
  #   {:ok, their_cet_adaptor_sig, their_cet_was_negated} =
  #     Schnorr.encrypted_sign(g.sk, their_cet_sighash, aux_rand, nil)

  #   #  send back to server
  #   {{my_cet_adaptor_sig, my_cet_was_negated}, {their_cet_adaptor_sig, their_cet_was_negated}}
  # end

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
