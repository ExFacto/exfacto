defmodule ExFacto.Gambler do
  @moduledoc """
    a Gambler only lives as long as their contract.
    A Gambler struct contains all the private info
    for a single party to a DLC
  """
  alias ExFacto.Contract
  alias ExFacto.{Oracle, Chain, Utils, Contract, Builder}
  alias ExFacto.Contract.{Offer, Accept, Acknowledge}
  alias ExFacto.Oracle.Announcement
  alias Bitcoinex.{Script, Transaction, Taproot}
  alias Bitcoinex.Secp256k1.{PrivateKey, Point, Schnorr}

  @type t :: %__MODULE__{
          network: Bitcoinex.Network.t(),
          funding_inputs: list(),
          funding_sk: PrivateKey.t(),
          funding_pubkey: Point.t(),
          change_script: Script.t(),
          payout_script: Script.t()
        }

  defstruct [
    :network,
    :funding_inputs,
    :funding_sk,
    :funding_pubkey,
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
        funding_sk: sk,
        funding_pubkey: pk,
        change_script: change_script,
        payout_script: payout_script
      }
    end
  end

  def create_offer(
        g = %__MODULE__{},
        oracle_info,
        payouts,
        offer_collateral_amount,
        total_collateral,
        refund_locktime_delta,
        fee_rate
      ) do
    announcement = oracle_info.announcement

    if !Announcement.verify(announcement) do
      {:error, "oracle announcement verification failed"}
    else
      contract_descriptor = Enum.zip(announcement.event.descriptor.outcomes, payouts)

      contract_info = %Contract{
        total_collateral: total_collateral,
        descriptor: contract_descriptor,
        oracle_info: oracle_info
      }

      Offer.new(
        Chain.chain_hash(g.network.name),
        contract_info,
        offer_collateral_amount,
        g.funding_inputs,
        g.funding_pubkey,
        g.payout_script,
        g.change_script,
        fee_rate,
        announcement.event.maturity_epoch,
        announcement.event.maturity_epoch + refund_locktime_delta
      )
    end
  end

  @spec create_accept(Gambler.t(), Offer.t()) ::
          {t(), Transaction.t(), list({String.t(), Transaction.t()}), Transaction.t()}
          | {:error, <<_::136>>}
  def create_accept(g = %__MODULE__{}, offer = %Offer{}) do
    cond do
      Chain.chain_hash(g.network.name) != offer.chain_hash ->
        {:error, "mismatch networks"}

      !Announcement.verify(announcement) ->
        {:error, "oracle announcement verification failed"}

      !Offer.verify(offer) ->
        {:error, "offer verification failed"}

      true ->
        # pubkeys will be sorted so order doesnt matter here
        funding_pubkeys = [offer.funding_pubkey, g.funding_pubkey]

        total_collateral = offer.contract_info.total_collateral
        accept_collateral = total_collateral - offer.collateral_amount

        inputs = g.funding_inputs ++ offer.funding_inputs

        {funding_amount, accept_change_amount, offer_change_amount} =
          Builder.calculate_funding_tx_outputs(
            offer,
            g.funding_inputs,
            g.payout_script,
            g.change_script
          )

        {funding_output, funding_leaf, dummy_tapkey_tweak} =
          Builder.build_funding_output(funding_amount, funding_pubkeys, Utils.new_rand_int())

        # if either change amount is dust, will not be included
        change_outputs =
          Builder.filter_dust_outputs([
            Builder.new_output(accept_change_amount, g.change_script),
            Builder.new_output(offer_change_amount, offer.change_script)
          ])

        # inputs & outputs will be sorted by bip69
        {_funding_tx, funding_outpoint} =
          Builder.build_funding_tx(
            inputs,
            funding_output,
            change_outputs
          )

        funding_txid = funding_outpoint.prev_txid |> Base.decode16!(case: :lower)

        contract_id =
          Contract.calculate_contract_id(funding_txid, funding_outpoint.prev_vout, offer.offer_id)

        # Build refund tx
        {refund_tx, refund_signature} =
          build_and_sign_refund_tx(
            g,
            offer,
            g.payout_script,
            funding_outpoint,
            funding_output,
            funding_leaf
          )

        # build CETs list({outcome, cet_tx})
        {outcomes_cet_txs, cet_adaptor_signatures} =
          build_and_sign_cets(g, offer, funding_outpoint, funding_output, funding_leaf)

        accept =
          Accept.new(
            offer.chain_hash,
            contract_id,
            offer.offer_id,
            g.funding_pubkey,
            dummy_tapkey_tweak,
            g.payout_script,
            g.change_script,
            accept_collateral,
            g.funding_inputs,
            cet_adaptor_signatures,
            refund_signature
          )

        {accept, outcomes_cet_txs, refund_tx}
    end
  end

  # TODO dedup this code with the above
  # when an offerer receives an accept, they also need to build all the txs and *sign* them
  def offerer_ack_accept(g = %__MODULE__{}, offer = %Offer{}, accept = %Accept{}) do
    # TODO: verify offer&accept
    cond do
      !Offer.verify(offer) ->
        {:error, "offer verification failed"}

      !offer_is_ours(g, offer) ->
        {:error, "offer does not belong to this gambler"}

      !Accept.verify(offer, accept) ->
        {:error, "accept verification failed"}

      true ->
        # pubkeys will be sorted so order doesnt matter here
        funding_pubkeys = [offer.funding_pubkey, accept.funding_pubkey]

        {funding_amount, accept_change_amount, offer_change_amount} =
          Builder.calculate_funding_tx_outputs(
            offer,
            accept.funding_inputs,
            accept.payout_script,
            accept.change_script
          )

        # recreate funding_scriptpubkey and check that internal key is unsolvable
        {funding_output, funding_leaf, _} =
          Builder.build_funding_output(funding_amount, funding_pubkeys, accept.dummy_tapkey_tweak)

        # if either change amount is dust, will not be included
        change_outputs =
          Builder.filter_dust_outputs([
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
            funding_leaf
          )

        # build CETs list({outcome, cet_tx})
        {outcomes_cet_txs, cet_adaptor_signatures} =
          build_and_sign_cets(g, offer, funding_outpoint, funding_output, funding_leaf)

        # sign funding tx
        # TODO how is this done?
        signed_funding_tx = sign_funding_tx(g, funding_tx)

        # the signed funding_tx can be broadcast
        # the txs just need to be saved by the client, not shared
        ack =
          Acknowledge.new(
            accept.contract_id,
            signed_funding_tx.witnesses,
            cet_adaptor_signatures,
            refund_signature
          )

        {ack, signed_funding_tx, outcomes_cet_txs, cet_adaptor_signatures, refund_tx,
         refund_signature}
    end
  end

  @doc """
    offer_is_ours checks if the offer belongs to this gambler and has matching
    inputs, pubkey, and output scripts
  """
  @spec offer_is_ours(t(), Offer.t()) :: boolean()
  def offer_is_ours(g = %__MODULE__{}, offer = %Offer{}) do
    g.funding_inputs == offer.funding_inputs &&
    g.funding_pubkey == offer.funding_pubkey &&
    g.change_script == offer.change_script &&
    g.payout_script == offer.payout_script
  end

  # finalize funding tx
  def accepter_sign_funding_tx(g = %__MODULE__{}, offer = %Offer{}, accept = %Accept{}, ack = %Acknowledge{}) do
    # TODO verify refund tx & signature


    # TODO verify CETs & signatures

    # TODO verify funding tx & signatures

    # sign tx
    fully_signed_funding_tx = sign_funding_tx(g, funding_tx)

    # broadcast funding_tx
    # BTCRPC.sendrawtransaction()
  end

  def verify_refund_tx(g = %__MODULE__{}, offer = %Offer{}, accept = %Accept{}, refund_tx = %Transaction{}) do
    # TODO verify refund tx & signature
    funding_tx = Builder.build_refund_tx(
      funding_outpoint,
      offer.contract_info.total_collateral,
      offer.collateral_amount,
      accept.payout_script,
      offer.payout_script,
      offer.refund_locktime
    )

    # TODO regenerate funding_script & leaf

    funding_sighash =
      settlement_sighash(
        funding_tx,
        [funding_output.value],
        [funding_outp],
        funding_leaf
      )


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
        funding_leaf
      ) do

    refund_tx =
      Builder.build_refund_tx(
        funding_outpoint,
        offer.contract_info.total_collateral,
        offer.collateral_amount,
        accept_payout_script,
        offer.payout_script,
        offer.refund_locktime
      )

    {:ok, refund_signature} = sign_settlement_tx(g, refund_tx, funding_output, funding_leaf)
    {refund_tx, refund_signature}
  end

  def build_and_sign_cets(g, offer, funding_outpoint, funding_output, funding_leaf) do
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
        offer.contract_info.oracle_info.announcement,
        funding_output,
        funding_leaf,
        outcomes_cet_txs
      )

    cet_adaptor_signatures =
      Enum.map(outcomes_cet_adaptor_signatures, fn {_, adaptor_sig, was_negated} ->
        %{adaptor_signature: adaptor_sig, was_negated: was_negated}
      end)

    {outcomes_cet_txs, cet_adaptor_signatures}
  end

  def sign_settlement_tx(
        g = %__MODULE__{},
        settlement_tx = %Transaction{},
        funding_output,
        funding_leaf
      ) do
    {:ok, script} = Script.parse_script(funding_output.script_pub_key)
    prev_scriptpubkey = Script.serialize_with_compact_size(script)

    settlement_sighash =
      settlement_sighash(
        settlement_tx,
        [funding_output.value],
        [prev_scriptpubkey],
        funding_leaf
      )

    aux = Utils.new_rand_int()
    Schnorr.sign(g.funding_sk, settlement_sighash, aux)
  end

  def encrypted_sign_all_cets(
        g = %__MODULE__{},
        announcement = %Announcement{},
        funding_output,
        funding_leaf,
        cet_txs
      ) do
    oracle_pubkey = announcement.public_key
    # for now, only 1 nonce_point per event
    nonce_point = Enum.at(announcement.event.nonce_points, 0)

    sign = fn cet_tx ->
      encrypted_sign_cet(g, oracle_pubkey, nonce_point, funding_output, funding_leaf, cet_tx)
    end

    Enum.map(cet_txs, sign)
  end

  def encrypted_sign_cet(
        g = %__MODULE__{},
        oracle_pubkey = %Point{},
        nonce_point = %Point{},
        funding_output = %Transaction.Out{},
        funding_leaf = %Taproot.TapLeaf{},
        {outcome, cet_tx}
      ) do
    # funding transactions

    outcome_sighash = Oracle.Attestation.sighash(outcome)

    outcome_sig_point =
      Schnorr.calculate_signature_point(nonce_point, oracle_pubkey, outcome_sighash)

    {:ok, script} = Script.parse_script(funding_output.script_pub_key)
    prev_scriptpubkey = Script.serialize_with_compact_size(script)

    cet_sighash =
      settlement_sighash(
        cet_tx,
        [funding_output.value],
        [prev_scriptpubkey],
        funding_leaf
      )

    # generate some entropy for this signature
    aux_rand = Utils.new_rand_int()
    # encrypted_sign
    {:ok, adaptor_sig, was_negated} =
      Schnorr.encrypted_sign(g.funding_sk, cet_sighash, aux_rand, outcome_sig_point)

    {outcome, adaptor_sig, was_negated}
  end

  # sign funding tx

  # TODO IMPLEMENT ME!
  def sign_funding_tx(_g = %__MODULE__{}, funding_tx) do
    # sig = %Bitcoinex.Secp256k1.Signature{r: 1, s: 1}
    funding_tx
  end

  # OLD

  def verify_funding_scriptpubkey(funding_scriptpubkey, dummy_taptweak_key) do
    ## TODO: 2nd arg
    Script.validate_unsolvable_internal_key(funding_scriptpubkey, nil, dummy_taptweak_key)
  end

  # def recv_cets(g, cets) do
  #   my_cet = Map.get(cets, g.my_outcome)
  #   my_cet_sighash = cet_sighash(my_cet, g.funding_amounts, g.funding_scriptpubkeys, g.funding_leaf)
  #   # TODO: make better
  #   new_rand_int = fn -> Enum.random(0..1000) end

  #   # generate some entropy for this signature
  #   aux_rand = new_rand_int.()

  #   ## TODO: last arg
  #   {:ok, my_cet_adaptor_sig, my_cet_was_negated} =
  #     Schnorr.encrypted_sign(g.sk, my_cet_sighash, aux_rand, nil)

  #   their_cet = Map.get(cets, g.their_outcome)
  #   their_cet_sighash = cet_sighash(their_cet, g.funding_amounts, g.funding_scriptpubkeys, g.funding_leaf)

  #   # generate some entropy for this signature
  #   aux_rand = new_rand_int.()

  #   ## TODO:  their_outcome
  #   {:ok, their_cet_adaptor_sig, their_cet_was_negated} =
  #     Schnorr.encrypted_sign(g.sk, their_cet_sighash, aux_rand, nil)

  #   #  send back to server
  #   {{my_cet_adaptor_sig, my_cet_was_negated}, {their_cet_adaptor_sig, their_cet_was_negated}}
  # end

  defp settlement_sighash(settlement_tx, funding_amounts, funding_scriptpubkeys, funding_leaf) do
    Transaction.bip341_sighash(
      settlement_tx,
      @sighash_default,
      @ext_flag_script_spend,
      # only one input in CET tx
      0,
      # list of amounts for each input being spent
      funding_amounts,
      # list of prev scriptpubkeys for each input being spent
      funding_scriptpubkeys,
      tapleaf: funding_leaf
    )
    |> :binary.decode_unsigned()
  end
end
