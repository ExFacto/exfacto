# defmodule ExFacto.Gambler do
#   @moduledoc """
#     a Gambler only lives as long as their contract.
#     A Gambler struct contains all the private info
#     for a single party to a DLC
#   """
#   alias ExFacto.Utils
#   alias Bitcoinex.Script

#   @type t :: %__MODULE__{
#           network: Bitcoinex.Network.t(),
#           init_output: Transaction.Out.t(),
#           init_outpoint: Utils.outpoint(),
#           fund_sk: PrivateKey.t(),
#           fund_pk: Point.t(),
#           change_script: Script.t(),
#           dest_script: Script.t()

#           # Other info Gambler should keep
#           # my_outcome
#           # their_outcome
#           # my outcome sigpoint
#           # their outcome sigpoint
#           # fund_amount
#           # fund_scriptpubkey
#           # fund_leaf # can be built from spk
#         }

#   defstruct [
#     :network,
#     :init_output,
#     :init_outpoint,
#     :fund_sk,
#     :fund_pk,
#     :change_script,
#     :dest_script
#   ]

#   def new(init_output, init_outpoint, change_address, dest_address) do
#     sk = Utils.new_private_key()
#     pk = PrivateKey.to_point(sk)

#     {:ok, change_script, change_network} = Script.from_address(change_address)
#     {:ok, dest_script, dest_network} = Script.from_address(dest_address)

#     if change_network != dest_network do
#       {:error, "mismatch networks"}
#     else
#       %__MODULE__{
#         network: Bitcoinex.Network.get_network(""),
#         init_output: init_output,
#         init_outpoint: init_outpoint,
#         fund_sk: sk,
#         fund_pk: pk,
#         change_script: change_script,
#         dest_script: dest_script
#       }
#     end
#   end

#   def register_with_coordinator(_g, _oracle_announcement, _outcome) do
#     # send to Coordinator
#     %{}
#   end

#   # def recv_bet_summary(g, %{
#   #       fund_amount: fund_amount,
#   #       winner_gets: winner_amount,
#   #       outcomes: outcomes,
#   #       dest_scripts: dest_scripts
#   #     }) do
#   #   # probably just have user click confirm, then set the fund amount, etc.
#   # end

#   # def recv_funding_tx_info(fund_tx, r) do
#   #   fund_txid = Transaction.transaction_id(fund_tx)
#   #   # verify output script includes your pubkey
#   #   ## TODO: get fundscript key
#   #   verify_fund_scriptpubkey(nil, r)
#   #   # click confirm, then recv cets
#   # end

#   def verify_fund_scriptpubkey(fund_scriptpubkey, r) do
#     ## TODO: 2nd arg
#     Script.validate_unsolvable_internal_key(fund_scriptpubkey, nil, r)
#   end

#   def recv_cets(g, cets) do
#     my_cet = Map.get(cets, g.my_outcome)
#     my_cet_sighash = cet_sighash(my_cet, g.fund_amounts, g.fund_scriptpubkeys, g.fund_leaf)
#     # TODO: make better
#     new_rand_int = fn -> Enum.random(0..1000) end

#     # generate some entropy for this signature
#     aux_rand = new_rand_int.()

#     ## TODO: last arg
#     {:ok, my_cet_adaptor_sig, my_cet_was_negated} =
#       Schnorr.encrypted_sign(g.sk, my_cet_sighash, aux_rand, nil)

#     their_cet = Map.get(cets, g.their_outcome)
#     their_cet_sighash = cet_sighash(their_cet, g.fund_amounts, g.fund_scriptpubkeys, g.fund_leaf)

#     # generate some entropy for this signature
#     aux_rand = new_rand_int.()

#     ## TODO:  their_outcome
#     {:ok, their_cet_adaptor_sig, their_cet_was_negated} =
#       Schnorr.encrypted_sign(g.sk, their_cet_sighash, aux_rand, nil)

#     #  send back to server
#     {{my_cet_adaptor_sig, my_cet_was_negated}, {their_cet_adaptor_sig, their_cet_was_negated}}
#   end

#   defp cet_sighash(cet_tx, fund_amounts, fund_scriptpubkeys, fund_leaf) do
#     cet_hash_type = 0x00
#     cet_ext_flag = 0x01

#       Transaction.bip341_sighash(
#         cet_tx,
#         # sighash_default (all)
#         cet_hash_type,
#         # we are using taproot scriptpath spend, so ext_flag = 1
#         cet_ext_flag,
#         # only one input in this tx
#         0,
#         # list of amounts for each input being spent
#         fund_amounts,
#         # list of prev scriptpubkeys for each input being spent
#         fund_scriptpubkeys,
#         tapleaf: fund_leaf
#       )
#       |> :binary.decode_unsigned()


#   end
# end
