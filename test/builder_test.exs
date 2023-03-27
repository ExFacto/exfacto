defmodule ExFacto.BuilderTest do
  use ExUnit.Case
  doctest ExFacto.Builder

  alias ExFacto.Builder
  alias Bitcoinex.{Script, Transaction, Utils}

  def example_p2tr_sig() do
    "09ffe333ebec5ff1dc074592c1d803b428ed3d0da59f9269b9c3aae8b662bb04efc2bf69149ea5bce56f5c50fd25e6ec683bcd127a409e776c6cf97c27b2235b"
    |> Base.decode16!(case: :lower)
  end

  def example_p2tr_keyspend_witness() do
    %Transaction.Witness{
      txinwitness: [example_p2tr_sig() |> Base.encode16(case: :lower)]
    }
  end

  def example_p2tr_scriptspend_witness() do
    %Transaction.Witness{
      txinwitness: [
        # TODO get single leaf spend
        ""
      ]
    }
  end

  def example_p2wpkh_sig() do
    "30440220476667985ce76be39e5e4a182b7a9639c9d30c0d9508c16803368f1874c112370220465ba49337f08baae20b693be9d6ecd2a923e7621ab3f1aaf4e93e495b5e3b6a01"
    |> Base.decode16!(case: :lower)
  end

  def example_p2wpkh_pk() do
    "02bb08315f65b485e2dcdf88109c2e70b6db44d5bc1d7155154af8c025f5fa1f95"
    |> Base.decode16!(case: :lower)
  end

  def example_p2wpkh_witness() do
    %Transaction.Witness{
      txinwitness: [
        example_p2wpkh_sig() |> Base.encode16(case: :lower),
        example_p2wpkh_pk() |> Base.encode16(case: :lower)
      ]
    }
  end

  def example_p2tr_scriptpubkey() do
    {:ok, script} =
      Script.create_p2tr(
        Base.decode16!("0101010101010101010101010101010101010101010101010101010101010101")
      )

    script
  end

  def example_p2wsh_scriptpubkey() do
    {:ok, script} =
      Script.parse_script("0020b2ccdccf05792a0b18d15e241a9c1cc2031535be51575597b68b4f3fc94af2cc")

    script
  end

  def example_p2wpkh_scriptpubkey() do
    {:ok, script} = Script.parse_script("001451c386e112eca3cdf38e5457d62becbfe57361ee")
    script
  end

  def example_p2sh_scriptpubkey() do
    {:ok, script} = Script.parse_script("a9148649a27175b045116554291e61222980d26efcb287")
    script
  end

  def example_p2pkh_scriptpubkey() do
    {:ok, script} = Script.parse_script("76a9141be475be1966ab2d4ae6ada6edb74ff231470ab188ac")
    script
  end

  def example_outputs(),
    do: [
      Builder.new_output(0, example_p2tr_scriptpubkey()),
      Builder.new_output(999, example_p2tr_scriptpubkey()),
      Builder.new_output(1000, example_p2tr_scriptpubkey()),
      Builder.new_output(1001, example_p2tr_scriptpubkey()),
      Builder.new_output(10000, example_p2tr_scriptpubkey())
    ]

  def example_filtered_outputs(),
    do: [
      Builder.new_output(1001, example_p2tr_scriptpubkey()),
      Builder.new_output(10000, example_p2tr_scriptpubkey())
    ]

  def funding_input_examples1() do
    {:ok, tx1} =
      Transaction.decode(
        "02000000000101b44b114075a5ff51a09aa7cea3706048ae76aa44134c7d0b66fcbe50a71ee7d50000000000feffffff0288580100000000001600141e4a3e865eaefb4a0f73214a7435a05f92182130f0a208000000000016001452dad5b80d2fc71a5c94ba0f149fb373a84256130247304402200fc5d51e4525a68169d2160da1133537be12ca9157e00408813d827bf4bba2ee02201675d78843ed732ed09b985e8ba6c022185a6a61dd4dfb77e21b920df16ad86e0121039e1d05184bad35efee5c9109d2afd0858d12f86f383c818dc18fb954ed73c8a199e60b00"
      )

    tx1 = %{
      prev_tx: tx1,
      prev_vout: 0,
      sequence: 0xFFFFFFFE,
      max_witness_len: Builder.max_witness_len_p2wpkh(),
      redeem_script: nil
    }

    {:ok, tx2} =
      Transaction.decode(
        "020000000001019d34250b5fa244c135d6acf1bf8eae793ca10146fcd2367832910a1a54f6d1c90100000000feffffff028c190a000000000016001419d066105581716952e766fc4393b36960af3d2cc0c62d00000000001976a91417f4d54dc57a06bb949691e572ec93ecbfea335688ac024730440220170bc9a042f07a84fd087b510f6f30001932a7071dc5a0f65c084addb562566002206e9cc1cfe3b9125c5c9c497b5110a1efaffce4613f6984c2df38c16a437d59ca0121037e72ae9fcc746d11f07d90f31722f785a326705ad57e9dc36bd86afd6962d0d2cae50b00"
      )

    tx2 = %{
      prev_tx: tx2,
      prev_vout: 0,
      sequence: 0xFFFFFFFE,
      max_witness_len: Builder.max_witness_len_p2wpkh(),
      redeem_script: nil
    }

    {:ok, tx3} =
      Transaction.decode(
        "020000000001012cd69f367a24f9b963335e79e41220c9e24c9767bea51097f1af8d4e48a42b2f0100000000feffffff0285295c000000000017a9140745114d367927ef0c0616f6e8fddb0a2b62dd7d8764d25f010000000016001437f360969ff36031a3b0303aa58e0f5960ec20a80247304402207d55479638fddb1ce6fbed75922dee51c7c49106b41af7a7d2ed28f3128eebad02206348ff3017849012a3d7fea8be37874298c29d37728156a2291686c540770ba4012102af2813038bef276ca3390c7c21c7e67b96ce999649d7924d4224f1ea8cbd772599e60b00"
      )

    tx3 = %{
      prev_tx: tx3,
      prev_vout: 1,
      sequence: 0xFFFFFFFE,
      max_witness_len: Builder.max_witness_len_p2wpkh(),
      redeem_script: nil
    }

    [tx1, tx2, tx3]
  end

  def funding_input_examples2() do
    {:ok, tx1} =
      Transaction.decode(
        "02000000000101f0cccf26b05ac18f267bb5b2793c8526a8eb25afab97376c0c9dacfecda2c31f0100000000fdffffff02d704010000000000225120b0840516d40ddf0249dd9a8a45a1bc3874e9a1e63e45e6b51bfcc0ecb6399a1f10270000000000002251207bdeab5b62c6f7c1f35f6badf1d4bb3616afd8339a43db5ee18e829f0bd6aa9701401e62d13b8460d75f424df40a02a79774a8d24a3b8ebb80370b7ae5c80a2329f5362cf1a8aa108496609472f24b32680d7ef67ca28030420febf61ce61eed0ec65be60b00"
      )

    tx1 = %{
      prev_tx: tx1,
      prev_vout: 0,
      sequence: 0xFFFFFFFE,
      max_witness_len: Builder.max_witness_len_p2tr_keyspend(),
      redeem_script: nil
    }

    {:ok, tx2} =
      Transaction.decode(
        "02000000000101f0cccf26b05ac18f267bb5b2793c8526a8eb25afab97376c0c9dacfecda2c31f0100000000fdffffff02d704010000000000225120b0840516d40ddf0249dd9a8a45a1bc3874e9a1e63e45e6b51bfcc0ecb6399a1f10270000000000002251207bdeab5b62c6f7c1f35f6badf1d4bb3616afd8339a43db5ee18e829f0bd6aa9701401e62d13b8460d75f424df40a02a79774a8d24a3b8ebb80370b7ae5c80a2329f5362cf1a8aa108496609472f24b32680d7ef67ca28030420febf61ce61eed0ec65be60b00"
      )

    tx2 = %{
      prev_tx: tx2,
      prev_vout: 1,
      sequence: 0xFFFFFFFE,
      max_witness_len: Builder.max_witness_len_p2tr_keyspend(),
      redeem_script: nil
    }

    {:ok, tx3} =
      Transaction.decode(
        "010000000001010f5dbc551e5834e88aa586084cc21fb7a185d9fcc12185f400d92f73009fe17d2200000000fdffffff02e4470100000000002251204587b08a189aa93dc8dc25efb36d37bda90f96b169bb90cc4992c730f40d2fe48ccd0f0000000000225120545eff4143fb4c4966940e35b4186d866f6348dab23a784b6a040035844b7e7c01405c5a8191113c861be51da25e83536f0711fe660c9cda0c1410a12485a6f172dbeef421083e98c91b18f059b8efbad59eae4a1d1e62b439d60334459a840f70a700000000"
      )

    tx3 = %{
      prev_tx: tx3,
      prev_vout: 1,
      sequence: 0xFFFFFFFE,
      max_witness_len: Builder.max_witness_len_p2tr_keyspend(),
      redeem_script: nil
    }

    [tx1, tx2, tx3]
  end

  @funding_input_infos [
    %{
      sum: 100_000_000,
      funding_input_infos: [
        %{
          max_witness_len: 64,
          prev_tx: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "bcda2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_294
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 100_000_000,
                script_pub_key:
                  "512086143e7dcfd988633682be2b71c5f556a9ed930aef8cc1bfaded0eed56215b31"
              }
            ],
            witnesses: nil,
            lock_time: 0
          },
          prev_vout: 0,
          redeem_script: nil,
          sequence: 4_294_967_294
        }
      ]
    },
    %{
      sum: 300_000_000,
      funding_input_infos: [
        %{
          prev_tx: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "bcda2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_294
              },
              %Bitcoinex.Transaction.In{
                prev_txid: "01da2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 1,
                script_sig: "",
                sequence_no: 4_294_967_294
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 100_000_000,
                script_pub_key:
                  "512086143e7dcfd988633682be2b71c5f556a9ed930aef8cc1bfaded0eed56215b31"
              },
              %Bitcoinex.Transaction.Out{
                value: 200_000_000,
                script_pub_key:
                  "512086143e7dcfd988633682be2b71c5f556a9ed930aef8cc1bfaded0eed56215b31"
              }
            ],
            witnesses: [
              %Transaction.Witness{
                txinwitness: [
                  "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
                ]
              },
              %Transaction.Witness{
                txinwitness: []
              }
            ],
            lock_time: 100_000
          },
          prev_vout: 1,
          redeem_script: nil,
          sequence: 4_294_967_294
        },
        %{
          prev_tx: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "bcda2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_294
              },
              %Bitcoinex.Transaction.In{
                prev_txid: "01da2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 1,
                script_sig: "",
                sequence_no: 4_294_967_294
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 100_000_000,
                script_pub_key:
                  "512086143e7dcfd988633682be2b71c5f556a9ed930aef8cc1bfaded0eed56215b31"
              },
              %Bitcoinex.Transaction.Out{
                value: 200_000_000,
                script_pub_key:
                  "512086143e7dcfd988633682be2b71c5f556a9ed930aef8cc1bfaded0eed56215b31"
              }
            ],
            witnesses: [
              %Transaction.Witness{
                txinwitness: [
                  "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
                ]
              },
              %Transaction.Witness{
                txinwitness: []
              }
            ],
            lock_time: 100_000
          },
          prev_vout: 0,
          redeem_script: nil,
          sequence: 4_294_967_294
        }
      ]
    }
  ]

  # filter_dust
  describe "test filter_dust" do
    test "" do
      non_dust_outputs = Builder.filter_dust_outputs(example_outputs())
      assert non_dust_outputs == example_filtered_outputs()
    end
  end

  describe "calculate funding_input_infos sum" do
    test "" do
      for t <- @funding_input_infos do
        sum = Builder.sum_input_amounts(t.funding_input_infos)
        assert sum == t.sum
      end
    end
  end

  # fund_tx fee
  describe "test fund fee calculation" do
    test "funding fee test" do
      # for fee_rate <- 1..12 do
      # funding inputs for both parties
      accept_inputs = funding_input_examples1()
      accept_change_script = example_p2tr_scriptpubkey()

      offer_inputs = funding_input_examples2()
      offer_change_script = example_p2tr_scriptpubkey()

      change_outputs = [
        Builder.new_output(10000, accept_change_script),
        Builder.new_output(10000, offer_change_script)
      ]

      funding_output = Builder.new_output(200_000, example_p2tr_scriptpubkey())

      # calculate singleparty fund_vybtes & fees to pay
      accept_tx_vbytes =
        Builder.calculate_singleparty_funding_tx_vbytes(accept_inputs, accept_change_script)

      # accept_fee = Builder.calculate_fee(accept_tx_vbytes, fee_rate)

      offer_tx_vbytes =
        Builder.calculate_singleparty_funding_tx_vbytes(offer_inputs, offer_change_script)

      # offer_fee = Builder.calculate_fee(offer_tx_vbytes, fee_rate)

      # construct full tx & add dummy witnesses of proper len
      {funding_tx, _funding_vout} =
        Builder.build_funding_tx(accept_inputs ++ offer_inputs, funding_output, change_outputs)

      accept_witnesses = [
        example_p2wpkh_witness(),
        example_p2wpkh_witness(),
        example_p2wpkh_witness()
      ]

      offer_witnesses = [
        example_p2tr_keyspend_witness(),
        example_p2tr_keyspend_witness(),
        example_p2tr_keyspend_witness()
      ]

      funding_tx = %Transaction{funding_tx | witnesses: accept_witnesses ++ offer_witnesses}
      # calculate full tx fee, ensure same feerate
      tx_vbytes = Transaction.vbyte_size(funding_tx)

      # together, the two singleparty estimates should be at least the weight
      # of the actual tx, and no more than 2 bytes larger.
      joint_tx_vbytes_estimate = accept_tx_vbytes + offer_tx_vbytes
      assert joint_tx_vbytes_estimate >= tx_vbytes
      assert joint_tx_vbytes_estimate - tx_vbytes < 2
      # end
    end
  end

  # cet fee
  describe "test cet tx fee calculation" do
    # test "cet tx" do
    #   accept_payout_script = example_p2tr_scriptpubkey()
    #   offer_payout_script = example_p2tr_scriptpubkey()

    #   accept_cet_vbytes = Builder.calculate_singleparty_cet_tx_vbytes([accept_payout_script])
    #   offer_cet_vbytes = Builder.calculate_singleparty_cet_tx_vbytes([offer_payout_script])

    #   cet_tx = Builder.build_cet_tx(example_p2tr_input(), 100_000, accept_payout_script, offer_payout_script, {"", 50_000}, 0)
    #   funding_witness = example_p2tr_scriptspend_witness()
    #   cet_tx = %Transaction{cet_tx | witnesses: [funding_witness]}

    #   cet_tx_vbytes = Transaction.vbyte_size(cet_tx)

    #   joint_cet_tx_vbytes_estimate = accept_cet_vbytes + offer_cet_vbytes
    #   assert joint_tx_vbytes_estimate >= tx_vbytes
    #   assert joint_tx_vbytes_estimate - tx_vbytes < 2
    # end

    def populate_dummy_script(len) do
      case len do
        0 ->
          nil

        # ??? its in the test vectors though. Create bogus datapush script
        x ->
          {:ok, s} =
            Script.parse_script(
              <<0x00>> <> Utils.encode_int(x - 2) <> <<0::little-size((x - 2) * 8)>>
            )

          s
      end
    end

    def populate_dummy_inputs(inputs) do
      {:ok, tx} =
        Transaction.decode(
          "0100000000010149d1f8c9e4a6b97a0d6d00b67ee25eee2213521c057565a9a55df3259c4676e40000000000ffffffff025038a9000000000017a914290d5b2ba36d0616f9134b5bf93eca3817a55a67876eef140100000000160014d701ce5e753bd9454d343c8a3b86d84a3c34dbf502483045022100a6f040382b8e873c51a165621c0ec3c90c0352f8ddbf24253031c36078a7452302207b7a272a09b89e466483420a0700692a895a1cd1d99dae4ce6c500faf34bb63e012102ee3c98964dd1bfe13bee16c0b95fcf8281f12c5885d1fcb7b59fc2cb01ca763200000000"
        )

      Enum.map(inputs, fn input ->
        %{
          prev_tx: tx,
          prev_vout: 0,
          sequence: 0xFFFFFFFE,
          max_witness_len: Map.fetch!(input, "maxWitnessLen"),
          redeem_script: populate_dummy_script(Map.fetch!(input, "redeemScriptLen"))
        }
      end)
    end

    def load_tx_inputs(t, inputs) do
      t
      |> Map.fetch!(inputs)
      |> populate_dummy_inputs()
    end
  end

  describe "full test" do
    test "dlcspec test vectors funding txs" do
      filename = "test/dlcspec_vectors/dlc_fee_test.json"

      {:ok, data} = File.read(filename)
      {:ok, tests} = Poison.decode(data)

      for t <- tests do
        # load inputs
        inputs = Map.fetch!(t, "inputs")
        accept_inputs = load_tx_inputs(inputs, "acceptInputs")
        offer_inputs = load_tx_inputs(inputs, "offerInputs")

        accept_payout_script = populate_dummy_script(Map.fetch!(inputs, "acceptPayoutSPKLen"))
        offer_payout_script = populate_dummy_script(Map.fetch!(inputs, "offerPayoutSPKLen"))

        accept_change_script = populate_dummy_script(Map.fetch!(inputs, "acceptChangeSPKLen"))
        offer_change_script = populate_dummy_script(Map.fetch!(inputs, "offerChangeSPKLen"))

        fee_rate = Map.fetch!(inputs, "feeRate")

        # calculate funding fees
        accept_tx_vbytes =
          Builder.calculate_singleparty_funding_tx_vbytes(accept_inputs, accept_change_script)

        accept_funding_fee = Builder.calculate_fee(accept_tx_vbytes, fee_rate)

        offer_tx_vbytes =
          Builder.calculate_singleparty_funding_tx_vbytes(offer_inputs, offer_change_script)

        offer_funding_fee = Builder.calculate_fee(offer_tx_vbytes, fee_rate)

        # load expected results
        c_offer_funding_fee = Map.fetch!(t, "offerFundingFee")
        # c_offer_closing_fee = Map.fetch!(t, "offerClosingFee")
        c_accept_funding_fee = Map.fetch!(t, "acceptFundingFee")
        # c_accept_closing_fee = Map.fetch!(t, "acceptClosingFee")

        # TODO We have a minor inaccuracy viz-a-viz DLCSpec test vectors
        # in our tx fee estimation but its never off by more than 2 bytes, so its not too bad
        accept_diff = c_accept_funding_fee - accept_funding_fee
        assert accept_diff <= 2 * fee_rate

        offer_diff = c_offer_funding_fee - offer_funding_fee
        assert offer_diff <= 2 * fee_rate

        # calculate settlement fees
        # CET fees won't be the same as test vectors since we use P2TR scriptpath not P2WSH
        # TODO add own test vectors
        # assert c_offer_closing_fee ==
        # assert c_accept_closing_fee ==
      end
    end
  end
end
