defmodule ExFacto.MessagingTest do
  use ExUnit.Case
  doctest ExFacto.Messaging

  alias ExFacto.{Messaging, Oracle, Event}
  alias ExFacto.Oracle.{Announcement, Attestation}
  alias ExFacto.Contract.{Offer, Accept}
  alias Bitcoinex.{Script, Transaction}

  @strings [
    "",
    "a",
    "aa",
    "AAAAA",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "1234567890-=/+[]{}|~qwertyuiopasdfghjkl;zxcvbnm,./?QWERTYUIOPASDFGHJKLZXCVBNM,."
  ]

  @scripts [
    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    "21035ce3ee697cd5148e12ab7bb45c1ef4dd5ee2bf4867d9d35135e214e073211344ac",
    "a9148a7810adbe753308a8ccae63f81841c92554174487",
    "76a91408be653b5582bb9c1b85ab1da70906946c90acc588ac",
    "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d",
    "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    "51200101010101010101010101010101010101010101010101010101010101010101",
    "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "522103a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af957521036ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640d210311ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef53ae",
  ]

  @events [
    %ExFacto.Event{
      id: "de8a901b458d1504db47fec55f54c5e1328be0a53a9ec6f082e2f001a74791bf",
      nonce_points: [
        %Bitcoinex.Secp256k1.Point{
          x: 111067853723109968862341562502361849308420935890317445403151459456451655546007,
          y: 98219862061597619972871948524344880289430062140482313443135300385384860800316,
          z: 0
        }
      ],
      descriptor: %{outcomes: ["CHIEFS WIN", "EAGLES WIN"]},
      maturity_epoch: 1678498879
    }
  ]

  @announcements [
    %ExFacto.Oracle.Announcement{
      signature: %Bitcoinex.Secp256k1.Signature{
        r: 74394279223756576794272994696959201136545732660825157347207683579661196532062,
        s: 15088053102944490215898831902819553553708576856562884099012052197723821337344
      },
      public_key: %Bitcoinex.Secp256k1.Point{
        x: 90394080248216755336278589138434108617948471155360081382669869140596986363036,
        y: 101474560319959597992285788353007897145330334507718858322618522004866641165264,
        z: 0
      },
      event: %ExFacto.Event{
        id: "de8a901b458d1504db47fec55f54c5e1328be0a53a9ec6f082e2f001a74791bf",
        nonce_points: [
          %Bitcoinex.Secp256k1.Point{
            x: 111067853723109968862341562502361849308420935890317445403151459456451655546007,
            y: 98219862061597619972871948524344880289430062140482313443135300385384860800316,
            z: 0
          }
        ],
        descriptor: %{outcomes: ["CHIEFS WIN", "EAGLES WIN"]},
        maturity_epoch: 1678498879
      }
    }

  ]

  @offers [
    %ExFacto.Contract.Offer{
      version: 0,
      contract_flags: 0,
      chain_hash: <<0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206, 217,
        15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67>>,
      temp_contract_id: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0>>,
      contract_info: %ExFacto.Contract{
        total_collateral: 100000000,
        descriptor: [{"CHIEFS WIN", 0}, {"EAGLES WIN", 100000000}],
        oracle_info: %ExFacto.Oracle.Announcement{
          signature: %Bitcoinex.Secp256k1.Signature{
            r: 74394279223756576794272994696959201136545732660825157347207683579661196532062,
            s: 15088053102944490215898831902819553553708576856562884099012052197723821337344
          },
          public_key: %Bitcoinex.Secp256k1.Point{
            x: 90394080248216755336278589138434108617948471155360081382669869140596986363036,
            y: 101474560319959597992285788353007897145330334507718858322618522004866641165264,
            z: 0
          },
          event: %ExFacto.Event{
            id: "de8a901b458d1504db47fec55f54c5e1328be0a53a9ec6f082e2f001a74791bf",
            nonce_points: [
              %Bitcoinex.Secp256k1.Point{
                x: 111067853723109968862341562502361849308420935890317445403151459456451655546007,
                y: 98219862061597619972871948524344880289430062140482313443135300385384860800316,
                z: 0
              }
            ],
            descriptor: %{outcomes: ["CHIEFS WIN", "EAGLES WIN"]},
            maturity_epoch: 1678498879
          }
        }
      },
      funding_pubkey: %Bitcoinex.Secp256k1.Point{
        x: 13046381441185578206173916196553656771870467164262121847591027029131609172334,
        y: 19220529104632635439108914606164677963810106594662176468734601431709699342552,
        z: 0
      },
      payout_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<39, 172, 241, 119, 115, 83, 253, 32, 178, 181, 16, 130, 62, 44, 139, 86, 194, 162, 101, 249,
            203, 42, 16, 233, 167, 108, 250, 85, 140, 148, 157, 33>>
        ]
      },
      collateral_amount: 50000000,
      funding_inputs: [
        %{
          amount: 100000000,
          max_witness_len: 64,
          prev_tx: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "bcda2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4294967294
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 100000000,
                script_pub_key: "512086143e7dcfd988633682be2b71c5f556a9ed930aef8cc1bfaded0eed56215b31"
              }
            ],
            witnesses: nil,
            lock_time: 0
          },
          prev_vout: 0,
          redeem_script: nil,
          sequence: 4294967294
        }
      ],
      change_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<3, 147, 139, 165, 52, 158, 91, 119, 2, 23, 7, 49, 251, 30, 210, 60, 208, 255, 97, 219, 39,
            225, 11, 187, 16, 179, 110, 4, 209, 63, 242, 219>>
        ]
      },
      fee_rate: 2,
      cet_locktime: 1678498879,
      refund_locktime: 1679702879,
      tlvs: nil
    }
  ]

  @cet_adaptor_signatures [
    %{adaptor_signature: %Bitcoinex.Secp256k1.Signature{
       r: 8452702831967167134703690397529993049769102016778040255098083991433522811449,
       s: 63666919473820067314254645779439296819988898893398369473825423844020090159738
     }, was_negated: false},
    %{adaptor_signature: %Bitcoinex.Secp256k1.Signature{
       r: 28865194841104661565299824354531180288040977263529974854078615047551017151669,
       s: 46772989195977650514826199438298360424789156412303377065601723456687270232192
     }, was_negated: false}
  ]

  @funding_witnesses [
    [%Transaction.Witness{
      txinwitness: []
    },
    %Transaction.Witness{
      txinwitness: [
        "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
      ]
    }],

  ]

  @accepts [
    %ExFacto.Contract.Accept{
      version: 0,
      chain_hash: <<0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
        217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67>>,
      temp_contract_id: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0>>,
      funding_pubkey: %Bitcoinex.Secp256k1.Point{
        x: 112039435473582708901458290925425415208882676393698153661281452299195342881455,
        y: 47847476984214126585697553188068862326082371309665069708919202593013279008408,
        z: 0
      },
      payout_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<214, 239, 31, 160, 153, 152, 35, 1, 93, 149, 173, 160, 195, 196, 166, 44, 54, 83, 123, 247,
            174, 194, 66, 32, 2, 138, 145, 60, 224, 225, 133, 199>>
        ]
      },
      change_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<190, 6, 92, 58, 182, 203, 65, 111, 29, 96, 180, 56, 137, 17, 17, 235, 217, 21, 139, 78,
            248, 151, 241, 176, 89, 140, 14, 35, 136, 117, 220, 234>>
        ]
      },
      collateral_amount: 50000000,
      funding_inputs: [
        %{
          amount: 100000000,
          max_witness_len: 64,
          prev_tx: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "bcda2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4294967294
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 100000000,
                script_pub_key: "51200a31874e737159447c69fb284a8cb890533f5cc7096448cc441aa6f2793384e6"
              }
            ],
            witnesses: nil,
            lock_time: 0
          },
          prev_vout: 0,
          redeem_script: "",
          sequence: 4294967294
        }
      ],
      funding_witnesses: [%Transaction.Witness{
        txinwitness: []
      },
      %Transaction.Witness{
        txinwitness: [
          "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
        ]
      }],
      cet_adaptor_signatures: [
        %{adaptor_signature: %Bitcoinex.Secp256k1.Signature{
           r: 8452702831967167134703690397529993049769102016778040255098083991433522811449,
           s: 63666919473820067314254645779439296819988898893398369473825423844020090159738
         }, was_negated: false},
        %{adaptor_signature: %Bitcoinex.Secp256k1.Signature{
           r: 28865194841104661565299824354531180288040977263529974854078615047551017151669,
           s: 46772989195977650514826199438298360424789156412303377065601723456687270232192
         }, was_negated: false}
      ],
      refund_signature: %Bitcoinex.Secp256k1.Signature{
        r: 3446189794769019937421287423656059447725566735138465699609476512815498798044,
        s: 51700873519172705935495752734112586584693969938438194293647447316060972020934
      },
      dummy_tapkey_tweak: 26818449057611358697594695413520937708107939349737122417988390949518817463526,
      negotiation_fields: nil,
      tlvs: nil
    }
  ]

  describe "basic par/ser symmetry" do
    test "bools" do
      for t <- [true, false] do
        {res, <<>>} =
          t
          |> Messaging.ser(:bool)
          |> Messaging.par(:bool)
        assert res == t
      end
    end

    def test_integer_symmetry(b) do
      sz = :"u#{b*8}"
      for _ <- 0..1000 do
        x =
          b
          # TODO find faster/weaker randomness to speed up test
          |> :crypto.strong_rand_bytes()
          |> :binary.decode_unsigned()
        {res, <<>>} =
          x
          |> Messaging.ser(sz)
          |> Messaging.par(sz)
        assert res == x
      end
    end

    test "u8s" do
      test_integer_symmetry(1)
    end

    test "u16s" do
      test_integer_symmetry(2)
    end

    test "u32s" do
      test_integer_symmetry(4)
    end

    test "u64s" do
      test_integer_symmetry(8)
    end

    test "u256s" do
      test_integer_symmetry(32)
    end

    test "utf8 strings" do
      for t <- @strings do
        {res, <<>>} =
          t
          |> Messaging.ser(:utf8)
          |> Messaging.par(:utf8)
        assert res == t
      end
    end

    # TODO test Normalization

    test "empty script" do
      for t <- ["", nil] do
        {msg, <<>>} =
          t
          |> Messaging.ser(:script)
          |> Messaging.par(:script)
        assert msg == nil
      end
    end
    test "non-empty script" do
      for t <- @scripts do
        {:ok, s} = Script.parse_script(t)
        {msg, <<>>} =
          s
          |> Messaging.ser(:script)
          |> Messaging.par(:script)
        assert msg == s
      end
    end
  end

  describe "message parts" do
    test "cet_adaptor_signatures" do
      for t <- @cet_adaptor_signatures do
        {cet_sig, <<>>} =
          t
          |> Accept.serialize_cet_adaptor_signature()
          |> Accept.parse_cet_adaptor_signature()
        assert cet_sig == t
      end
    end

    test "funding_witness" do
      for t <- @funding_witnesses do
        {funding_witnesses, <<>>} =
          t
          |> Messaging.serialize_funding_witnesses()
          |> Messaging.parse_funding_witnesses()
        assert funding_witnesses == t
      end
    end
  end

  describe "full message symmetry" do
    test "events" do
      for t <- @events do
        {msg, <<>>} =
          t
          |> Event.serialize()
          |> Event.parse()
        assert msg == t
      end
    end

    test "announcements" do
      for t <- @announcements do
        {msg, <<>>} =
          t
          |> Announcement.serialize()
          |> Announcement.parse()
        assert msg == t
      end
    end

    test "attestations" do

    end

    test "offers" do
      for t <- @offers do
        msg =
          t
          |> Offer.serialize()
          |> Offer.parse()
        assert msg == t
      end
    end

    test "accepts" do
      for t <- @accepts do
        msg =
          t
          |> Accept.serialize()
          |> Accept.parse()
        assert msg == t
      end
    end
  end
end
