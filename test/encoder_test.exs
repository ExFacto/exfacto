defmodule ExFacto.EncoderTest do
  use ExUnit.Case
  doctest ExFacto.Encoder

  alias ExFacto.{Encoder, Oracle, Event}
  alias ExFacto.Oracle.{Announcement, Attestation}
  alias ExFacto.Contract.{Offer, Accept}
  alias Bitcoinex.{Script, Transaction}

  @events [
    %ExFacto.Event{
      id: "de8a901b458d1504db47fec55f54c5e1328be0a53a9ec6f082e2f001a74791bf",
      nonce_points: [
        %Bitcoinex.Secp256k1.Point{
          x:
            111_067_853_723_109_968_862_341_562_502_361_849_308_420_935_890_317_445_403_151_459_456_451_655_546_007,
          y:
            98_219_862_061_597_619_972_871_948_524_344_880_289_430_062_140_482_313_443_135_300_385_384_860_800_316,
          z: 0
        }
      ],
      descriptor: %{outcomes: ["CHIEFS WIN", "EAGLES WIN"]},
      maturity_epoch: 1_678_498_879
    }
  ]

  @announcements [
    %ExFacto.Oracle.Announcement{
      signature: %Bitcoinex.Secp256k1.Signature{
        r:
          74_394_279_223_756_576_794_272_994_696_959_201_136_545_732_660_825_157_347_207_683_579_661_196_532_062,
        s:
          15_088_053_102_944_490_215_898_831_902_819_553_553_708_576_856_562_884_099_012_052_197_723_821_337_344
      },
      public_key: %Bitcoinex.Secp256k1.Point{
        x:
          90_394_080_248_216_755_336_278_589_138_434_108_617_948_471_155_360_081_382_669_869_140_596_986_363_036,
        y:
          101_474_560_319_959_597_992_285_788_353_007_897_145_330_334_507_718_858_322_618_522_004_866_641_165_264,
        z: 0
      },
      event: %ExFacto.Event{
        id: "de8a901b458d1504db47fec55f54c5e1328be0a53a9ec6f082e2f001a74791bf",
        nonce_points: [
          %Bitcoinex.Secp256k1.Point{
            x:
              111_067_853_723_109_968_862_341_562_502_361_849_308_420_935_890_317_445_403_151_459_456_451_655_546_007,
            y:
              98_219_862_061_597_619_972_871_948_524_344_880_289_430_062_140_482_313_443_135_300_385_384_860_800_316,
            z: 0
          }
        ],
        descriptor: %{outcomes: ["CHIEFS WIN", "EAGLES WIN"]},
        maturity_epoch: 1_678_498_879
      }
    }
  ]

  @attestations [
    # TODO
  ]

  @contracts [
    %ExFacto.Contract{
      total_collateral: 100_000_000,
      descriptor: [{"CHIEFS WIN", 0}, {"EAGLES WIN", 100_000_000}],
      oracle_info: %{
        announcement: %ExFacto.Oracle.Announcement{
          signature: %Bitcoinex.Secp256k1.Signature{
            r:
              74_394_279_223_756_576_794_272_994_696_959_201_136_545_732_660_825_157_347_207_683_579_661_196_532_062,
            s:
              15_088_053_102_944_490_215_898_831_902_819_553_553_708_576_856_562_884_099_012_052_197_723_821_337_344
          },
          public_key: %Bitcoinex.Secp256k1.Point{
            x:
              90_394_080_248_216_755_336_278_589_138_434_108_617_948_471_155_360_081_382_669_869_140_596_986_363_036,
            y:
              101_474_560_319_959_597_992_285_788_353_007_897_145_330_334_507_718_858_322_618_522_004_866_641_165_264,
            z: 0
          },
          event: %ExFacto.Event{
            id: "de8a901b458d1504db47fec55f54c5e1328be0a53a9ec6f082e2f001a74791bf",
            nonce_points: [
              %Bitcoinex.Secp256k1.Point{
                x:
                  111_067_853_723_109_968_862_341_562_502_361_849_308_420_935_890_317_445_403_151_459_456_451_655_546_007,
                y:
                  98_219_862_061_597_619_972_871_948_524_344_880_289_430_062_140_482_313_443_135_300_385_384_860_800_316,
                z: 0
              }
            ],
            descriptor: %{outcomes: ["CHIEFS WIN", "EAGLES WIN"]},
            maturity_epoch: 1_678_498_879
          }
        }
      }
    }
  ]

  @offers [
    %ExFacto.Contract.Offer{
      version: 0,
      contract_flags: 0,
      chain_hash:
        <<0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206, 217, 15,
          163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67>>,
      offer_id:
        <<23, 113, 111, 65, 125, 160, 195, 120, 114, 184, 44, 198, 47, 81, 173, 235, 131, 230,
          199, 133, 156, 34, 244, 91, 178, 24, 108, 177, 162, 224, 235, 118>>,
      contract_info: %ExFacto.Contract{
        total_collateral: 100_000_000,
        descriptor: [{"CHIEFS WIN", 0}, {"EAGLES WIN", 100_000_000}],
        oracle_info: %{
          announcement: %ExFacto.Oracle.Announcement{
            signature: %Bitcoinex.Secp256k1.Signature{
              r:
                34_990_150_429_969_567_872_419_901_581_148_415_077_196_455_065_790_319_621_416_977_863_523_532_842_035,
              s:
                112_897_498_301_182_476_897_994_910_550_258_485_327_812_997_611_568_291_961_027_155_882_600_334_052_503
            },
            public_key: %Bitcoinex.Secp256k1.Point{
              x:
                63_836_016_090_621_579_538_018_341_679_870_816_089_134_175_427_578_863_018_685_135_020_341_244_429_099,
              y:
                7_762_423_201_341_024_809_386_861_498_144_792_764_392_384_755_050_675_881_369_144_943_712_955_725_460,
              z: 0
            },
            event: %ExFacto.Event{
              id: "bd0276384b1e81b6e93ba07981c584e90262d44bb5b212334aad0211212eb7f5",
              nonce_points: [
                %Bitcoinex.Secp256k1.Point{
                  x:
                    111_069_474_625_714_919_918_482_384_078_840_446_194_528_854_476_298_253_686_973_206_939_061_396_532_243,
                  y:
                    90_027_847_584_268_126_950_760_867_076_396_047_836_799_726_927_506_068_933_841_772_253_266_280_305_656,
                  z: 0
                }
              ],
              descriptor: %{outcomes: ["CHIEFS WIN", "EAGLES WIN"]},
              maturity_epoch: 1_678_498_879
            }
          }
        }
      },
      funding_pubkey: %Bitcoinex.Secp256k1.Point{
        x:
          23_360_314_246_058_653_695_188_183_797_085_476_706_522_923_974_404_413_816_872_771_157_416_707_499_653,
        y:
          50_649_542_849_068_517_976_917_855_838_985_766_719_798_066_399_921_381_634_371_218_573_794_760_076_162,
        z: 0
      },
      payout_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<138, 103, 149, 79, 180, 168, 133, 143, 163, 165, 76, 126, 76, 172, 168, 175, 63, 49,
            1, 200, 124, 83, 168, 172, 214, 19, 24, 115, 202, 2, 26, 65>>
        ]
      },
      collateral_amount: 50_000_000,
      funding_inputs: [
        %{
          amount: 100_000_000,
          max_witness_len: 64,
          prev_tx: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "bcda2fe66ca90e922c3679b224b7b38e34660049a597a8193b850e951c90b268",
                prev_vout: 6,
                script_sig: "",
                sequence_no: 4_294_967_294
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 100_000_000,
                script_pub_key:
                  "51200f7ea178a09b5d9801088ab34ee5232a5b567b479c1aaf2a7a39be5dcce8e4e3"
              }
            ],
            witnesses: nil,
            lock_time: 0
          },
          prev_vout: 0,
          redeem_script: nil,
          sequence: 4_294_967_294
        }
      ],
      change_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<247, 161, 129, 228, 74, 72, 255, 178, 63, 120, 93, 207, 74, 190, 71, 206, 89, 213,
            222, 192, 27, 56, 162, 156, 126, 149, 13, 142, 117, 55, 131, 236>>
        ]
      },
      fee_rate: 2,
      cet_locktime: 1_678_498_879,
      refund_locktime: 1_679_702_879,
      tlvs: nil
    }
  ]

  @accepts [
    %ExFacto.Contract.Accept{
      version: 0,
      chain_hash:
        <<0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206, 217, 15,
          163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67>>,
      contract_id:
        <<31, 228, 45, 144, 201, 99, 133, 236, 236, 126, 183, 98, 28, 122, 101, 53, 186, 122, 186,
          120, 251, 146, 243, 147, 13, 114, 131, 23, 195, 249, 143, 196>>,
      offer_id:
        <<107, 250, 53, 140, 121, 127, 129, 1, 32, 21, 109, 81, 31, 96, 226, 225, 160, 128, 245,
          13, 177, 190, 156, 209, 10, 71, 16, 244, 94, 203, 103, 146>>,
      funding_pubkey: %Bitcoinex.Secp256k1.Point{
        x:
          115_173_691_961_261_604_234_971_760_036_970_987_575_681_931_132_440_858_626_218_853_319_792_245_342_254,
        y:
          106_732_370_398_947_387_171_276_185_558_782_171_202_505_898_468_952_487_808_082_224_868_036_261_274_432,
        z: 0
      },
      dummy_tapkey_tweak:
        50_873_436_422_722_464_044_439_349_450_733_382_134_259_854_848_747_707_355_699_559_803_029_102_725_681,
      payout_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<168, 118, 155, 10, 75, 4, 5, 243, 73, 96, 18, 45, 89, 117, 44, 211, 119, 28, 53, 73,
            52, 245, 44, 77, 155, 250, 162, 25, 68, 135, 123, 66>>
        ]
      },
      change_script: %Bitcoinex.Script{
        items: [
          81,
          32,
          <<8, 87, 181, 177, 230, 23, 132, 20, 172, 199, 98, 39, 116, 242, 29, 81, 70, 78, 173,
            217, 223, 12, 125, 154, 23, 207, 11, 113, 229, 33, 71, 65>>
        ]
      },
      collateral_amount: 50_000_000,
      funding_inputs: [
        %{
          amount: 100_000_000,
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
                  "5120173acf11eaf0430c7fbdfa7ceee309178094b7f8d1e1af7137687589c1c6bfa4"
              }
            ],
            witnesses: nil,
            lock_time: 0
          },
          prev_vout: 0,
          redeem_script: nil,
          sequence: 4_294_967_294
        }
      ],
      cet_adaptor_signatures: [
        %{
          adaptor_signature: %Bitcoinex.Secp256k1.Signature{
            r:
              87_318_959_201_378_187_720_759_494_052_292_383_522_665_133_978_592_189_100_770_837_360_418_282_845_612,
            s:
              58_602_801_186_288_728_807_551_283_536_112_985_298_239_208_379_553_448_534_829_428_710_414_898_926_159
          },
          was_negated: true
        },
        %{
          adaptor_signature: %Bitcoinex.Secp256k1.Signature{
            r:
              38_442_300_185_406_578_792_207_349_113_335_933_693_760_701_067_066_138_817_757_572_171_584_448_005_987,
            s:
              98_993_361_140_950_387_878_933_120_859_903_065_114_553_095_419_001_615_851_511_879_974_570_434_385_187
          },
          was_negated: false
        }
      ],
      refund_signature: %Bitcoinex.Secp256k1.Signature{
        r:
          97_241_178_561_803_237_645_070_179_086_462_997_477_080_679_604_473_422_209_272_309_384_962_818_813_435,
        s:
          50_009_011_244_591_821_688_460_710_109_774_349_038_353_424_076_480_600_924_890_600_241_350_597_336_506
      }
    }
  ]

  @acknowledges [
    %ExFacto.Contract.Acknowledge{
      contract_id:
        <<117, 190, 36, 128, 131, 184, 152, 18, 54, 67, 139, 101, 30, 31, 143, 209, 176, 173, 113,
          146, 164, 142, 251, 191, 231, 135, 179, 232, 82, 129, 36, 143>>,
      funding_witnesses: nil,
      cet_adaptor_signatures: [
        %{
          adaptor_signature: %Bitcoinex.Secp256k1.Signature{
            r:
              71_545_299_047_403_584_280_350_093_102_881_688_899_045_651_630_875_972_501_665_480_063_499_441_775_354,
            s:
              113_255_400_802_490_240_213_356_401_307_713_237_895_933_173_450_941_633_902_558_963_401_455_761_658_868
          },
          was_negated: true
        },
        %{
          adaptor_signature: %Bitcoinex.Secp256k1.Signature{
            r:
              113_943_090_579_295_950_747_425_423_646_814_870_534_250_816_951_008_286_503_127_944_112_158_272_850_817,
            s:
              98_411_006_057_455_546_361_992_457_794_195_164_115_046_965_386_001_900_636_803_840_984_332_865_348_491
          },
          was_negated: true
        }
      ],
      refund_signature: %Bitcoinex.Secp256k1.Signature{
        r:
          68_365_117_727_113_787_193_406_509_136_072_374_812_719_626_143_900_228_734_004_104_953_954_332_899_542,
        s:
          79_004_258_105_906_074_360_111_001_897_659_133_199_729_191_643_905_471_892_954_206_592_133_776_135_360
      }
    }
  ]

  describe "single-message symmetry" do
    test "events" do
      for t <- @events do
        events =
          t
          |> Encoder.encode()
          |> Encoder.decode()

        assert length(events) == 1
        assert Enum.at(events, 0) == t
      end
    end

    test "announcements" do
      for t <- @announcements do
        announcements =
          t
          |> Encoder.encode()
          |> Encoder.decode()

        assert length(announcements) == 1
        assert Enum.at(announcements, 0) == t
      end
    end

    test "attestations" do
      for t <- @attestations do
        attestations =
          t
          |> Encoder.encode()
          |> Encoder.decode()

        assert length(attestations) == 1
        assert Enum.at(attestations, 0) == t
      end
    end

    test "offers" do
      for t <- @offers do
        offers =
          t
          |> Encoder.encode()
          |> Encoder.decode()

        assert length(offers) == 1
        assert Enum.at(offers, 0) == t
      end
    end

    test "accepts" do
      for t <- @accepts do
        accepts =
          t
          |> Encoder.encode()
          |> Encoder.decode()

        assert length(accepts) == 1
        assert Enum.at(accepts, 0) == t
      end
    end

    test "acknowledges" do
    end
  end

  describe "multi-message symmetry" do
    test "one of each event" do
      collection = [
        Enum.at(@events, 0),
        Enum.at(@announcements, 0),
        Enum.at(@attestations, 0),
        Enum.at(@contracts, 0),
        Enum.at(@offers, 0),
        Enum.at(@accepts, 0)
      ]

      res =
        collection
        |> Encoder.encode()
        |> Encoder.decode()

      assert length(res) == length(collection)
      assert res == collection
    end
  end
end
