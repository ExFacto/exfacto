defmodule ExFacto.MessagingTest do
  use ExUnit.Case
  doctest ExFacto.Messaging

  alias ExFacto.{Messaging, Event}
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
    "522103a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af957521036ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640d210311ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef53ae"
  ]

  @cet_adaptor_signatures [
    %{
      adaptor_signature: %Bitcoinex.Secp256k1.Signature{
        r:
          8_452_702_831_967_167_134_703_690_397_529_993_049_769_102_016_778_040_255_098_083_991_433_522_811_449,
        s:
          63_666_919_473_820_067_314_254_645_779_439_296_819_988_898_893_398_369_473_825_423_844_020_090_159_738
      },
      was_negated: false
    },
    %{
      adaptor_signature: %Bitcoinex.Secp256k1.Signature{
        r:
          28_865_194_841_104_661_565_299_824_354_531_180_288_040_977_263_529_974_854_078_615_047_551_017_151_669,
        s:
          46_772_989_195_977_650_514_826_199_438_298_360_424_789_156_412_303_377_065_601_723_456_687_270_232_192
      },
      was_negated: false
    }
  ]

  @funding_input_infos [
    [
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
    ],
    [
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
        sequence: 4_294_967_294,
        max_witness_len: 108
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
        prev_vout: 1,
        redeem_script: nil,
        sequence: 4_294_967_294,
        max_witness_len: 64
      }
    ]
  ]

  @funding_witnesses [
    [
      %Transaction.Witness{
        txinwitness: []
      },
      %Transaction.Witness{
        txinwitness: [
          "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
        ]
      }
    ],
    [
      %Transaction.Witness{
        txinwitness: [
          "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
        ]
      },
      %Transaction.Witness{
        txinwitness: []
      }
    ],
    [
      %Transaction.Witness{
        txinwitness: [
          "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
        ]
      },
      %Transaction.Witness{
        txinwitness: []
      },
      %Transaction.Witness{
        txinwitness: [
          "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
          "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
        ]
      }
    ]
  ]

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

  @dlcspec_events [
    %{
    hex: "fdd8224e00013a2c422295dce607d3350e09530ae713a58fd5629e287452d400910c34142a706317df00fdd8060e0002054845414453055441494c531559657420416e6f7468657220436f696e20466c6970",
    event: %ExFacto.Event{
      id: "Yet Another Coin Flip",
      nonce_points: [
        %Bitcoinex.Secp256k1.Point{
          x: 26312342936359178150622555548499246551738633326874346112063830638709802543728,
          y: 74615337950833348788289066904762431058621341577109663184119116632231914658250,
          z: 0
        }
      ],
      descriptor: %{outcomes: ["HEADS", "TAILS"]},
      maturity_epoch: 1662508800
    }
  }
  ]

  @dlcspec_announcements [
    %{
      hex:
        "fdd824b28b92f54b966050ff418fc371d99bf9293564a889ee5570c5a0267b0ff08f594178d372a56f7ecb48108a5e78295bad19cc7c02d11b313a5716602cbcdca718666d5b21a0fd11bc339b4811f74ce5c4eccad4e0f20d44e2aabdec06bf206397aefdd8224e00013a2c422295dce607d3350e09530ae713a58fd5629e287452d400910c34142a706317df00fdd8060e0002054845414453055441494c531559657420416e6f7468657220436f696e20466c6970",
      announcement: %ExFacto.Oracle.Announcement{
        signature: %Bitcoinex.Secp256k1.Signature{
          r:
            63_131_138_590_219_101_837_408_461_175_232_692_705_436_038_477_762_288_089_920_157_340_453_431_105_857,
          s:
            54_651_137_819_876_764_332_013_655_892_062_080_287_140_530_153_877_749_890_519_026_210_989_052_205_158
        },
        public_key: %Bitcoinex.Secp256k1.Point{
          x:
            49_463_115_676_343_085_754_197_350_475_275_151_660_295_559_127_171_114_198_435_097_608_539_563_333_550,
          y:
            51_625_052_320_939_938_233_560_171_558_171_669_425_913_728_132_246_447_519_429_399_557_637_745_226_896,
          z: 0
        },
        event: %ExFacto.Event{
          id: "Yet Another Coin Flip",
          nonce_points: [
            %Bitcoinex.Secp256k1.Point{
              x:
                26_312_342_936_359_178_150_622_555_548_499_246_551_738_633_326_874_346_112_063_830_638_709_802_543_728,
              y:
                74_615_337_950_833_348_788_289_066_904_762_431_058_621_341_577_109_663_184_119_116_632_231_914_658_250,
              z: 0
            }
          ],
          descriptor: %{outcomes: ["HEADS", "TAILS"]},
          maturity_epoch: 1_662_508_800
        }
      }
    }
  ]

  @attestations [
    # TODO
  ]

  @dlcspec_attestations [
    %{
      hex:
        "fdd8687e1559657420416e6f7468657220436f696e20466c69706d5b21a0fd11bc339b4811f74ce5c4eccad4e0f20d44e2aabdec06bf206397ae00013a2c422295dce607d3350e09530ae713a58fd5629e287452d400910c34142a7025bad1cf89e77cac10501dfba25c119f7ec9b40310d613b888cee36e1bbd4b1c055441494c53",
      attestation: %ExFacto.Oracle.Attestation{
        public_key: %Bitcoinex.Secp256k1.Point{
          x:
            49_463_115_676_343_085_754_197_350_475_275_151_660_295_559_127_171_114_198_435_097_608_539_563_333_550,
          y:
            51_625_052_320_939_938_233_560_171_558_171_669_425_913_728_132_246_447_519_429_399_557_637_745_226_896,
          z: 0
        },
        signatures: [
          %Bitcoinex.Secp256k1.Signature{
            r:
              26_312_342_936_359_178_150_622_555_548_499_246_551_738_633_326_874_346_112_063_830_638_709_802_543_728,
            s:
              17_065_657_011_848_087_370_286_112_004_192_896_998_581_158_334_111_134_043_677_060_478_850_448_575_260
          }
        ],
        event_id: "Yet Another Coin Flip",
        outcomes: ["TAILS"]
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
      sz = :"u#{b * 8}"

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

    test "funding_input_info" do
      for t <- @funding_input_infos do
        {funding_inputs, <<>>} =
          t
          |> Messaging.serialize_funding_inputs()
          |> Messaging.parse_funding_inputs()

        assert funding_inputs == t
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

  describe "dlcspec compliance" do
    test "events" do
      for t <- @dlcspec_events do
        # serialize
        msg = Event.to_hex(t.event)
        assert msg == t.hex
        # parse
        {event, <<>>} = Event.parse(t.hex)
        assert event == t.event
      end
    end

    test "announcement" do
      for t <- @dlcspec_announcements do
        # serialize
        msg = Announcement.to_hex(t.announcement)
        assert msg == t.hex
        # parse
        {ann, <<>>} = Announcement.parse(t.hex)
        assert ann == t.announcement
      end
    end

    test "attestations" do
      for t <- @dlcspec_attestations do
        # serialize
        msg = Attestation.to_hex(t.attestation)
        assert msg == t.hex
        # parse
        {att, <<>>} = Attestation.parse(t.hex)
        assert att == t.attestation
      end
    end
  end
end
