defmodule ExFacto.ContractTest do
  use ExUnit.Case
  doctest ExFacto.Contract

  alias ExFacto.Contract

  def get_bin(m, key), do: Map.fetch!(m, key) |> Base.decode16!(case: :lower)
  def get_int(m, key), do: Map.fetch!(m, key)

  @offers [
    %{
      offer_id:
        65_191_725_439_089_355_908_111_615_769_300_204_093_617_297_022_610_062_829_115_666_503_151_019_721_118,
      offer: %ExFacto.Contract.Offer{
        version: 0,
        contract_flags: 0,
        chain_hash:
          <<0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206, 217,
            15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67>>,
        contract_info: %ExFacto.Contract{
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
        },
        funding_pubkey: %Bitcoinex.Secp256k1.Point{
          x:
            13_046_381_441_185_578_206_173_916_196_553_656_771_870_467_164_262_121_847_591_027_029_131_609_172_334,
          y:
            19_220_529_104_632_635_439_108_914_606_164_677_963_810_106_594_662_176_468_734_601_431_709_699_342_552,
          z: 0
        },
        payout_script: %Bitcoinex.Script{
          items: [
            81,
            32,
            <<39, 172, 241, 119, 115, 83, 253, 32, 178, 181, 16, 130, 62, 44, 139, 86, 194, 162,
              101, 249, 203, 42, 16, 233, 167, 108, 250, 85, 140, 148, 157, 33>>
          ]
        },
        collateral_amount: 50_000_000,
        funding_inputs: [
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
        change_script: %Bitcoinex.Script{
          items: [
            81,
            32,
            <<3, 147, 139, 165, 52, 158, 91, 119, 2, 23, 7, 49, 251, 30, 210, 60, 208, 255, 97,
              219, 39, 225, 11, 187, 16, 179, 110, 4, 209, 63, 242, 219>>
          ]
        },
        fee_rate: 2,
        cet_locktime: 1_678_498_879,
        refund_locktime: 1_679_702_879,
        tlvs: nil
      }
    }
  ]

  describe "id calculation" do
    test "calculate offer_id" do
      for t <- @offers do
        offer_id = Contract.Offer.calculate_offer_id(t.offer)
        assert offer_id == t.offer_id
      end
    end

    test "calculate contract_id" do
      filename = "test/dlcspec_vectors/contract_id_test.json"

      {:ok, data} = File.read(filename)
      {:ok, tests} = Poison.decode(data)

      for t <- tests do
        c_contract_id = get_bin(t, "contractId")
        fund_vout = get_int(t, "fundOutputIndex")
        fund_txid = get_bin(t, "fundTxId")
        temp_contract_id = get_bin(t, "temporaryContractId")

        contract_id = Contract.calculate_contract_id(fund_txid, fund_vout, temp_contract_id)
        assert contract_id == c_contract_id
      end
    end
  end
end
