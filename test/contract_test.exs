defmodule ExFacto.ContractTest do
  use ExUnit.Case
  doctest ExFacto.Contract

  alias ExFacto.Contract

  def get_bin(m, key), do: Map.fetch!(m, key) |> Base.decode16!(case: :lower)
  def get_int(m, key), do: Map.fetch!(m, key)

  describe "contract_id" do
    # test "calculate temp_contract_id" do

    # end

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
