defmodule ExFacto.Chain do
  def chain_hash(:mainnet) do
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    |> Base.decode16!(case: :lower)
  end

  def chain_hash(:testnet) do
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    |> Base.decode16!(case: :lower)
  end
end
