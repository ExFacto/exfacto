defmodule ExFacto.Utils do
  # alias Bitcoinex.Utils
  alias Bitcoinex.{Script, Secp256k1.PrivateKey, Secp256k1}

  @type outpoint :: {String.t(), non_neg_integer()}

  @protocol_version_v0 0
  def get_protocol_version(), do: @protocol_version_v0

  def new_rand_int() do
    32
    |> :crypto.strong_rand_bytes()
    |> :binary.decode_unsigned()
  end

  def new_serial_id(), do: new_rand_int()

  def new_private_key() do
    {:ok, sk} =
      new_rand_int()
      |> PrivateKey.new()

    Secp256k1.force_even_y(sk)
  end

  def big_size(compact_size) do
    cond do
      compact_size >= 0 and compact_size <= 0xFC ->
        <<compact_size::big-size(8)>>

      compact_size <= 0xFFFF ->
        <<0xFD>> <> <<compact_size::big-size(16)>>

      compact_size <= 0xFFFFFFFF ->
        <<0xFE>> <> <<compact_size::big-size(32)>>

      compact_size <= 0xFF ->
        <<0xFF>> <> <<compact_size::big-size(64)>>
    end
  end

  def get_counter(<<counter::big-size(8), vec::binary>>) do
    case counter do
      # 0xFD followed by the length as uint16_t
      0xFD ->
        <<len::big-size(16), vec::binary>> = vec
        {len, vec}

      # 0xFE followed by the length as uint32_t
      0xFE ->
        <<len::big-size(32), vec::binary>> = vec
        {len, vec}

      # 0xFF followed by the length as uint64_t
      0xFF ->
        <<len::big-size(64), vec::binary>> = vec
        {len, vec}

      _ ->
        {counter, vec}
    end
  end

  def parse_compact_size_value(key_value) do
    {len, key_value} = get_counter(key_value)
    <<value::binary-size(len), remaining::binary>> = key_value
    {value, remaining}
  end

  def with_big_size(data) do
    data
    |> byte_size()
    |> big_size()
    |> Kernel.<>(data)
  end

  def script_with_big_size(script = %Script{}) do
    script
    |> Script.serialize_script()
    |> with_big_size()
  end

  @spec serialize_with_count(list(), any()) :: {non_neg_integer(), binary}
  def serialize_with_count(items, serialize_func) do
    Enum.reduce(items, {0, <<>>}, fn item, {ct, acc} ->
      {ct+1, acc <> serialize_func.(item)}
    end)
  end


end
