defmodule ExFacto.SchnorrTest do
  use ExUnit.Case

  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{PrivateKey, Point, Signature, Schnorr}

  def sk_from_hex(h) do
    {:ok, sk} =
      h
      |> Base.decode16!(case: :lower)
      |> :binary.decode_unsigned()
      |> PrivateKey.new()

    sk
  end

  def pk_from_hex(h) do
    {:ok, pk} =
      h
      |> Base.decode16!(case: :lower)
      |> Point.lift_x()

    pk
  end

  def get_bin(m, key), do: Map.fetch!(m, key) |> Base.decode16!(case: :lower)

  def get_sighash(m) do
    Map.fetch!(m, "inputs")
    |> Map.fetch!("msgHash")
    |> Base.decode16!(case: :lower)
    |> :binary.decode_unsigned()
  end

  def get_privkey(m) do
    Map.fetch!(m, "inputs")
    |> Map.fetch!("privKey")
    |> sk_from_hex()
  end

  def get_privnonce(m) do
    Map.fetch!(m, "inputs")
    |> Map.fetch!("privNonce")
    |> sk_from_hex()
  end

  def get_pubkey(m, key) do
    Map.fetch!(m, key)
    |> pk_from_hex
  end

  def get_sigpoint(m) do
    {:ok, sigpoint} =
      Map.fetch!(m, "sigPoint")
      # |> Base.decode16!(case: :lower)
      |> Point.parse_public_key()

    sigpoint
  end

  def get_sig(m, key) do
    {:ok, sig} =
      Map.fetch!(m, key)
      |> Base.decode16!(case: :lower)
      |> Signature.parse_signature()

    sig
  end

  describe "schnorr sighash" do
    test "sigpoint calculation" do
      filename = "test/dlcspec_vectors/dlc_schnorr_test.json"
      {:ok, data} = File.read(filename)
      {:ok, tests} = Poison.decode(data)

      for t <- tests do
        privkey = get_privkey(t)
        pubkey = get_pubkey(t, "pubKey")
        priv_nonce = get_privnonce(t)
        pub_nonce = get_pubkey(t, "pubNonce")
        signature = get_sig(t, "signature")
        sig_point = get_sigpoint(t)
        sighash = get_sighash(t)

        pk = Secp256k1.force_even_y(privkey) |> PrivateKey.to_point()
        assert pk == pubkey

        nonce_point = Secp256k1.force_even_y(priv_nonce) |> PrivateKey.to_point()
        assert nonce_point == pub_nonce

        sigpoint =
          Schnorr.calculate_signature_point(pub_nonce, pubkey, <<sighash::big-size(256)>>)

        assert sigpoint == sig_point

        # sig = Schnorr.sign_with_nonce(privkey, priv_nonce, sighash)
        # assert sig == signature
      end
    end
  end
end
