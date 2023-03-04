defmodule ExfactoTest do
  use ExUnit.Case
  doctest Exfacto

  test "greets the world" do
    assert Exfacto.hello() == :world
  end
end
