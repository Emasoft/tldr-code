# Elixir debt fixture for M-015 - complexity, nesting, long method, TODOs

defmodule Bigger do
  def extremely_complex_function(a, b, c, d, e, f, g) do
    # TODO: refactor this monster
    result = cond do
      a > 0 ->
        cond do
          b > 0 ->
            cond do
              c > 0 ->
                cond do
                  d > 0 ->
                    cond do
                      e > 0 ->
                        cond do
                          f > 0 -> a + b + c + d + e + f + g
                          f < 0 -> a - b
                          true -> 0
                        end
                      true -> -1
                    end
                  true -> -2
                end
              true -> -3
            end
          true -> -4
        end
      true -> -5
    end
    case a do
      1 -> result + 1
      2 -> result + 2
      3 -> result + 3
      4 -> result + 4
      5 -> result + 5
      6 -> result + 6
      7 -> result + 7
      8 -> result + 8
      9 -> result + 9
      10 -> result + 10
      _ -> result
    end
  end

  def another_long_method() do
    # FIXME: this should be split
    x = 0
    x = x + 1
    x = x + 2
    x = x + 3
    x = x + 4
    x = x + 5
    x = x + 6
    x = x + 7
    x = x + 8
    x = x + 9
    x = x + 10
    x = x + 11
    x = x + 12
    x = x + 13
    x = x + 14
    x = x + 15
    x = x + 16
    x = x + 17
    x = x + 18
    x = x + 19
    x = x + 20
    x = x + 21
    x = x + 22
    x = x + 23
    x = x + 24
    x = x + 25
    x = x + 26
    x = x + 27
    x = x + 28
    x = x + 29
    x = x + 30
    x = x + 31
    x = x + 32
    x = x + 33
    x = x + 34
    x = x + 35
    x = x + 36
    x = x + 37
    x = x + 38
    x = x + 39
    x = x + 40
    x = x + 41
    x = x + 42
    x = x + 43
    x = x + 44
    x = x + 45
    x = x + 46
    x = x + 47
    x = x + 48
    x = x + 49
    x = x + 50
    x = x + 51
    x = x + 52
    x = x + 53
    x = x + 54
    x
  end
end
