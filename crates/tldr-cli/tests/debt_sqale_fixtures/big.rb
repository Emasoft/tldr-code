# Ruby debt fixture for M-015 - complexity, nesting, long method, TODOs

def extremely_complex_function(a, b, c, d, e, f, g)
  # TODO: refactor this monster
  result = 0
  if a > 0
    if b > 0
      if c > 0
        if d > 0
          if e > 0
            if f > 0
              result = a + b + c + d + e + f + g
            elsif f < 0
              result = a - b
            else
              result = 0
            end
          else
            result = -1
          end
        else
          result = -2
        end
      else
        result = -3
      end
    else
      result = -4
    end
  else
    result = -5
  end
  case a
  when 1 then result += 1
  when 2 then result += 2
  when 3 then result += 3
  when 4 then result += 4
  when 5 then result += 5
  when 6 then result += 6
  when 7 then result += 7
  when 8 then result += 8
  when 9 then result += 9
  when 10 then result += 10
  end
  result
end

def another_long_method
  # FIXME: this should be split
  x = 0
  x += 1
  x += 2
  x += 3
  x += 4
  x += 5
  x += 6
  x += 7
  x += 8
  x += 9
  x += 10
  x += 11
  x += 12
  x += 13
  x += 14
  x += 15
  x += 16
  x += 17
  x += 18
  x += 19
  x += 20
  x += 21
  x += 22
  x += 23
  x += 24
  x += 25
  x += 26
  x += 27
  x += 28
  x += 29
  x += 30
  x += 31
  x += 32
  x += 33
  x += 34
  x += 35
  x += 36
  x += 37
  x += 38
  x += 39
  x += 40
  x += 41
  x += 42
  x += 43
  x += 44
  x += 45
  x += 46
  x += 47
  x += 48
  x += 49
  x += 50
  x += 51
  x += 52
  x += 53
  x += 54
  x
end
