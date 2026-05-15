-- Lua debt fixture for M-015 - complexity, nesting, long method, TODOs

local function extremely_complex_function(a, b, c, d, e, f, g)
    -- TODO: refactor this monster
    local result = 0
    if a > 0 then
        if b > 0 then
            if c > 0 then
                if d > 0 then
                    if e > 0 then
                        if f > 0 then
                            result = a + b + c + d + e + f + g
                        elseif f < 0 then
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
    if a == 1 then result = result + 1
    elseif a == 2 then result = result + 2
    elseif a == 3 then result = result + 3
    elseif a == 4 then result = result + 4
    elseif a == 5 then result = result + 5
    elseif a == 6 then result = result + 6
    elseif a == 7 then result = result + 7
    elseif a == 8 then result = result + 8
    elseif a == 9 then result = result + 9
    elseif a == 10 then result = result + 10
    end
    return result
end

local function another_long_method()
    -- FIXME: this should be split
    local x = 0
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
    return x
end

return { extremely_complex_function, another_long_method }
