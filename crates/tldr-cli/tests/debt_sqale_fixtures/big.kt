// Kotlin debt fixture for M-015 — has complexity, deep nesting, long method, TODOs

fun extremelyComplexFunction(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int): Int {
    // TODO: refactor this monster
    var result = 0
    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                if (d > 0) {
                    if (e > 0) {
                        if (f > 0) {
                            result = a + b + c + d + e + f + g
                        } else if (f < 0) {
                            result = a - b
                        } else {
                            result = 0
                        }
                    } else {
                        result = -1
                    }
                } else {
                    result = -2
                }
            } else {
                result = -3
            }
        } else {
            result = -4
        }
    } else {
        result = -5
    }
    when (a) {
        1 -> result += 1
        2 -> result += 2
        3 -> result += 3
        4 -> result += 4
        5 -> result += 5
        6 -> result += 6
        7 -> result += 7
        8 -> result += 8
        9 -> result += 9
        10 -> result += 10
    }
    return result
}

fun anotherLongMethodWithManyLines(): Int {
    // FIXME: this should be split
    var x = 0
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
    return x
}
