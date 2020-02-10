import io

from age.format import load_header

GOOGLE_DOC_TEST_FILE = b"""age-encryption.org/v1
-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
-> scrypt GixTkc7+InSPLzPNGU6cFw 18
kC4zjzi7LRutdBfOlGHCgox8SXgfYxRYhWM1qPs0ca8
-> ssh-rsa SkdmSg
SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
j8mC2GaqR0gUcpGwIk6QZMxOdxNSOO7jhIC32nt1w2Ep1ftk9wV1sFyQo+YYrzOx
yCDdUwQAu9oM3Ez6AWkmFyG6AvKIny8I4xgJcBt1DEYZcD5PIAt51nRJQcs2/ANP
+Y1rKeTsskMHnlRpOnMlXqoeN6A3xS+EWxFTyg1GREQeaVztuhaL6DVBB22sLskw
XBHq/XlkLWkqoLrQtNOPvLoDO80TKUORVsP1y7OyUPHqUumxj9Mn/QtsZjNCPyKN
ds7P2OLD/Jxq1o1ckzG3uzv8Vb6sqYUPmRvlXyD7/s/FURA1GetBiQEdRM34xbrB
-> ssh-ed25519 Xyg06A rH24zuz7XHFc1lRyQmMrekpLrcKrJupohEh/YjvQCxs
Bbtnl6veSZhZmG7uXGQUX0hJbrC8mxDkL3zW06tqlWY
--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
[BINARY ENCRYPTED PAYLOAD]"""


def test_loading():
    stream = io.BytesIO(GOOGLE_DOC_TEST_FILE)
    header, _ = load_header(stream)
    assert len(header.recipients) == 5
    assert header.recipients[0].type == "X25519"
    assert header.recipients[1].type == "X25519"
    assert header.recipients[2].type == "scrypt"
