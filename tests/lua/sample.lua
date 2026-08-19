local secret = "flag{lua-preprocess-test}"
local function mix(a, b)
  local t = {a=a, b=b, secret=secret}
  return (a * 7 + b) % 256, t.secret
end
local x, s = mix(6, 9)
print(x, s)
return x
