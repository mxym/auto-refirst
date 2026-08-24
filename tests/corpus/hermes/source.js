"use strict";

const marker = "AUTO_REFIRST_HERMES_FIXTURE";

function greet(name) {
  return marker + ":hello:" + name;
}

function score(limit) {
  let total = 0;
  for (let index = 0; index < limit; index += 1) {
    total += (index * 3) ^ 0x2a;
  }
  return total;
}

function choose(name, limit) {
  return score(limit) > 100 ? greet(name) : marker + ":small";
}

globalThis.__autoRefirstHermesFixture = choose("epoch", 9);
