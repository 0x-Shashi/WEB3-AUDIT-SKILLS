# Cantina - Audit Findings

## Overview

**Total Findings**: 2,932 (5.80% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 321 | 543 | 1811 | 257 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Liquidation | 2 |
| Code Quality | 1 |
| Pause | 1 |
| Front-Running | 1 |

---

## Notable Findings

### 1. Incorrect opcode offset used for Branch Less instruction 

**Protocol**: OpenVM | **Impact**: HIGH

## Issue Description

## Context
(No context files were provided by the reviewer)

## Description
The `Rv32BranchLessThan256Chip` uses the wrong opcode offset when creating its internal `BranchLessThanCoreChip`. It uses `Rv32LessThan256Opcode::CLASS_OFFSET` instead of `Rv32BranchLessThan256Opcode::CLASS_OFFSET`. This will cause the branch less than instruction to be decoded and executed incorrectly. This affects all 256-bit branch-less-than operations (`BLT`, `BGE`, `BLTU`, `BGEU`), leading to incorrect branch condition evaluation.

## Proof of Concept
This part of the code from the `Int256::b...

---

### 2. Missing constraints in LOADWand STOREW 

**Protocol**: OpenVM | **Impact**: HIGH

## Context
(No context files were provided by the reviewer)

## Summary
In the recursion VM, the LOADW and STOREW instructions are missing constraints to link the read value to the written value. As a result, a malicious prover can write any value.

## Finding Description
The `NativeLoadStoreCoreAir::eval` function does not constrain anything except the values of the instruction flags given the opcode. In particular, there is no constraint between `cols.data_read` and `cols.data_write`. Also, the `NativeLoadStoreAdapterAir` does not enforce any constraint between `ctx.reads.1` and `ctx.writes`...

---

### 3. Incorrect upper bound check in wExp(x) can produce an overﬂowed result 

**Protocol**: Morpho | **Impact**: HIGH

## Context: MathLib.sol#L26

## Description
Upper-bound used in `wExp(x)` is not restrict enough:

```solidity
// Revert if x > ln(2^256-1) ~ 177.
require(x <= 177.44567822334599921 ether, ErrorsLib.WEXP_OVERFLOW);
```

As this function accepts `x` in the 18 decimal format and is supposed to return an 18 decimal number, the upper bound should be calculated similarly to Remco's `FixedPointMathLib`:

\[
10^{18} e^{x + \epsilon} \leq 10^{18} e^{x + \epsilon} 10^{18} \leq 2^{256} - 1
\]

So:

\[
x \leq \frac{10^{18} \ln(2^{256} - 1)}{10^{18}} - \epsilon
\]

Here \(\epsilon = \text{LN2\_INT}\).

An...

---

### 4. Blast is conﬁgured in the implementation contract constructor, not the proxy 

**Protocol**: Particle | **Impact**: HIGH

## Context
(No context files were provided by the reviewer)

## Description
The `ParticlePositionManager` contract has a line in the constructor (which is currently commented out to deploy on mainnet, but will be uncommented when it is deployed on Blast) intended to configure the yield and gas modes of the contract as claimable.

## ParticlePositionManager
```solidity
// ...
constructor() payable {
    _disableInitializers();
    // Blast.configure();
}
// ...
```

## Blast (library)
```solidity
// ...
function configure() external {
    IBlast(BLAST).configureClaimableYield();
    IBlast(BLAS...

---

### 5. TroveManager's RewardIntegral update logic is ﬂawed, users may be receiving less rewards than expected 

**Protocol**: Bima | **Impact**: HIGH

## TroveManager Reward Calculation Issue

## Context
(No context files were provided by the reviewer)

## Description
TroveManager rewards users with the Bima token based on the amount of debt they have. Rewards are updated by the `_updateIntegrals` function. The updating mechanism is similar to Sushiswap Masterchef, maintaining the amount of reward tokens per debt token in `rewardIntegral` (global) and `rewardIntegralFor[account]` (per account). The key difference is that debt is always accruing interest.

The issue is that the global reward rate `rewardIntegral` always uses the total debt as...

---

### 6. Poseidon2 verify_batch: start_top_levelis not constrained to happen only once during top level 

**Protocol**: OpenVM | **Impact**: HIGH

## Context

**File:** `air.rs#L476-L480`

## Description

The variable `start_top_level` is supposed to be true only once during top-level processing, specifically during the first row incorporation. However, the current implementation in the code does not enforce these constraints. Setting `start_top_level` in the middle of the top-level process can influence the value expected as a result of the `row_hash`:

```rust
let row_hash = from_fn(|i| {
    (start_top_level * left_output[i])
    + ((AB::Expr::ONE - start_top_level) * right_input[i])
});
```

This means that a malicious prover could s...

---

### 7. P256 guest uses invalid parameters 

**Protocol**: OpenVM | **Impact**: HIGH

## Context
`p256.rs#L60-L77`

## Description
The `GENERATOR` and `NEG_GENERATOR` constants for the P256 curve are not valid. As we can see in the following snippet, the parameters are encoded in big endian to match the generator parameters of the curve (see neuromancer.sk reference on secp256r1).

```rust
impl CyclicGroup for P256Point {
    const GENERATOR: Self = P256Point {
        x: P256Coord::from_const_bytes(hex!(
            // @POC: higher bits lower bits
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            // ...
        ));
    }
}
```

When we ...

---

### 8. Additional airs can be added to proof in recursion program 

**Protocol**: OpenVM | **Impact**: HIGH

## Context
`mod.rs#L281-L291`

## Description
When using dynamic configuration (`builder.flags.static_only == false`), an arbitrary number of proofs per_air can be provided (independently of the number of chips used during key generation). However, as the chips used during keygen are matched to these proofs by index, the access made to match the additional chip is made out-of-bounds:

### Code Snippet
```rust
// Build domains
let domains = builder.array(num_airs);
let quotient_domains = builder.array(num_airs);
let trace_points_per_domain = builder.array(num_airs);
let quotient_chunk_domains =...

---

### 9. Invalid Divrem chip row can send arbitrary bitwise range check with multiplicity -1 (equiv- alent to receive) 

**Protocol**: OpenVM | **Impact**: HIGH

## Context: core.rs#L282

## Description
The Divrem chip uses a bitwise range check to ensure that two F numbers are valid 16-bit limbs, with multiplicity defined as `is_valid - special_case`. Unfortunately, there is no constraint requiring `special_case` to be true only when `is_valid` is true. This oversight means the prover can insert a row that emits the `send_range` over the bitwise bus with a multiplicity of -1 (which is equivalent to "receiving" the range check).

### Relevant Code
```rust
// divrem/core.rs#L280-L282.
self.bitwise_lookup_bus
    .send_range(cols.lt_diff - AB::Expr::ONE,...

---

### 10. Jalr imm_signis unconstrained 

**Protocol**: OpenVM | **Impact**: HIGH

## Context: core.rs#L143-L145

## Description
In the Jalr opcode circuit, there is a flag to sign extend the 12-bit immediate passed to the instruction:

```rust
// jalr/core.rs#L144
//@audit additional term because of sign extending the immediate
let imm_extend_limb = imm_sign * AB::F::from_canonical_u32((1 << 16) - 1);
let carry = (rs1_limbs_23 + imm_extend_limb + carry - to_pc_limbs[1]) * inv;
builder.when(is_valid).assert_bool(carry);
```

Unfortunately, `imm_sign` is not constrained, thus the prover can decide to make `imm_extend_limb` zero or `((1 << 16) - 1)` and change program flow.

#...

---

### 11. Heap pointer can overﬂow 

**Protocol**: OpenVM | **Impact**: HIGH

## Memory Allocator Vulnerability

## Context
`memory.rs#L97`

## Summary & Finding Description
In the bump allocator, the heap pointer is computed as `heap_pos += bytes` after an allocation. Below this line, there is a check that the allocator can't go into the SYSTEM area, but since the addition is not checked for overflow, we can return a new pointer that points to any heap cell. Because of the SYSTEM check, the allocation jump has to be at least `k = u32::MAX - 0x0c00_0000` to cause the bug.

## Impact Explanation
The exploit can be crafted so that it allows the attacker to manipulate spec...

---

### 12. Poseidon2 verify batch: top-level rows can come right after an inside_row but before in- side_rowend 

**Protocol**: OpenVM | **Impact**: HIGH

## Context

Refer to `air.rs#L155-L172` for details.

## Description

When using an `incorporate_row` type during a verify batch instruction, execution of the actual ingestion of the row is "deferred" using the internal bus:

```rust
self.internal_bus.interact(
    builder,
    true,
    incorporate_row,
    timestamp_after_initial_reads.clone(),
    end_timestamp - AB::F::TWO,
    opened_base_pointer,
    opened_element_size_inv,
    initial_opened_index,
    final_opened_index,
    row_hash,
);
```

This means that the actual row hashing is constrained by a series of `inside_row` rows, which...

---

### 13. Poseidon2 verify batch: Incorporate sibling row can also be ﬁrst of top level phase, skipping row incorporation 

**Protocol**: OpenVM | **Impact**: HIGH

## Context: air.rs#L109-L112

## Description
The verify batch instruction should always start with a row that is of type `incorporate_row` and `start_top_level`, as hinted by the constraint:

- **poseidon2/air.rs#L109-L112:**
  
  ```rust
  let end = end_inside_row + end_top_level + simple + (AB::Expr::ONE - enabled.clone());
  builder
      .when(end.clone())
      .when(next.incorporate_row)
      .assert_one(next.start_top_level);
  ```

However, only the following implication is constrained by these conditions:
If the first row is an `incorporate_row`, then `start_top_level` must be true. ...

---

### 14. Poseidon2 verify_batchopcode can send to execution bus for invalid row 

**Protocol**: OpenVM | **Impact**: HIGH

## Context: air.rs#L612-L628

## Description

Most chips' AIRs define an `enabled` or `is_valid` boolean variable based on which interactions are emitted. In the case of the Poseidon2 AIR, multiple opcodes (`VERIFY_BATCH`, `PERM_POS2`, `COMP_POS2`) are handled, and `enabled` is defined as below:

- **poseidon2/air.rs#L102-L103:**

    ```rust
    let enabled = incorporate_row + incorporate_sibling + inside_row + simple;
    builder.assert_bool(enabled.clone());
    ```

The execution interaction of the `VERIFY_BATCH` opcode is emitted when `end_top_level` is `1`, but `end_top_level` is not con...

---

### 15. Unconstrained sign bit in Rv32LoadStoreAdapter 

**Protocol**: OpenVM | **Impact**: HIGH

## Load and Store Operation Vulnerability

## Context
**File:** `loadstore.rs#L230`

## Summary
In a load or store operation, the instruction's immediate value is added to the value of `RS1`. This allows the prover to flip the higher limb of the immediate value (which can be either `0x0` or `0xffff`). As a result, a malicious prover can access a different memory cell.

## Finding Description
The `Rv32LoadStoreAdapterChip` is responsible for managing interactions with memory during load or store operations. It adds the instruction's immediate value to the value of `RS1`, using 16-bit limb addit...

---


## Statistics

- Total findings from Cantina: 2,932
- Last updated: 2026-01-29

