# Fixture Contracts

These JSON files define exact live `idump` expectations for Structor.

They are generated from the current blessed baseline and then checked verbatim after normalizing away volatile IDs, addresses, and timing fields.

Each contract names a fixture binary and one or more synthesis cases. A case specifies:

- `synth`: what to synthesize
- `dump_functions`: which functions to dump from `idump`
- `golden_result`: the exact normalized synthesized result expected
- `golden_pseudocode`: the exact dumped pseudocode snapshot expected

Optional `expect` keys still exist for targeted extra checks, but the default workflow is golden-result comparison.

Supported `synth` forms:

- function variable by index
```json
{
  "kind": "function",
  "target": "process_simple",
  "var_idx": 0
}
```

- function variable by name
```json
{
  "kind": "function",
  "target": "process_simple",
  "var_name": "ptr"
}
```

- global by symbol name
```json
{
  "kind": "global",
  "target": "g_device"
}
```

Useful optional `expect` keys:

- `success`
- `z3_status`
- `used_fallback`
- `structure_size`
- `non_padding_field_count`
- `exact_fields`
- `contains_fields`
- `forbid_fields`
- `vtable_slot_count`
- `exact_vtable_slots`
- `propagated_to_contains`
- `pseudocode_contains`
- `pseudocode_forbid`

`exact_fields` compares non-padding fields in order unless `ignore_padding` is set to `false`.

## Workflow

1. Update the case manifest in `integration_tests/generate_fixture_contracts.py`.
2. Regenerate the contract JSON for the fixture from live `idump` output.
3. Review the new golden result and pseudocode diff carefully.
4. Commit the updated contract with the code change that intentionally changed recovery.

## Commands

Regenerate one fixture contract:

```bash
python3 integration_tests/generate_fixture_contracts.py \
  --repo-root /path/to/structor \
  --plugin /path/to/structor/build/structor.dylib \
  --fixture test_simple_struct
```

Regenerate all fixture contracts:

```bash
python3 integration_tests/generate_fixture_contracts.py \
  --repo-root /path/to/structor \
  --plugin /path/to/structor/build/structor.dylib
```

Run all contracts:

```bash
python3 integration_tests/check_fixture_contracts.py \
  --repo-root /path/to/structor \
  --plugin /path/to/structor/build/structor.dylib
```

Run the full live integrity suite, including exact contracts plus the dedicated type-fixer/global regression scripts:

```bash
python3 integration_tests/check_full_integrity_suite.py \
  --repo-root /path/to/structor \
  --plugin /path/to/structor/build/structor.dylib
```
