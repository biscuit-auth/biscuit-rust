# `3.0.0` (Unreleased)

- Fix rendering of set terms (#140) (Clément Delafargue)
- handle expression execution failure (#135) (Geoffroy Couprie)
- support for authorizer snapshots (#127, #133, #137) (Geoffroy Couprie, Clément Delafargue)
- Add support for != in datalog (#128) (Clément Delafargue)
- Improved `Authorizer::print_world()` (#126, #129) (Geoffroy Couprie)

# `3.0.0-alpha4`

- Support for bitwise operators on ints (#122) (Nathan Walsh)
- Fix operators precedence (#121) (Clément Delafargue)
- Fix public key display in `UnverifiedBiscuit` (#119) (Clément Delafargue)
- Add `Display` implementation for `Biscuit` (Bastien Vigneron)

# `3.0.0-alpha3`

- Support for `check all` (#107) (Geoffroy Couprie)
- Add `Debug` implementation for third-party requests (#116) (Pierre Tondereau)
- Add the current block to the default rule scope (#115) (Clément Delafargue, Geffroy Couprie)
- Macro overhaul (#109) (Till Höppner)
- Support for using UUIDs as terms (#110) (Till Höppner)
- Make the `Convert` trait public (#106) (Akanoa)

# `3.0.0-alpha2`

- Fix clippy warnings (#82) (Matthias Vogelgesang)
- Remove panics from parser (#102) (Pierre Tondereau)
- Use rule scopes in authorizer query (#100) (Clément Delafargue)
- API updates (#98, #99) (Geoffroy Couprie, Clément Delafargue)
- 3rd party requests API updates (#96) (Geoffroy Couprie)

# `3.0.0-alpha1`

- Third-party blocks (#79, #92, #93, #94) (Geoffroy Couprie, Clément Delafargue)
- API cleanup (#86, #88, #89) (Geoffroy Couprie, Clément Delafargue)
- Improved macro errors (#77) (Clément Delafargue)


# `2.2.0`

- Datalog macros (#76) (Clément Delafargue)
- Add `Authorizer::dump_code` (Clément Delafargue)
- Parameter interpolation (#69, #71) (Clément Delafargue)
- Fix deprecation warnings (#73) (Pierre Tondereau)
- Remove symbols leftovers (#68) (Clément Delafargue)
- Biscuit sealing improvements (#64, #65) (Clément Delafargue)
