# Contributing to Bitcoin Echo

Thank you for your interest in Bitcoin Echo!

## Current Status

Bitcoin Echo is in active development (Phase 9 of 12). We're not yet accepting large-scale external code contributions, but we **absolutely welcome**:

- **Code contributions** for bug fixes and test improvements
- **Technical review** of completed phases
- **Test case suggestions** from Bitcoin Core test vectors
- **Documentation improvements**
- **Bug reports** if you find consensus discrepancies

## How to Help

### Contribute Code

We welcome contributions! Here's how:

1. **Open an issue first** - Describe the bug or improvement you want to make
2. **Wait for feedback** - We'll discuss approach and feasibility
3. **Submit a PR** - Include tests and follow our code style
4. **Be patient** - We review carefully since this code is designed to ossify

**What makes a good contribution:**
- Bug fixes with test cases demonstrating the issue
- Additional test coverage from Bitcoin Core test vectors
- Performance improvements with benchmarks
- Documentation clarifications

**What we're NOT accepting:**
- New features beyond the roadmap
- Refactoring for style preferences
- External dependencies
- Breaking changes to the API

### Review the Code

The best contribution right now is careful review of consensus-critical code:
- Cryptographic primitives (`src/crypto/`)
- Script interpreter (`src/consensus/script.c`)
- Transaction validation (`src/consensus/tx_validate.c`)
- Block validation (`src/consensus/block_validate.c`)

### Report Issues

If you find a consensus bug or discrepancy with Bitcoin Core:
1. Create an issue with a minimal test case
2. Reference Bitcoin Core behavior
3. Include relevant BIP numbers if applicable
4. Provide steps to reproduce

## Code Style

- **Language:** Pure C11, zero dependencies
- **Style:** Follow existing code conventions
- **Tests:** Every PR must include tests
- **Comments:** Explain *why*, not *what*
- **Commits:** Atomic, conventional commit messages

## Testing

Before submitting a PR:

```bash
# Run all tests
make test

# Run specific test suites
make test/unit/test_<name>
./test/unit/test_<name>
```

All tests must pass. See `test/unit/README.md` for test framework documentation.

## Understanding Ossification

**"But what about bugs? Security issues? Platform changes?"**

Let's be clear about what ossification means for Bitcoin Echo:

### What Ossifies (Frozen Forever)

- **Consensus rules** - How blocks and transactions are validated
- **Feature set** - No new capabilities, no optimization rewrites
- **Architecture** - The design is complete
- **v2.0 will never exist** - No major revisions, no roadmap beyond v1.0

### What Doesn't Ossify (Responsible Maintenance)

- **Critical consensus bugs** - Fixed via minimal errata (v1.0.1, v1.0.2, etc.)
- **Security vulnerabilities** - Patched immediately with documented errata
- **Platform compatibility** - OS updates may require platform layer maintenance
- **Documentation & comments** - Clarifications, improvements, and expansions welcome
- **Test coverage** - Additional test vectors and edge case coverage encouraged
- **Educational materials** - Explanatory documentation, guides, and curriculum

### What About Protocol Changes?

If Bitcoin adopts quantum-resistant signatures or other soft forks:
- **We don't modify Bitcoin Echo v1.0** - It remains frozen
- **We create a successor** - Bitcoin Echo-Q, Bitcoin Echo-R, etc.
- **Each successor is also frozen** - Upon completion, it too becomes immutable
- **The chain of succession is linear** - Each validates all historical blocks

**Version numbers tell the story:**
- v1.0.0 → v1.0.47 (errata/patches) ✅ Acceptable
- v1.0.0 → v2.0.0 (new features) ❌ Will never happen
- Bitcoin Echo v1.0 → Bitcoin Echo-Q v1.0 (successor) ✅ How we evolve

This is **pragmatic ossification**: Strong intention to freeze consensus and features, with responsible governance for defects and succession.

See [Whitepaper §15: Cryptographic Succession](https://github.com/bitcoinecho/bitcoinecho-org/blob/main/bitcoin-echo-whitepaper.md#15-cryptographic-succession) and [Errata Policy](https://github.com/bitcoinecho/bitcoinecho-org/blob/main/ERRATA_POLICY.md) for complete details.

### Your Contribution Lives Forever

- Your code becomes a **permanent artifact**
- Your name in git history will be there for centuries
- No future maintainer can change or remove your work
- You're contributing to Bitcoin's permanent archaeological record

**This is your chance to be part of Bitcoin history.**

Every contributor during this development phase will be forever preserved in the codebase that scholars and historians will study for generations.

## After v1.0

Once Bitcoin Echo reaches v1.0 and is audited, the codebase freezes. No further feature contributions will be accepted—by design. The code becomes a permanent artifact, a snapshot of Bitcoin consensus frozen in time.

Bug fixes for critical consensus issues may be accepted post-freeze, but only after extensive review and only if they represent genuine Bitcoin protocol bugs.

## Funding

Bitcoin Echo is seeking funding for professional audit and development completion. See [bitcoinecho.org/funding](https://bitcoinecho.org/funding) for details.

## Questions?

- **Documentation:** [bitcoinecho.org](https://bitcoinecho.org)
- **Whitepaper:** [Technical Specification](https://bitcoinecho.org/docs/whitepaper)
- **Manifesto:** [Why Permanence Matters](https://bitcoinecho.org/docs/manifesto)
- **Email:** echo@bitcoinecho.org
- **X/Twitter:** [@bitcoinechoorg](https://twitter.com/bitcoinechoorg)

---

*Build once. Build right. Stop.*
