## Summary

<!-- What does this PR do? One or two sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New detector
- [ ] New resolver
- [ ] New collector / integration
- [ ] Dashboard improvement
- [ ] Documentation update
- [ ] Refactor / cleanup
- [ ] Other

## How to test

<!-- Steps to verify this works end-to-end, ideally using the demo simulator. -->

1. `docker compose up --build -d`
2. `docker compose exec sentinel-engine python -m scripts.demo_simulator`
3. Observe ...

## Checklist

- [ ] Tested end-to-end with the demo simulator
- [ ] No secrets or credentials committed
- [ ] CONTRIBUTING.md followed (new detectors/resolvers registered correctly)
- [ ] README updated if new configuration or behaviour was introduced
