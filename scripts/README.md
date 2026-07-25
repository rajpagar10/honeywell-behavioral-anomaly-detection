# Operational Scripts

The installed `badp` command is the supported operational interface. Milestone
3 adds real dataset generation through:

```text
badp --config config/development.yaml generate-data \
  --generator-config config/generator/demo.yaml \
  --output data/samples/honeywell_demo
```

Model training, evaluation, and streaming scripts will be added with their
owning milestones rather than as nonfunctional stubs.
