"""Reproducibility controls shared by generators and model training."""

import os
import random
from dataclasses import dataclass
from importlib.util import find_spec


@dataclass(frozen=True, slots=True)
class SeedReport:
    """Record which installed numerical runtimes received a seed."""

    seed: int
    python_seeded: bool
    numpy_seeded: bool
    torch_seeded: bool
    deterministic_torch: bool


def set_global_seed(seed: int, *, deterministic_torch: bool = True) -> SeedReport:
    """Seed installed random runtimes without requiring optional ML dependencies."""

    if seed < 0:
        raise ValueError("seed must be non-negative")

    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    numpy_seeded = _seed_numpy(seed)
    torch_seeded = _seed_torch(seed, deterministic=deterministic_torch)
    return SeedReport(
        seed=seed,
        python_seeded=True,
        numpy_seeded=numpy_seeded,
        torch_seeded=torch_seeded,
        deterministic_torch=deterministic_torch and torch_seeded,
    )


def _seed_numpy(seed: int) -> bool:
    """Seed NumPy when the optional ML dependency is installed."""

    if find_spec("numpy") is None:
        return False
    import numpy as np

    np.random.seed(seed)
    return True


def _seed_torch(seed: int, *, deterministic: bool) -> bool:
    """Seed PyTorch and enable deterministic algorithms when installed."""

    if find_spec("torch") is None:
        return False
    import torch

    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    if deterministic:
        torch.use_deterministic_algorithms(True, warn_only=True)
        torch.backends.cudnn.benchmark = False
    return True
