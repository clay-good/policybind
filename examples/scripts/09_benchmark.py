#!/usr/bin/env python3
"""
PolicyBind Performance Benchmark Script

This script measures the performance of PolicyBind's enforcement pipeline
under various conditions. It provides latency statistics and throughput
measurements for performance tuning.

Usage:
    python 09_benchmark.py [--requests N] [--rules N] [--warmup N]

Example:
    python 09_benchmark.py --requests 10000 --rules 50 --warmup 100
"""

import argparse
import gc
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any

# Add parent directory to path for imports
sys.path.insert(0, str(__file__).rsplit("/", 3)[0])

from policybind.engine.matcher import PolicyMatcher
from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""

    name: str
    requests: int
    duration_seconds: float
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def throughput(self) -> float:
        """Requests per second."""
        if self.duration_seconds == 0:
            return 0.0
        return self.requests / self.duration_seconds

    @property
    def avg_latency_ms(self) -> float:
        """Average latency in milliseconds."""
        if not self.latencies_ms:
            return 0.0
        return statistics.mean(self.latencies_ms)

    @property
    def p50_latency_ms(self) -> float:
        """50th percentile latency."""
        if not self.latencies_ms:
            return 0.0
        return statistics.median(self.latencies_ms)

    @property
    def p95_latency_ms(self) -> float:
        """95th percentile latency."""
        if not self.latencies_ms:
            return 0.0
        return statistics.quantiles(self.latencies_ms, n=20)[18]

    @property
    def p99_latency_ms(self) -> float:
        """99th percentile latency."""
        if not self.latencies_ms:
            return 0.0
        return statistics.quantiles(self.latencies_ms, n=100)[98]

    @property
    def min_latency_ms(self) -> float:
        """Minimum latency."""
        if not self.latencies_ms:
            return 0.0
        return min(self.latencies_ms)

    @property
    def max_latency_ms(self) -> float:
        """Maximum latency."""
        if not self.latencies_ms:
            return 0.0
        return max(self.latencies_ms)

    def print_report(self) -> None:
        """Print a formatted report."""
        print(f"\n{'=' * 60}")
        print(f"Benchmark: {self.name}")
        print(f"{'=' * 60}")
        print(f"Requests:      {self.requests:,}")
        print(f"Duration:      {self.duration_seconds:.2f}s")
        print(f"Throughput:    {self.throughput:,.0f} req/s")
        print()
        print("Latency (ms):")
        print(f"  Min:         {self.min_latency_ms:.3f}")
        print(f"  Avg:         {self.avg_latency_ms:.3f}")
        print(f"  P50:         {self.p50_latency_ms:.3f}")
        print(f"  P95:         {self.p95_latency_ms:.3f}")
        print(f"  P99:         {self.p99_latency_ms:.3f}")
        print(f"  Max:         {self.max_latency_ms:.3f}")
        print(f"{'=' * 60}")


def create_policy_set(num_rules: int = 10) -> PolicySet:
    """
    Create a PolicySet with the specified number of rules.

    Args:
        num_rules: Number of rules to create.

    Returns:
        A PolicySet with test rules.
    """
    rules = []

    # Add some specific rules
    rules.append(PolicyRule(
        name="block-dangerous-model",
        description="Block dangerous model usage",
        match_conditions={
            "model": {"pattern": "dangerous-*"},
        },
        action="DENY",
        priority=1000,
    ))

    rules.append(PolicyRule(
        name="allow-engineering",
        description="Allow engineering department",
        match_conditions={
            "department": "engineering",
        },
        action="ALLOW",
        priority=500,
    ))

    # Add department-specific rules
    departments = ["sales", "marketing", "research", "support", "finance", "hr", "legal"]
    for i, dept in enumerate(departments):
        if len(rules) >= num_rules:
            break
        rules.append(PolicyRule(
            name=f"dept-{dept}-policy",
            description=f"Policy for {dept} department",
            match_conditions={
                "department": dept,
                "data_classification": {"not_contains": "restricted"},
            },
            action="ALLOW",
            priority=400 - i,
        ))

    # Add model-specific rules
    models = ["gpt-4", "gpt-3.5-turbo", "claude-3-opus", "claude-3-sonnet", "gemini-pro"]
    for i, model in enumerate(models):
        if len(rules) >= num_rules:
            break
        rules.append(PolicyRule(
            name=f"model-{model}-policy",
            description=f"Policy for {model}",
            match_conditions={
                "model": model,
            },
            action="ALLOW",
            priority=300 - i,
        ))

    # Add generic rules to reach target count
    while len(rules) < num_rules:
        idx = len(rules)
        rules.append(PolicyRule(
            name=f"generic-rule-{idx}",
            description=f"Generic rule {idx}",
            match_conditions={
                "and": [
                    {"provider": {"in": ["openai", "anthropic", "google"]}},
                    {"estimated_cost": {"lt": 100.0}},
                ],
            },
            action="ALLOW",
            priority=100 - (idx % 100),
        ))

    # Add default deny rule
    rules.append(PolicyRule(
        name="default-deny",
        description="Default deny rule",
        match_conditions={},
        action="DENY",
        priority=0,
    ))

    return PolicySet(
        name="benchmark-policy",
        version="1.0.0",
        rules=rules,
    )


def create_test_requests(count: int = 1000) -> list[AIRequest]:
    """
    Create test requests for benchmarking.

    Args:
        count: Number of requests to create.

    Returns:
        List of AIRequest objects.
    """
    requests = []

    providers = ["openai", "anthropic", "google", "azure"]
    models = ["gpt-4", "gpt-3.5-turbo", "claude-3-opus", "claude-3-sonnet", "gemini-pro"]
    departments = ["engineering", "sales", "marketing", "research", "support"]
    use_cases = ["customer-support", "code-review", "content-generation", "analysis"]

    for i in range(count):
        requests.append(AIRequest(
            provider=providers[i % len(providers)],
            model=models[i % len(models)],
            user_id=f"user-{i % 100}",
            department=departments[i % len(departments)],
            data_classification=["internal"] if i % 3 == 0 else [],
            intended_use_case=use_cases[i % len(use_cases)],
            estimated_tokens=(i % 1000) + 100,
            estimated_cost=((i % 100) / 10.0) + 0.01,
            source_application="benchmark",
        ))

    return requests


def benchmark_matcher(
    policy_set: PolicySet,
    requests: list[AIRequest],
    warmup: int = 100,
) -> BenchmarkResult:
    """
    Benchmark the PolicyMatcher directly.

    Args:
        policy_set: The PolicySet to match against.
        requests: List of requests to process.
        warmup: Number of warmup requests.

    Returns:
        BenchmarkResult with latency data.
    """
    matcher = PolicyMatcher()
    matcher.precompile(policy_set)

    # Warmup
    for i in range(min(warmup, len(requests))):
        matcher.match(policy_set, requests[i])

    # Force garbage collection before benchmark
    gc.collect()

    # Benchmark
    latencies = []
    start_time = time.perf_counter()

    for request in requests:
        req_start = time.perf_counter()
        matcher.match(policy_set, request)
        req_end = time.perf_counter()
        latencies.append((req_end - req_start) * 1000)  # Convert to ms

    end_time = time.perf_counter()

    return BenchmarkResult(
        name=f"PolicyMatcher ({len(policy_set.rules)} rules)",
        requests=len(requests),
        duration_seconds=end_time - start_time,
        latencies_ms=latencies,
    )


def benchmark_pipeline(
    policy_set: PolicySet,
    requests: list[AIRequest],
    warmup: int = 100,
) -> BenchmarkResult:
    """
    Benchmark the full EnforcementPipeline.

    Args:
        policy_set: The PolicySet to enforce.
        requests: List of requests to process.
        warmup: Number of warmup requests.

    Returns:
        BenchmarkResult with latency data.
    """
    config = PipelineConfig(
        enable_timing=True,
        enable_audit=False,  # Disable for pure performance test
        require_classification=False,
        rate_limit_enabled=False,
        cost_tracking_enabled=False,
    )

    pipeline = EnforcementPipeline(policy_set, config)

    # Warmup
    for i in range(min(warmup, len(requests))):
        pipeline.process(requests[i])

    # Force garbage collection before benchmark
    gc.collect()

    # Benchmark
    latencies = []
    start_time = time.perf_counter()

    for request in requests:
        req_start = time.perf_counter()
        pipeline.process(request)
        req_end = time.perf_counter()
        latencies.append((req_end - req_start) * 1000)

    end_time = time.perf_counter()

    return BenchmarkResult(
        name=f"EnforcementPipeline ({len(policy_set.rules)} rules)",
        requests=len(requests),
        duration_seconds=end_time - start_time,
        latencies_ms=latencies,
    )


def benchmark_with_varying_rules(
    requests: list[AIRequest],
    rule_counts: list[int],
    warmup: int = 100,
) -> list[BenchmarkResult]:
    """
    Benchmark with varying numbers of rules.

    Args:
        requests: List of requests to process.
        rule_counts: List of rule counts to test.
        warmup: Number of warmup requests.

    Returns:
        List of BenchmarkResult for each rule count.
    """
    results = []

    for num_rules in rule_counts:
        policy_set = create_policy_set(num_rules)
        result = benchmark_matcher(policy_set, requests, warmup)
        result.name = f"Matcher ({num_rules} rules)"
        results.append(result)

    return results


def main() -> None:
    """Run the benchmarks."""
    parser = argparse.ArgumentParser(
        description="PolicyBind Performance Benchmark",
    )
    parser.add_argument(
        "--requests", "-n",
        type=int,
        default=10000,
        help="Number of requests to process (default: 10000)",
    )
    parser.add_argument(
        "--rules", "-r",
        type=int,
        default=50,
        help="Number of policy rules (default: 50)",
    )
    parser.add_argument(
        "--warmup", "-w",
        type=int,
        default=100,
        help="Number of warmup requests (default: 100)",
    )
    parser.add_argument(
        "--vary-rules",
        action="store_true",
        help="Run benchmarks with varying rule counts",
    )

    args = parser.parse_args()

    print("PolicyBind Performance Benchmark")
    print("================================")
    print(f"Requests: {args.requests:,}")
    print(f"Rules: {args.rules}")
    print(f"Warmup: {args.warmup}")
    print()

    # Create test data
    print("Creating test data...")
    requests = create_test_requests(args.requests)
    policy_set = create_policy_set(args.rules)
    print(f"Created {len(requests):,} requests and {len(policy_set.rules)} rules")

    # Run benchmarks
    print("\nRunning benchmarks...")

    # Benchmark matcher only
    matcher_result = benchmark_matcher(policy_set, requests, args.warmup)
    matcher_result.print_report()

    # Benchmark full pipeline
    pipeline_result = benchmark_pipeline(policy_set, requests, args.warmup)
    pipeline_result.print_report()

    # Vary rule counts if requested
    if args.vary_rules:
        print("\nRunning benchmarks with varying rule counts...")
        rule_counts = [10, 25, 50, 100, 200, 500]
        results = benchmark_with_varying_rules(requests, rule_counts, args.warmup)

        print("\nRule Count Comparison:")
        print("-" * 60)
        print(f"{'Rules':<10} {'Throughput (req/s)':<20} {'Avg Latency (ms)':<20}")
        print("-" * 60)
        for result in results:
            rules = result.name.split("(")[1].split()[0]
            print(f"{rules:<10} {result.throughput:<20,.0f} {result.avg_latency_ms:<20.3f}")
        print("-" * 60)

    # Summary
    print("\nPerformance Summary:")
    print("-" * 40)
    print(f"Matcher throughput:  {matcher_result.throughput:,.0f} req/s")
    print(f"Pipeline throughput: {pipeline_result.throughput:,.0f} req/s")
    print(f"Matcher P99 latency: {matcher_result.p99_latency_ms:.3f} ms")
    print(f"Pipeline P99 latency:{pipeline_result.p99_latency_ms:.3f} ms")

    # Check performance targets
    print("\nPerformance Targets:")
    target_latency_ms = 1.0  # Sub-millisecond target for matcher
    if matcher_result.p99_latency_ms < target_latency_ms:
        print(f"  [PASS] Matcher P99 < {target_latency_ms}ms")
    else:
        print(f"  [FAIL] Matcher P99 ({matcher_result.p99_latency_ms:.3f}ms) >= {target_latency_ms}ms")

    target_throughput = 10000  # 10k req/s target
    if matcher_result.throughput >= target_throughput:
        print(f"  [PASS] Matcher throughput >= {target_throughput:,} req/s")
    else:
        print(f"  [FAIL] Matcher throughput ({matcher_result.throughput:,.0f}) < {target_throughput:,} req/s")


if __name__ == "__main__":
    main()
