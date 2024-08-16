import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

time_multiplier = {
    "s": 1_000_000,
    "ms": 1_000,
    "µs": 1,
}


def time_string(µs: int) -> str:
    # microsecond * 1,000,000 = 1 second
    if µs < 1_000:
        return f"{µs}µs"
    if µs < 1_000_000:
        return f"{µs/1_000}ms"
    s = µs / 1_000_000
    if s < 60:
        return f"{s:.2f}s"
    if s < 3600:
        return f"{int(s//60)}m{s % 60:.1f}s"
    return f"{int(s//3600)}h{int(s//60) % 60}m{s % 60:.1f}s"


def split_logs_into_queries(log_file: Path) -> list[str]:
    if not log_file.exists():
        return []
    full_log_contents = log_file.read_text()
    queries_log_contents = full_log_contents.split(
        "ipa_core::query::runner::oprf_ipa: new"
    )
    if len(queries_log_contents) < 2:
        return []
    return queries_log_contents[1:]


@dataclass
class Step:
    size: int
    method: str
    busy_time: float
    idle_time: float

    @property
    def total_time(self) -> float:
        return self.busy_time + self.idle_time

    def percent_busy_time(self, total_busy_time) -> float:
        return 100.0 * self.busy_time / total_busy_time

    def percent_idle_time(self, total_idle_time) -> float:
        return 100.0 * self.idle_time / total_idle_time

    def percent_total_time(self, total_time) -> float:
        return 100.0 * self.total_time / total_time


@dataclass
class Steps:
    steps: list[Step]
    helper: int

    @classmethod
    def build_from_logs(cls, helper: int, log_contents: str) -> "Steps":
        pattern = (
            r".*{sz=(\d+)}:([a-zA-Z_]+):.*close time\.busy=(\d+\.?\d*)(ms|µs|s) "
            r"time\.idle=(\d+\.?\d*)(ms|µs|s)"
        )
        matches = re.findall(pattern, log_contents)
        steps = [
            Step(
                size=int(re_match[0]),
                method=re_match[1],
                busy_time=float(re_match[2]) * time_multiplier[re_match[3]],
                idle_time=float(re_match[4]) * time_multiplier[re_match[5]],
            )
            for re_match in matches
        ]
        return cls(
            steps=steps,
            helper=helper,
        )

    @property
    def total_busy_time(self) -> float:
        return sum(step.busy_time for step in self.steps)

    @property
    def total_idle_time(self) -> float:
        return sum(step.idle_time for step in self.steps)

    @property
    def total_time(self) -> float:
        return sum(step.total_time for step in self.steps)

    @property
    def size(self) -> Optional[int]:
        if not self.steps:
            return None
        return self.steps[0].size

    def report_table(self) -> str:
        if len(self.steps) == 0:
            return f"Helper {self.helper}: No steps found."
        data = [
            (
                step.method,
                f"{step.percent_idle_time(self.total_idle_time):.2f}%",
                f"{step.percent_busy_time(self.total_busy_time):.2f}%",
                f"{step.percent_total_time(self.total_time):.2f}%",
            )
            for step in self.steps
        ]
        data.append(
            (
                "total",
                time_string(self.total_idle_time),
                time_string(self.total_busy_time),
                time_string(self.total_time),
            )
        )

        widths = [max(len(item) for item in column) for column in zip(*data)]

        header = (
            f"|{'step':<{widths[0]}}|{'% idle':<{widths[1]}}|"
            f"{'% busy':<{widths[2]}}|{'% total':<{widths[3]}}|\n"
            f"|{'---':<{widths[0]}}|{'---':<{widths[1]}}|"
            f"{'---':<{widths[2]}}|{'---':<{widths[3]}}|"
        )
        steps_report = "\n".join(
            f"|{d[0]:<{widths[0]}}|"
            f"{d[1]:<{widths[1]}}|"
            f"{d[2]:<{widths[2]}}|"
            f"{d[3]:<{widths[3]}}|"
            for d in data
        )
        return (
            f"Helper {self.helper} Summary - Query Size {self.size:_}\n"
            f"{header}\n{steps_report}\n"
        )


@dataclass
class Errors:
    helper: int
    size: int
    error_counter: Counter

    @classmethod
    def build_from_logs(cls, helper: int, log_contents: str, size: int) -> "Errors":
        error_counter = Counter()
        for log in log_contents.split("\n"):
            if "ERROR" in log:
                error_message = log.split(":")[-1].strip()
                error_counter[error_message] += 1
        return cls(helper=helper, error_counter=error_counter, size=size)

    def report_table(self) -> str:
        if len(self.error_counter) == 0:
            return f"Helper {self.helper} - Query Size {self.size:_}: No Errors"
        width = max(len(error_message) for error_message in self.error_counter.keys())
        header = f"|{'error_message':<{width}}|count  |\n|{'---':<{width}}|---    |"
        error_report = "\n".join(
            f"|{error_message:<{width}}|{count:<7}|"
            for (error_message, count) in sorted(
                self.error_counter.items(), key=lambda x: x[0].lower()
            )
        )
        return (
            f"Helper {self.helper} Error Summary - Query Size {self.size:_}"
            f"\n{header}\n{error_report}\n"
        )


def main():
    log_files = [Path(f"in-market-test/v2/logs/helper{i}.log") for i in [1, 2, 3]]
    for i, log_file in enumerate(log_files):
        for query in split_logs_into_queries(log_file):
            steps = Steps.build_from_logs(helper=i + 1, log_contents=query)
            print(steps.report_table())
            errors = Errors.build_from_logs(
                helper=i + 1, log_contents=query, size=steps.size
            )
            print(errors.report_table())
            print()


if __name__ == "__main__":
    main()
