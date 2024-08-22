import argparse
import re
from collections import Counter
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Optional

time_multiplier = {
    "s": 1_000_000,
    "ms": 1_000,
    "µs": 1,
}


def time_string(µs: float) -> str:
    # microsecond * 1,000,000 = 1 second
    if µs < 1_000:
        return f"{µs:.1f}µs"
    if µs < 1_000_000:
        return f"{µs/1_000:.1f}ms"
    s = µs / 1_000_000
    if s < 60:
        return f"{s:.1f}s"
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


def table_formatter(data: list[tuple[str, ...]], title: str) -> str:
    widths = [
        max(len(item) for item in column)
        for column in zip_longest(*data, fillvalue="N/A")
    ]
    table = "\n".join(
        "|"
        + "|".join(
            f"{d:<{width}}" for (d, width) in zip_longest(row, widths, fillvalue="N/A")
        )
        + "|"
        for row in data
    )
    return f"## {title}\n\n{table}"


def tsv_formatter(data: list[tuple[str, ...]], title: str) -> str:
    rows = ["\t".join(col) for col in data]
    return f"{title}\n" + "\n".join(row for row in rows)


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

    def percent_busy_time_str(self, total_busy_time) -> str:
        if total_busy_time is None:
            return "N/A"
        return f"{self.percent_busy_time(total_busy_time):.2f}%"

    def percent_idle_time_str(self, total_idle_time) -> str:
        if total_idle_time is None:
            return "N/A"
        return f"{self.percent_idle_time(total_idle_time):.2f}%"

    def percent_total_time_str(self, total_time) -> str:
        if total_time is None:
            return "N/A"
        return f"{self.percent_total_time(total_time):.2f}%"


@dataclass
class Steps:
    steps: list[Step]
    helper: int

    @classmethod
    def build_from_logs(cls, helper: int, log_contents: str) -> "Steps":
        pattern = (
            r".*{sz=(\d+)}:([a-zA-Z_ ]+):.*close time\.busy=(\d+\.?\d*)(ms|µs|s) "
            r"time\.idle=(\d+\.?\d*)(ms|µs|s)"
        )
        matches = re.findall(pattern, log_contents)
        steps = [
            Step(
                size=int(re_match[0]),
                method=re_match[1].strip(),
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
    def total_step(self) -> Optional[Step]:
        if not self.steps or self.steps[-1].method != "ipa_core":
            return None
        return self.steps[-1]

    @property
    def total_busy_time(self) -> Optional[float]:
        if self.total_step is not None:
            return self.total_step.busy_time
        return None

    @property
    def total_idle_time(self) -> Optional[float]:
        if self.total_step is not None:
            return self.total_step.idle_time
        return None

    @property
    def total_time(self) -> Optional[float]:
        if self.total_step is not None:
            return self.total_step.total_time
        return None

    @property
    def size(self) -> Optional[int]:
        if not self.steps:
            return None
        return self.steps[0].size

    @property
    def report_title(self) -> str:
        return f"Helper {self.helper} Summary - Query Size {self.size:_}"

    def report_matrix(self) -> list[tuple[str, ...]]:
        if len(self.steps) == 0:
            return f"Helper {self.helper}: No steps found."

        data = [
            ("step", "idle", "% idle", "busy", "% busy", "total", "% total"),
            ("---", "---", "---", "---", "---", "---", "---"),
        ]

        data.extend(
            [
                (
                    step.method,
                    f"{time_string(step.idle_time)}",
                    step.percent_idle_time_str(self.total_idle_time),
                    f"{time_string(step.busy_time)}",
                    step.percent_busy_time_str(self.total_busy_time),
                    f"{time_string(step.total_time)}",
                    step.percent_total_time_str(self.total_time),
                )
                for step in self.steps
            ]
        )
        data.append(("---", "---", "---", "---", "---", "---", "---"))
        if self.total_step is None:
            data.append(("total", "N/A", "", "N/A", "", "N/A", ""))
        else:
            data.append(
                (
                    "total",
                    time_string(self.total_idle_time),
                    "",
                    time_string(self.total_busy_time),
                    "",
                    time_string(self.total_time),
                    "",
                )
            )
        return data


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

    @property
    def report_title(self) -> str:
        if len(self.error_counter) == 0:
            return f"Helper {self.helper} - Query Size {self.size:_}: No Errors"
        return f"Helper {self.helper} Error Summary - Query Size {self.size:_}"

    def report_matrix(self) -> list[tuple[str, ...]]:
        data = [
            ("error_message", "count"),
            ("---", "---"),
        ]
        data.extend(
            [
                (error_message, str(count))
                for (error_message, count) in sorted(
                    self.error_counter.items(), key=lambda x: x[0].lower()
                )
            ]
        )
        return data


def main():
    parser = argparse.ArgumentParser(description="Parse log files from IPA helpers")
    parser.add_argument(
        "--tab-separated",
        action="store_true",
        help="Print as tab separated text. (Default prints as a table)",
    )
    args = parser.parse_args()

    log_files = [Path(f"in-market-test/v2/logs/helper{i}.log") for i in [1, 2, 3]]
    for i, log_file in enumerate(log_files):
        for query in split_logs_into_queries(log_file):
            steps = Steps.build_from_logs(helper=i + 1, log_contents=query)
            errors = Errors.build_from_logs(
                helper=i + 1, log_contents=query, size=steps.size
            )

            if args.tab_separated:
                print(tsv_formatter(steps.report_matrix(), steps.report_title))
                print()
                print(tsv_formatter(errors.report_matrix(), errors.report_title))
                print()
            else:
                print(table_formatter(steps.report_matrix(), steps.report_title))
                print()
                print(table_formatter(errors.report_matrix(), errors.report_title))
                print()


if __name__ == "__main__":
    main()
