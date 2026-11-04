"""BenchStore: persistence, leaderboard scoring, and winner/fallback selection."""
from groundtrace.bench_store import BenchStore


def _store(tmp_path):
    return BenchStore(str(tmp_path / "bench.db"))


def _summary_row(model, *, halluc=False, sentences=3, error=None, latency=0.1):
    if error:
        return {"model": model, "error": error}
    return {"model": model, "latency_s": latency, "output": "a. b. c.",
            "ungrounded_tokens": ["9.9"] if halluc else [],
            "hallucination_flag": halluc, "sentence_count": sentences}


def test_run_persists_results(tmp_path):
    s = _store(tmp_path)
    rid = s.start_run("summary", input_label="sample_cve")
    s.save_result(rid, "summary", _summary_row("offline"))
    s.finish_run(rid, 1)

    runs = s.list_runs()
    assert len(runs) == 1 and runs[0]["model_count"] == 1
    rows = s.results_for_run(rid)
    assert rows[0]["model"] == "offline" and rows[0]["ok"] == 1
    s.close()


def test_errored_model_recorded_as_not_ok(tmp_path):
    s = _store(tmp_path)
    rid = s.start_run("summary")
    s.save_result(rid, "summary", _summary_row("bad", error="KeyError: x"))
    row = s.results_for_run(rid)[0]
    assert row["ok"] == 0 and "KeyError" in row["error"]
    s.close()


def test_leaderboard_ranks_grounded_formatted_highest(tmp_path):
    s = _store(tmp_path)
    rid = s.start_run("summary")
    s.save_result(rid, "summary", _summary_row("good"))                       # clean
    s.save_result(rid, "summary", _summary_row("sloppy", halluc=True,
                                               sentences=5))                  # worse
    s.save_result(rid, "summary", _summary_row("broken", error="down"))       # worst
    s.finish_run(rid, 3)

    board = s.leaderboard("summary")
    assert [b["model"] for b in board] == ["good", "sloppy", "broken"]
    assert board[0]["score"] == 100.0
    assert board[-1]["score"] == 0.0
    s.close()


def test_leaderboard_aggregates_across_runs(tmp_path):
    s = _store(tmp_path)
    for _ in range(3):
        rid = s.start_run("summary")
        s.save_result(rid, "summary", _summary_row("m"))
    board = s.leaderboard("summary")
    assert board[0]["runs"] == 3
    s.close()


def test_suggest_selection_skips_always_failing_model(tmp_path):
    s = _store(tmp_path)
    rid = s.start_run("summary")
    s.save_result(rid, "summary", _summary_row("works"))
    s.save_result(rid, "summary", _summary_row("fails", error="boom"))
    s.finish_run(rid, 2)

    sug = s.suggest_selection("summary")
    assert sug["winner"] == "works"
    assert sug["fallback"] is None  # the only other model always errored
    s.close()


def test_set_and_get_selection(tmp_path):
    s = _store(tmp_path)
    s.set_selection("summary", winner="ollama:qwen2.5", fallback="offline",
                    reason="best grounding")
    pins = {p["task"]: p for p in s.get_selection()}
    assert pins["summary"]["winner"] == "ollama:qwen2.5"
    assert pins["summary"]["fallback"] == "offline"
    # Upsert, not duplicate.
    s.set_selection("summary", winner="gemini")
    assert len(s.get_selection("summary")) == 1
    assert s.get_selection("summary")[0]["winner"] == "gemini"
    s.close()


def test_ioc_scoring_penalizes_parse_errors_and_rejects(tmp_path):
    s = _store(tmp_path)
    rid = s.start_run("ioc")
    s.save_result(rid, "ioc", {"model": "clean", "latency_s": 0.1,
                               "data": {"ips": ["1.1.1.1"]}, "rejected": {},
                               "parse_error": ""})
    s.save_result(rid, "ioc", {"model": "messy", "latency_s": 0.1, "data": {},
                               "rejected": {"ips": ["9.9.9.9", "8.8.8.8"]},
                               "parse_error": "no JSON object found"})
    s.finish_run(rid, 2)

    board = s.leaderboard("ioc")
    assert board[0]["model"] == "clean"
    assert board[0]["score"] > board[1]["score"]
    s.close()
