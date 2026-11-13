from pathlib import Path

from strata.cli.main import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_import_commands_and_list(tmp_path, capsys):
    db = tmp_path / "strata.db"

    assert (
        main(
            [
                "import-vulnharvest",
                str(FIXTURES / "vulnharvest_sample.json"),
                "--db",
                str(db),
            ]
        )
        == 0
    )
    assert "imported=5" in capsys.readouterr().out

    assert (
        main(["import-jsast", str(FIXTURES / "jsast_sample.json"), "--db", str(db)])
        == 0
    )
    assert "imported=2" in capsys.readouterr().out

    assert main(["list", "--db", str(db), "--limit", "20"]) == 0
    out = capsys.readouterr().out
    assert "app.example.com/api/v1/users" in out


def test_import_bad_report_returns_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"endpoints": [{}]}', encoding="utf-8")
    assert main(["import-vulnharvest", str(bad), "--db", str(tmp_path / "x.db")]) == 2
    assert "missing a url" in capsys.readouterr().err
