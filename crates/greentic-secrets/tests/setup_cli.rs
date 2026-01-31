use predicates::prelude::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn cli_help_mentions_admin() -> Result<()> {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("greentic-secrets");
    cmd.args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
    Ok(())
}

#[test]
fn admin_help_lists_list_command() -> Result<()> {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("greentic-secrets");
    cmd.args(["admin", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list"));
    Ok(())
}
