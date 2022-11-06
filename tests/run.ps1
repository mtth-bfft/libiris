# Wrapper used by gitlab-ci to run compiled tests without `cargo` installed
$exit_code=0
$at_least_one=0
Get-ChildItem -Path "$($args[0])" -Filter '*.exe' -ErrorAction Stop | % {
    Write-Host "===== $($_.BaseName)"
    $at_least_one=1
    & "$($_.FullName)"
    if ($LASTEXITCODE -ne 0) {
        $exit_code = $LASTEXITCODE
        Write-Error "$($_.BaseName) failed with code $LASTEXITCODE"
    }
}
if ($at_lease_one -eq 0) {
     exit 1
}
exit $exit_code
