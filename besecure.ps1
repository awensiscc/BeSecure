param(
  [string]$Python = "python"
)

.\getconnections.ps1
& $Python .\besecure.py
