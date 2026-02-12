#!/usr/bin/env powershell

Write-Host "`n=== BSOD Analyzer GitHub Setup ===" -ForegroundColor Cyan

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Git is not installed!" -ForegroundColor Red
    Write-Host "Please install Git from https://git-scm.com/" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n1. Create new repository at https://github.com/new" -ForegroundColor Green
Write-Host "   Repository name: bsod-analyzer" -ForegroundColor Green
Write-Host "   Public or Private - your choice" -ForegroundColor Green
Write-Host "   Click Create repository" -ForegroundColor Green

$repoUrl = Read-Host "`n2. Enter your GitHub repository URL"

if ([string]::IsNullOrWhiteSpace($repoUrl)) {
    Write-Host "ERROR: Repository URL is required!" -ForegroundColor Red
    exit 1
}

Write-Host "`n3. Setting up git remote and pushing..." -ForegroundColor Cyan

& git remote add origin $repoUrl
$branch = & git rev-parse --abbrev-ref HEAD
$branch = $branch.Trim()

if ($branch -eq "master") {
    Write-Host "Renaming branch to main..." -ForegroundColor Yellow
    & git branch -m main
}

Write-Host "Pushing to GitHub..." -ForegroundColor Cyan
& git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nSUCCESS! Repository pushed to GitHub." -ForegroundColor Green
    Write-Host "URL: $repoUrl`n" -ForegroundColor Green
}
else {
    Write-Host "`nERROR during push!" -ForegroundColor Red
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  git config --global user.name 'Your Name'" -ForegroundColor Gray
    Write-Host "  git config --global user.email 'your@email.com'" -ForegroundColor Gray
    exit 1
}
