# Builds static/app.css with the Tailwind standalone CLI (no Node). The exe is git-ignored; download pinned v4.3.5 from
# https://github.com/tailwindlabs/tailwindcss/releases into vendor/tailwindcss.exe.
Set-Location $PSScriptRoot
& .\vendor\tailwindcss.exe -i input.css -o static/app.css --minify
