# Rebuilds web/app.css (committed, so a normal `cargo build` needs no Tailwind) from the classes used
# in web/index.html and web/app.js. Run it after changing either file.
#
# Uses the Tailwind standalone CLI v4.3.5 (no Node). It is git-ignored; it lives in the T3 spike at
# spikes/web-spike/vendor/tailwindcss.exe, or download tailwindcss-windows-x64.exe from
# https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.3.5 and pass its path.
param([string]$Tailwind = "$PSScriptRoot\..\..\spikes\web-spike\vendor\tailwindcss.exe")
Set-Location "$PSScriptRoot\web"
& $Tailwind -i input.css -o app.css --minify
