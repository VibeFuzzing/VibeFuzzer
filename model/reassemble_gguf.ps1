# reassemble_gguf.ps1
# Usage: .\reassemble_gguf.ps1 model_q4km.gguf
# Looks for model_q4km.part0, model_q4km.part1, etc. in same directory as output file

param(
    [Parameter(Mandatory=$true)]
    [string]$OutputFile
)

# Resolve to absolute path so .NET methods work correctly
$OutputFile = Join-Path (Get-Location) $OutputFile
$dir = [System.IO.Path]::GetDirectoryName($OutputFile)
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFile)

$outStream = [System.IO.File]::OpenWrite($OutputFile)
$part = 0
$bufferSize = 64 * 1024 * 1024  # 64 MB read buffer
$buffer = New-Object byte[] $bufferSize

Write-Host "Reassembling parts into $OutputFile..."

while ($true) {
    $partPath = Join-Path $dir "${baseName}.part${part}"
    if (-not (Test-Path $partPath)) { break }

    Write-Host "  Reading ${baseName}.part${part}..."
    $inStream = [System.IO.File]::OpenRead($partPath)

    while ($true) {
        $bytesRead = $inStream.Read($buffer, 0, $bufferSize)
        if ($bytesRead -eq 0) { break }
        $outStream.Write($buffer, 0, $bytesRead)
    }

    $inStream.Close()
    $part++
}

$outStream.Close()

$fileSize = (Get-Item $OutputFile).Length
Write-Host "Done! Reassembled $part parts into $OutputFile ($([math]::Round($fileSize / 1GB, 2)) GB)"