<#
.SYNOPSIS
    PowerShell module to download files with support for multiple threads for improved speed.
.DESCRIPTION
    Downloads a file from a specified URL. It supports multi-threaded downloads, progress reporting, hash verification, and automatic retries.

    To see all available parameters:
    Get-Help Start-Download -Full

    To see just the examples:
    Get-Help Start-Download -Examples
.PARAMETER Url
    The URL of the file to download.
    Can be directly specified or piped from another command.
    Either a single URL or an array of URLs can be provided.
.PARAMETER Destination
    The local path where the file should be saved. Can be either a file path or directory.
    If a directory is specified, the filename will be extracted from the URL or server response.
.PARAMETER TempPath
    Directory to store temporary segment files. Defaults to system temp directory.
.PARAMETER NoProgress
    Suppresses the download progress bar.
.PARAMETER Quiet
    Suppresses all output except errors.
.PARAMETER Force
    Overwrites the destination file if it already exists.
.PARAMETER Threads
    Number of concurrent download threads. Higher numbers may improve speed but use more memory.
    Defaults to 1. Recommended range: 1-16.
.PARAMETER MaxRetry
    Maximum number of retry attempts if download fails. Defaults to 3.
.PARAMETER Timeout
    Timeout for the HTTP request in seconds. Defaults to 30.
.PARAMETER ExpectedHash
    Expected file hash. If specified, verifies the downloaded file's hash matches.
    Will retry the download if verification fails.

    Note: if processing multiple URLs through pipeline, hash verification will be disabled.
.PARAMETER HashType
    Type of hash to verify. Valid values: MD5, SHA1, SHA256, SHA384, SHA512.
    Defaults to MD5 if unspecified.
.PARAMETER UserAgent
    User agent string for the HTTP request. Change if experiencing server restrictions.
    Available presets:
    - 'Chrome' (default): Latest Chrome browser
    - 'Firefox': Latest Firefox browser
    - 'Edge': Latest Edge browser
    - 'Safari': Latest Safari browser
    - 'Opera': Latest Opera browser
    - 'Simple': Simple Mozilla string
    - 'Wget': Wget-like user agent
    - 'Curl': Curl-like user agent
    - 'PS': PowerShell user agent
    - 'None': Empty string (no user agent)
    - Or provide your own custom user agent string
.EXAMPLE
    Start-Download -Url "https://example.com/file.zip"

.EXAMPLE
    Start-Download -Url "https://example.com/file.zip" -Destination "C:\Downloads" -Threads 8

.EXAMPLE
    Start-Download -Url "https://example.com/file.zip" -ExpectedHash "1234ABCD..." -HashType SHA256

.EXAMPLE
    Start-Download -Url "https://example.com/file.zip" -Destination "D:\Data" -Quiet -Force

.EXAMPLE
    Start-Download -Url "https://example.com/file.zip" -TempDir "E:\Temp" -MaxRetry 5
#>

function Start-Download {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)][string]$Url,
        [Parameter()][string]$Destination = $PWD.Path,
        [Parameter()][string]$TempPath = $env:TEMP,
        [Parameter()][switch]$NoProgress,
        [Parameter()][switch]$Quiet,
        [Parameter()][switch]$Force,
        [Parameter()][int]$Threads = 1,
        [Parameter()][int]$MaxRetry = 3,
        [Parameter()][int]$Timeout = 30,
        [Parameter()][string]$ExpectedHash,
        [Parameter()][ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')][string]$HashType = 'MD5',
        [Parameter()][string]$UserAgent = 'Chrome'
    )

    begin {
        $userAgents = @{
            'Chrome' = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            'Firefox' = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
            'Edge' = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92"
            'Safari' = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15"
            'Opera' = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0"
            'Simple' = "Mozilla/5.0"
            'Wget' = "Wget/1.21.4"
            'Curl' = "curl/8.4.0"
            'PS' = "PowerShell/7.4 (Windows NT 10.0; Win64; x64)"
            'None' = $null
        }

        if ($ExpectedHash) {
            $script:ExpectedHash = $ExpectedHash.ToUpper()
        }
        
        # If UserAgent is a preset name, use the corresponding string
        if ($userAgents.ContainsKey($UserAgent)) {
            $UserAgent = $userAgents[$UserAgent]
        }

        if ($Quiet -and $Verbose) {
            Write-Error "Cannot use Quiet and Verbose at the same time."
            return
        }

        $isPipeline = -not $PSBoundParameters.ContainsKey('Url')
        
        if ($isPipeline) {
            $script:pipelineUrls = @()
        }
    }

    process {
        if ($isPipeline) {
            $script:pipelineUrls += $Url
        }
        
        if ($isPipeline -and $script:pipelineUrls.Count -gt 1 -and $ExpectedHash) {
            Write-Warning "Hash verification is disabled when processing multiple URLs."
            $ExpectedHash = $null
        }

        Write-Verbose "Processing URL: $Url"

        $attempt = 0
        $success = $false

        while ($attempt -lt $MaxRetry -and -not $success) {
            try {
                $attempt++
                if ($attempt -gt 1) {
                    Write-Verbose "Retry attempt $attempt of $MaxRetry"
                    Start-Sleep -Seconds ($attempt * 2)
                }

                $BUFFER_SIZE = 64KB
                $MB = 1024 * 1024

                $request = [System.Net.HttpWebRequest]::Create($Url)
                $request.Method = "HEAD"
                $request.UserAgent = $UserAgent
                $response = $request.GetResponse()
                
                if (Test-Path $Destination -PathType Container) {
                    $fileName = ""
                    
                    $contentDisposition = $response.Headers["Content-Disposition"]
                    if ($contentDisposition -match 'filename=(.+?)$') {
                        $fileName = $matches[1].Trim('"', "'")
                    }
                    
                    if (-not $fileName) {
                        $fileName = [System.IO.Path]::GetFileName([System.Uri]::UnescapeDataString($Url))
                    }
                    
                    if (-not $fileName) {
                        $fileName = "download"
                        
                        $contentType = $response.ContentType
                        $extension = [System.Web.MimeMapping]::GetMimeMapping($contentType)
                        if ($extension) {
                            $fileName = "$fileName$extension"
                        }
                    }
                    
                    $OutFile = Join-Path $Destination $fileName
                }
                else {
                    $OutFile = $Destination
                }

                if ($tempDir -and (Test-Path $tempDir)) {
                    try {
                        Write-Verbose "Cleaning up existing temp directory: $tempDir"
                        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Failed to remove existing temp directory: $_"
                    }
                }

                $contentLength = $response.ContentLength
                $response.Close()

                $downloadTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $segmentSize = [math]::Ceiling($contentLength / $Threads)
                $tempDir = Join-Path $TempPath "DownloadSegments-$(New-Guid)"
                $segmentSizes = @{}

                if (Test-Path $OutFile) {
                    if ($Force) {
                        Write-Verbose "Overwriting file at $OutFile"
                        Remove-Item -Path $OutFile -Force -ErrorAction Ignore
                    }
                    else {
                        Write-Warning "File already exists at $OutFile. Skipping download."
                        return
                    }
                }

                while (Test-Path $tempDir) {
                    try {
                        Write-Verbose "Cleaning up existing temp directory: $tempDir"
                        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Failed to remove existing temp directory: $_"
                        $tempDir = Join-Path $TempPath "DownloadSegments-$(New-Guid)"
                    }
                }
                New-Item -ItemType Directory -Path $tempDir | Out-Null

                $downloadSegment = {
                    param(
                        [string]$url,
                        [string]$tempFile,
                        [long]$start,
                        [long]$end,
                        [int]$bufferSize,
                        [int]$timeout,
                        [string]$userAgent
                    )
                    
                    $request = [System.Net.HttpWebRequest]::Create($url)
                    $request.AddRange($start, $end)
                    $request.Timeout = $timeout * 1000
                    $request.ReadWriteTimeout = $timeout * 1000
                    $request.UserAgent = $userAgent
                    $totalBytes = 0
                    $expectedBytes = $end - $start + 1
                    
                    try {
                        $response = $request.GetResponse()
                        $stream = $response.GetResponseStream()
                        $stream.ReadTimeout = $timeout * 1000
                        $fileStream = [System.IO.File]::Create($tempFile)
                        $buffer = New-Object byte[] $bufferSize
                        
                        while ($totalBytes -lt $expectedBytes) {
                            $remaining = $expectedBytes - $totalBytes
                            $toRead = [Math]::Min($buffer.Length, $remaining)
                            $read = $stream.Read($buffer, 0, $toRead)
                            
                            if ($read -eq 0) { break }
                            
                            $fileStream.Write($buffer, 0, $read)
                            $totalBytes += $read
                            Write-Output @{ BytesRead = $totalBytes }
                        }

                        if ($totalBytes -ne $expectedBytes) {
                            throw "Segment size mismatch: Expected $expectedBytes bytes, got $totalBytes bytes"
                        }
                    }
                    finally {
                        if ($fileStream) { $fileStream.Dispose() }
                        if ($stream) { $stream.Dispose() }
                        if ($response) { $response.Dispose() }
                    }
                }

                $jobs = @()
                $tempFiles = @()

                for ($i = 0; $i -lt $Threads; $i++) {
                    $start = $i * $segmentSize
                    $end = [Math]::Min(($i + 1) * $segmentSize - 1, $contentLength - 1)
                    $tempFile = Join-Path $tempDir "segment_$i"
                    $tempFiles += $tempFile
                    
                    $segmentSizes[$i] = $end - $start + 1
                    
                    $job = Start-Job -ScriptBlock $downloadSegment -ArgumentList $Url, $tempFile, $start, $end, $BUFFER_SIZE, $Timeout, $UserAgent
                    $jobs += $job
                }

                $fileName = [System.IO.Path]::GetFileName($OutFile)
                $totalSize = switch ($contentLength) {
                    { $_ -gt 1TB } { "{0:n2} TB" -f ($_ / 1TB); Break }
                    { $_ -gt 1GB } { "{0:n2} GB" -f ($_ / 1GB); Break }
                    { $_ -gt 1MB } { "{0:n2} MB" -f ($_ / 1MB); Break }
                    { $_ -gt 1KB } { "{0:n2} KB" -f ($_ / 1KB); Break }
                    default { "{0} B " -f $_ }
                }

                $lastUpdate = 0
                $completedSegments = @{}
                $lastProgressTime = [DateTime]::Now
                $segmentLastProgress = @{}
                $segmentRetries = @{}
                $maxSegmentRetries = 3

                function Restart-Segment {
                    param(
                        [int]$segmentIndex,
                        [string]$reason
                    )
                    
                    if (-not $segmentRetries.ContainsKey($segmentIndex)) {
                        $segmentRetries[$segmentIndex] = 0
                    }
                    
                    $segmentRetries[$segmentIndex]++
                    if ($segmentRetries[$segmentIndex] -gt $maxSegmentRetries) {
                        Write-Warning "Segment $segmentIndex failed after $maxSegmentRetries retries: $reason"
                        throw "Download failed - segment $segmentIndex max retries exceeded"
                    }
                    
                    Write-Verbose "Restarting segment $segmentIndex (attempt $($segmentRetries[$segmentIndex]) of $maxSegmentRetries): $reason"
                    
                    # Clean up old job
                    $oldJob = $jobs[$segmentIndex]
                    if ($oldJob) {
                        try {
                            if ($oldJob.State -ne 'Completed') {
                                $oldJob | Stop-Job -ErrorAction SilentlyContinue
                            }
                            $oldJob | Remove-Job -Force -ErrorAction SilentlyContinue
                        } catch {
                            Write-Warning "Failed to cleanup old job for segment $($segmentIndex): $_"
                        }
                    }
                    
                    # Calculate start and end positions
                    $start = $segmentIndex * $segmentSize
                    $end = [Math]::Min(($segmentIndex + 1) * $segmentSize - 1, $contentLength - 1)
                    $tempFile = Join-Path $tempDir "segment_$segmentIndex"
                    
                    # Start new job
                    $jobs[$segmentIndex] = Start-Job -ScriptBlock $downloadSegment -ArgumentList $Url, $tempFile, $start, $end, $BUFFER_SIZE, $Timeout, $UserAgent
                    
                    # Reset progress tracking
                    $segmentLastProgress[$segmentIndex] = @{
                        LastTime = [DateTime]::Now
                        LastBytes = 0
                        StuckCount = 0
                    }
                }

                while ($true) {
                    $totalBytesRead = 0
                    $allComplete = $true
                    $currentTime = [DateTime]::Now
                    
                    # Global timeout check - if no progress
                    if (($currentTime - $lastProgressTime).TotalSeconds -gt $Timeout) {
                        throw "Download timed out - no progress for $Timeout seconds"
                    }
                    
                    for ($i = 0; $i -lt $Threads; $i++) {
                        if ($completedSegments[$i]) {
                            $totalBytesRead += $segmentSizes[$i]
                            continue
                        }
                        
                        $job = $jobs[$i]
                        if (-not $job) {
                            Restart-Segment -segmentIndex $i -reason "Job was lost"
                            $allComplete = $false
                            continue
                        }
                        
                        # Initialize progress tracking for this segment if not exists
                        if (-not $segmentLastProgress.ContainsKey($i)) {
                            $segmentLastProgress[$i] = @{
                                LastTime = $currentTime
                                LastBytes = 0
                                StuckCount = 0
                            }
                        }
                        
                        if ($job.State -eq 'Failed') {
                            $errorMsg = $job.ChildJobs[0].JobStateInfo.Reason.Message
                            Restart-Segment -segmentIndex $i -reason $errorMsg
                            $allComplete = $false
                            continue
                        }
                        
                        # Handle completed jobs that might be stuck
                        if ($job.State -eq 'Completed') {
                            $data = Receive-Job -Job $job -Keep -ErrorAction Stop
                            if (-not $data -or $data.Count -eq 0 -or ($data | Select-Object -Last 1).BytesRead -lt $segmentSizes[$i]) {
                                Restart-Segment -segmentIndex $i -reason "Completed but did not finish downloading"
                                $allComplete = $false
                                continue
                            }
                        }
                        
                        try {
                            $data = Receive-Job -Job $job -Keep -ErrorAction Stop
                            if ($data -and $data.Count -gt 0) {
                                $lastBytes = ($data | Select-Object -Last 1).BytesRead
                                
                                # Check if this segment is making progress
                                if ($lastBytes -gt $segmentLastProgress[$i].LastBytes) {
                                    $segmentLastProgress[$i].LastTime = $currentTime
                                    $segmentLastProgress[$i].LastBytes = $lastBytes
                                    $segmentLastProgress[$i].StuckCount = 0
                                    $lastProgressTime = $currentTime
                                } else {
                                    # Check if segment is stuck
                                    $segmentStuckTime = ($currentTime - $segmentLastProgress[$i].LastTime).TotalSeconds
                                    if ($segmentStuckTime -gt $Timeout) {
                                        $segmentLastProgress[$i].StuckCount++
                                        if ($segmentLastProgress[$i].StuckCount -gt 3) {
                                            Restart-Segment -segmentIndex $i -reason "Stuck for too long"
                                            $allComplete = $false
                                            continue
                                        }
                                    }
                                }
                                
                                if ($lastBytes -ge $segmentSizes[$i]) {
                                    $completedSegments[$i] = $true
                                    $totalBytesRead += $segmentSizes[$i]
                                    $segmentLastProgress.Remove($i)
                                    try {
                                        if ($job.State -ne 'Completed') {
                                            $job | Stop-Job -ErrorAction SilentlyContinue
                                        }
                                        $job | Remove-Job -Force -ErrorAction SilentlyContinue
                                        $jobs[$i] = $null
                                    }
                                    catch {
                                        Write-Warning "Failed to cleanup completed job $($i): $_"
                                    }
                                } else {
                                    $allComplete = $false
                                    $totalBytesRead += $lastBytes
                                }
                            } else {
                                $allComplete = $false
                                
                                # Check if segment has been silent too long
                                $segmentStuckTime = ($currentTime - $segmentLastProgress[$i].LastTime).TotalSeconds
                                if ($segmentStuckTime -gt 10) {
                                    $segmentLastProgress[$i].StuckCount++
                                    if ($segmentLastProgress[$i].StuckCount -gt 3) {
                                        Restart-Segment -segmentIndex $i -reason "No progress for too long"
                                        continue
                                    }
                                }
                            }
                        }
                        catch {
                            Restart-Segment -segmentIndex $i -reason "Error: $_"
                            $allComplete = $false
                            continue
                        }
                    }
                    
                    if ($allComplete) { break }
                    
                    if (-not $NoProgress) {
                        $progress = [Math]::Min(($totalBytesRead / $contentLength) * 100, 100)
                        $speed = ($totalBytesRead - $lastUpdate) / 0.5 # MB/s
                        $lastUpdate = $totalBytesRead
                        
                        Write-Progress -Activity "Downloading File: $fileName ($totalSize)" `
                                      -Status "$([math]::Round($progress, 2))% Complete - $([math]::Round($speed / $MB, 2)) MB/s" `
                                      -PercentComplete $progress
                    }
                    
                    Start-Sleep -Milliseconds 500
                }

                $finalFile = [System.IO.File]::Create($OutFile)
                try {
                    for ($i = 0; $i -lt $Threads; $i++) {
                        if (-not $NoProgress) {
                            Write-Progress -Activity "Merging segments: $fileName" `
                                          -Status "Processing segment $($i + 1) of $Threads" `
                                          -PercentComplete (($i / $Threads) * 100)
                        }
                        
                        $tempFile = Join-Path $tempDir "segment_$i"
                        $expectedSize = $segmentSizes[$i]
                        
                        if (-not (Test-Path $tempFile)) {
                            throw "Missing segment file: $tempFile"
                        }
                        
                        $bytes = [System.IO.File]::ReadAllBytes($tempFile)
                        if ($bytes.Length -eq 0) {
                            throw "Empty segment file: $tempFile"
                        }
                        if ($bytes.Length -ne $expectedSize) {
                            throw "Segment size mismatch: Expected $expectedSize, got $($bytes.Length)"
                        }
                        
                        $finalFile.Write($bytes, 0, $bytes.Length)
                    }
                }
                finally {
                    $finalFile.Close()
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                }

                if (-not $NoProgress) {
                    Write-Progress -Activity "Downloading File" -Completed
                }

                if ($ExpectedHash) {
                    Write-Verbose "Verifying file hash..."
                    $actualHash = (Get-FileHash -Path $OutFile -Algorithm $HashType).Hash
                    if ($actualHash -ne $ExpectedHash) {
                        Write-Warning "Hash verification failed! Expected: $ExpectedHash, Got: $actualHash"
                        $success = $false
                        continue
                    }
                    Write-Verbose "Hash verification successful"
                }

                $downloadTimer.Stop()

                if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
                    Write-Output "`nFile downloaded successfully."
                    $elapsed = $downloadTimer.Elapsed
                    $formattedTime = if ($elapsed.Hours -gt 0) {
                        "{0} hour{1} {2} minute{3} {4:N3} seconds" -f 
                            $elapsed.Hours,
                            $(if ($elapsed.Hours -eq 1) {""} else {"s"}),
                            $elapsed.Minutes,
                            $(if ($elapsed.Minutes -eq 1) {""} else {"s"}),
                            ($elapsed.Seconds + $elapsed.Milliseconds / 1000)
                    } elseif ($elapsed.Minutes -gt 0) {
                        "{0} minute{1} {2:N3} seconds" -f 
                            $elapsed.Minutes,
                            $(if ($elapsed.Minutes -eq 1) {""} else {"s"}),
                            ($elapsed.Seconds + $elapsed.Milliseconds / 1000)
                    } else {
                        "{0:N3} seconds" -f ($elapsed.Seconds + $elapsed.Milliseconds / 1000)
                    }
                    
                    Write-Output "Path: $OutFile"
                    Write-Output "Size: $totalSize"
                    Write-Output "Elapsed Time: $formattedTime"
                    Write-Output "$($HashType): $($(Get-FileHash -Path $OutFile -Algorithm $HashType).Hash)`n"
                }
                else {
                    if (-not $Quiet) {
                        Write-Output "File downloaded successfully."
                    }
                }

                $success = $true
            }
            catch {
                if ($attempt -ge $MaxRetry) {
                    Write-Error "Failed after $MaxRetry attempts: $_"
                    throw
                }
                Write-Warning "Download failed (attempt $attempt of $MaxRetry): $_"
                
                if (Test-Path $tempDir) {
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path $OutFile) {
                    Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue
                }
            }
            finally {
                $jobs | Where-Object { $_ } | ForEach-Object {
                    try {
                        if ($_.State -ne 'Completed') {
                            $_ | Stop-Job -ErrorAction SilentlyContinue
                        }
                        $_ | Remove-Job -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Warning "Failed to cleanup job: $_"
                    }
                }
                $jobs = @()
            }
        }
    }
}