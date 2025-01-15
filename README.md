# PSDownloader

A PowerShell module for downloading files with multi-threaded support. Features include progress reporting, hash verification, automatic retries, pipeline support, and multiple user agent options.

# Features

- Multi-threaded downloads
- Progress/speed reporting
- Hash verification
- Automatic retries
- Pipeline support
- Multiple user agent options
- Segment retry on failure

# Installation

1. Install the module
```powershell
Install-Module -Name PSDownloader
```
2. Import the module:
```powershell
Import-Module PSDownloader
```

# Usage

## Basic Download

```powershell
Start-Download -Url "https://example.com/file.zip"
```

## Multi-threaded Download

```powershell
Start-Download -Url "https://example.com/file.zip" -Threads 8
```

## Download with Hash Verification

```powershell
Start-Download -Url "https://example.com/file.zip" -ExpectedHash "1234ABCD" -HashType SHA256
```

## Pipeline Support

```powershell
# Download multiple files
Get-Content "urls.txt" | Start-Download -Destination "D:\Downloads"
```

## Parameters

- `Url`: The URL of the file to download
- `Destination`: Output path (file or directory)
- `TempPath`: Directory for temporary files
- `NoProgress`: Suppress progress bar
- `Quiet`: Suppress all output except errors
- `Force`: Overwrite existing files
- `Threads`: Number of download threads (default: 1)
- `MaxRetry`: Maximum retry attempts (default: 3)
- `Timeout`: Connection timeout in seconds (default: 30)
- `ExpectedHash`: Expected file hash for verification
- `HashType`: Hash algorithm (MD5, SHA1, SHA256, SHA384, SHA512)
- `UserAgent`: User agent string or preset name

## User Agent Presets

- 'Chrome' (default)
- 'Firefox'
- 'Edge'
- 'Safari'
- 'Opera'
- 'Simple'
- 'Wget'
- 'Curl'
- 'PS'
- 'None'

# Advanced Usage

For more detailed help, run the command below
```powershell
Get-Help Start-Download -Full
```