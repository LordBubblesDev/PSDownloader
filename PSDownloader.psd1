@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'PSDownloader.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = '05862360-6d8e-4879-adf4-566e5f6029ac'

    # Author of this module
    Author = 'LordBubbles'

    # Company or vendor of this module
    CompanyName = 'LordBubbles'

    # Copyright statement for this module
    Copyright = '(c) 2025 LordBubbles. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'A PowerShell module for downloading files with multi-threaded support. Features include progress reporting, hash verification, automatic retries, pipeline support, and multiple user agent options.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @('Start-Download')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('download', 'multithread', 'http', 'file-transfer', 'downloader', 'multi-thread', 'hash-verification', 'powershell')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/LordBubblesDev/PSDownloader/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/LordBubblesDev/PSDownloader'

            # A URL to the readme for this module
            ReadmeUri = 'https://github.com/LordBubblesDev/PSDownloader/blob/main/README.md'

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release of PSDownloader module.'
        }
    }
} 