using System;
using System.Collections.Generic;
using System.IO;

namespace Capsara.SDK.Internal
{
    /// <summary>
    /// MIME type lookup by file extension.
    /// </summary>
    internal static class MimetypeLookup
    {
        private static readonly Dictionary<string, string> MimeMap = new(StringComparer.OrdinalIgnoreCase)
        {
            // Documents - PDF
            { ".pdf", "application/pdf" },

            // Documents - Microsoft Office
            { ".doc", "application/msword" },
            { ".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
            { ".xls", "application/vnd.ms-excel" },
            { ".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
            { ".ppt", "application/vnd.ms-powerpoint" },
            { ".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },

            // Documents - OpenDocument
            { ".odt", "application/vnd.oasis.opendocument.text" },
            { ".ods", "application/vnd.oasis.opendocument.spreadsheet" },
            { ".odp", "application/vnd.oasis.opendocument.presentation" },

            // Images
            { ".jpg", "image/jpeg" },
            { ".jpeg", "image/jpeg" },
            { ".png", "image/png" },
            { ".gif", "image/gif" },
            { ".bmp", "image/bmp" },
            { ".tif", "image/tiff" },
            { ".tiff", "image/tiff" },
            { ".webp", "image/webp" },
            { ".svg", "image/svg+xml" },
            { ".heic", "image/heic" },
            { ".heif", "image/heif" },

            // Audio
            { ".mp3", "audio/mpeg" },
            { ".wav", "audio/wav" },
            { ".m4a", "audio/mp4" },
            { ".aac", "audio/aac" },
            { ".ogg", "audio/ogg" },
            { ".wma", "audio/x-ms-wma" },
            { ".flac", "audio/flac" },

            // Video
            { ".mp4", "video/mp4" },
            { ".mov", "video/quicktime" },
            { ".avi", "video/x-msvideo" },
            { ".wmv", "video/x-ms-wmv" },
            { ".mkv", "video/x-matroska" },
            { ".webm", "video/webm" },
            { ".m4v", "video/x-m4v" },
            { ".3gp", "video/3gpp" },
            { ".ts", "video/mp2t" },             // MPEG transport stream (dashcam)

            // Text/Data
            { ".txt", "text/plain" },
            { ".csv", "text/csv" },
            { ".json", "application/json" },
            { ".xml", "application/xml" },
            { ".html", "text/html" },
            { ".htm", "text/html" },
            { ".rtf", "application/rtf" },

            // Archives
            { ".zip", "application/zip" },
            { ".gz", "application/gzip" },
            { ".gzip", "application/gzip" },
            { ".tar", "application/x-tar" },
            { ".7z", "application/x-7z-compressed" },
            { ".rar", "application/vnd.rar" },

            // Email
            { ".eml", "message/rfc822" },
            { ".msg", "application/vnd.ms-outlook" },

            // Insurance Industry Formats
            { ".al3", "application/x-al3" },           // ACORD AL3 (Agency/Company interface)
            { ".tt2", "application/x-turbotag" },      // TurboTag indexing files
            { ".acord", "application/xml" },           // ACORD XML forms
            { ".idx", "application/x-index" },         // Index files (common in document management)

            // EDI/Financial Formats
            { ".edi", "application/EDI-X12" },         // EDI X12 transactions
            { ".x12", "application/EDI-X12" },         // EDI X12 alternate extension
            { ".837", "application/EDI-X12" },         // Healthcare claims
            { ".835", "application/EDI-X12" },         // Healthcare remittance
            { ".834", "application/EDI-X12" },         // Benefit enrollment
            { ".270", "application/EDI-X12" },         // Eligibility inquiry
            { ".271", "application/EDI-X12" },         // Eligibility response
            { ".820", "application/EDI-X12" },         // Payment order/remittance
            { ".850", "application/EDI-X12" },         // Purchase order
            { ".856", "application/EDI-X12" },         // Ship notice/manifest
            { ".810", "application/EDI-X12" },         // Invoice

            // Financial Data Formats
            { ".ofx", "application/x-ofx" },           // Open Financial Exchange
            { ".qfx", "application/x-qfx" },           // Quicken Financial Exchange
            { ".qbo", "application/x-qbo" },           // QuickBooks Online
            { ".qif", "application/x-qif" },           // Quicken Interchange Format
            { ".iif", "text/plain" },                  // Intuit Interchange Format

            // Database/Reporting
            { ".mdb", "application/x-msaccess" },      // Access database
            { ".accdb", "application/x-msaccess" },    // Access 2007+ database
            { ".dbf", "application/x-dbf" },           // dBASE database files
        };

        /// <summary>
        /// Look up MIME type by file path or extension.
        /// </summary>
        /// <param name="pathOrExtension">File path or extension (e.g., "file.pdf", ".pdf", or "pdf")</param>
        /// <returns>MIME type string, or null if not found</returns>
        public static string? Lookup(string? pathOrExtension)
        {
            if (string.IsNullOrEmpty(pathOrExtension))
                return null;

            var ext = Path.GetExtension(pathOrExtension);

            // If no extension found, try treating input as bare extension
            if (string.IsNullOrEmpty(ext) && !pathOrExtension!.Contains("/") && !pathOrExtension.Contains("\\"))
            {
                ext = pathOrExtension.StartsWith(".") ? pathOrExtension : "." + pathOrExtension;
            }

            if (string.IsNullOrEmpty(ext))
                return null;

            return MimeMap.TryGetValue(ext, out var mimetype) ? mimetype : null;
        }
    }
}
