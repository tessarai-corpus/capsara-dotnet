using System.Text.Json.Serialization;

namespace Capsara.SDK.Models
{
    /// <summary>Server-enforced limits for file and capsa operations.</summary>
    public sealed class SystemLimits
    {
        /// <summary>Maximum allowed size for a single file, in bytes.</summary>
        [JsonPropertyName("maxFileSize")]
        public long MaxFileSize { get; set; }

        /// <summary>Maximum number of files allowed per capsa.</summary>
        [JsonPropertyName("maxFilesPerCapsa")]
        public int MaxFilesPerCapsa { get; set; }

        /// <summary>Maximum total size of all files in a capsa, in bytes.</summary>
        [JsonPropertyName("maxTotalSize")]
        public long MaxTotalSize { get; set; }

        /// <summary>Default system limits: 1 GB per file, 100 files per capsa, 10 GB total.</summary>
        public static SystemLimits Default => new()
        {
            MaxFileSize = 1024 * 1024 * 1024,      // 1 GB
            MaxFilesPerCapsa = 100,
            MaxTotalSize = 10L * 1024 * 1024 * 1024 // 10 GB
        };
    }
}
