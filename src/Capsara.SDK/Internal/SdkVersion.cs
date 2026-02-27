using System.Reflection;

namespace Capsara.SDK.Internal
{
    internal static class SdkVersion
    {
        public static string Version { get; }
        public static string FullName { get; }

        static SdkVersion()
        {
            var assembly = typeof(SdkVersion).Assembly;
            var version = assembly.GetName().Version;
            Version = version != null
                ? $"{version.Major}.{version.Minor}.{version.Build}"
                : "1.0.0";

            FullName = $"Capsara.SDK/{Version}";
        }

        public static string BuildUserAgent(string? customAgent = null)
        {
            var baseAgent = $"Capsara.SDK-dotnet/{Version}";
            return string.IsNullOrEmpty(customAgent)
                ? baseAgent
                : $"{baseAgent} {customAgent}";
        }
    }
}
