using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Capsara.SDK.Internal.Http
{
    /// <summary>Injects Bearer authentication tokens into outgoing requests.</summary>
    internal sealed class AuthHandler : DelegatingHandler
    {
        private readonly Func<string?> _getToken;

        public AuthHandler(Func<string?> getToken)
            : base()
        {
            _getToken = getToken ?? throw new ArgumentNullException(nameof(getToken));
        }

        public AuthHandler(HttpMessageHandler innerHandler, Func<string?> getToken)
            : base(innerHandler)
        {
            _getToken = getToken ?? throw new ArgumentNullException(nameof(getToken));
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var token = _getToken();
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}
