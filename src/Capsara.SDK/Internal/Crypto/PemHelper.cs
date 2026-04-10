using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Capsara.SDK.Internal.Crypto
{
    /// <summary>
    /// Helper for PEM key import/export operations.
    /// Supports both .NET 6+ native methods and .NET Framework 4.8 (via BouncyCastle).
    /// </summary>
    internal static class PemHelper
    {
        private const string PublicKeyHeader = "-----BEGIN PUBLIC KEY-----";
        private const string PublicKeyFooter = "-----END PUBLIC KEY-----";
        private const string PrivateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        private const string PrivateKeyFooter = "-----END PRIVATE KEY-----";
        private const string RsaPublicKeyHeader = "-----BEGIN RSA PUBLIC KEY-----";
        private const string RsaPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";

        /// <summary>
        /// Import a public key from PEM format into an RSA instance.
        /// Supports both SPKI (BEGIN PUBLIC KEY) and PKCS#1 (BEGIN RSA PUBLIC KEY) formats.
        /// </summary>
        public static void ImportPublicKey(RSA rsa, string pem)
        {
            if (rsa == null) throw new ArgumentNullException(nameof(rsa));
            if (string.IsNullOrEmpty(pem)) throw new ArgumentNullException(nameof(pem));

            pem = pem.Trim();

#if NET6_0_OR_GREATER
            // .NET 5+ has native PEM support
            if (pem.Contains(PublicKeyHeader))
            {
                rsa.ImportFromPem(pem);
            }
            else if (pem.Contains(RsaPublicKeyHeader))
            {
                // PKCS#1 format - also supported natively
                rsa.ImportFromPem(pem);
            }
            else
            {
                throw new ArgumentException(
                    "Invalid public key PEM format. Expected 'BEGIN PUBLIC KEY' or 'BEGIN RSA PUBLIC KEY'",
                    nameof(pem));
            }
#else
            // .NET Framework 4.8 - use BouncyCastle
            ImportPublicKeyBouncyCastle(rsa, pem);
#endif
        }

        /// <summary>
        /// Import a private key from PEM format into an RSA instance.
        /// Supports both PKCS#8 (BEGIN PRIVATE KEY) and PKCS#1 (BEGIN RSA PRIVATE KEY) formats.
        /// </summary>
        public static void ImportPrivateKey(RSA rsa, string pem)
        {
            if (rsa == null) throw new ArgumentNullException(nameof(rsa));
            if (string.IsNullOrEmpty(pem)) throw new ArgumentNullException(nameof(pem));

            pem = pem.Trim();

#if NET6_0_OR_GREATER
            if (pem.Contains(PrivateKeyHeader))
            {
                rsa.ImportFromPem(pem);
            }
            else if (pem.Contains(RsaPrivateKeyHeader))
            {
                rsa.ImportFromPem(pem);
            }
            else
            {
                throw new ArgumentException(
                    "Invalid private key PEM format. Expected 'BEGIN PRIVATE KEY' or 'BEGIN RSA PRIVATE KEY'",
                    nameof(pem));
            }
#else
            ImportPrivateKeyBouncyCastle(rsa, pem);
#endif
        }

        /// <summary>
        /// Export a public key to PEM format (SPKI / SubjectPublicKeyInfo).
        /// </summary>
        public static string ExportPublicKeyPem(RSA rsa)
        {
            if (rsa == null) throw new ArgumentNullException(nameof(rsa));

#if NET6_0_OR_GREATER
            return rsa.ExportSubjectPublicKeyInfoPem();
#else
            return ExportPublicKeyPemBouncyCastle(rsa);
#endif
        }

        /// <summary>
        /// Export a private key to PEM format (PKCS#8).
        /// </summary>
        public static string ExportPrivateKeyPem(RSA rsa)
        {
            if (rsa == null) throw new ArgumentNullException(nameof(rsa));

#if NET6_0_OR_GREATER
            return rsa.ExportPkcs8PrivateKeyPem();
#else
            return ExportPrivateKeyPemBouncyCastle(rsa);
#endif
        }

        /// <summary>
        /// Export SubjectPublicKeyInfo as DER bytes.
        /// Used for fingerprint calculation.
        /// </summary>
        public static byte[] ExportSubjectPublicKeyInfo(RSA rsa)
        {
            if (rsa == null) throw new ArgumentNullException(nameof(rsa));

#if NET6_0_OR_GREATER
            return rsa.ExportSubjectPublicKeyInfo();
#else
            return ExportSubjectPublicKeyInfoBouncyCastle(rsa);
#endif
        }

#if NETFRAMEWORK
        private static void ImportPublicKeyBouncyCastle(RSA rsa, string pem)
        {
            using (var reader = new System.IO.StringReader(pem))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                var keyObject = pemReader.ReadObject();

                Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsaParams;

                if (keyObject is Org.BouncyCastle.Crypto.AsymmetricKeyParameter akp)
                {
                    rsaParams = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)akp;
                }
                else if (keyObject is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair)
                {
                    rsaParams = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)keyPair.Public;
                }
                else
                {
                    throw new ArgumentException("Invalid public key PEM format", nameof(pem));
                }

                var parameters = new RSAParameters
                {
                    Modulus = rsaParams.Modulus.ToByteArrayUnsigned(),
                    Exponent = rsaParams.Exponent.ToByteArrayUnsigned()
                };

                rsa.ImportParameters(parameters);
            }
        }

        private static void ImportPrivateKeyBouncyCastle(RSA rsa, string pem)
        {
            using (var reader = new System.IO.StringReader(pem))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
                var keyObject = pemReader.ReadObject();

                Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters privateKey;

                if (keyObject is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair)
                {
                    privateKey = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyPair.Private;
                }
                else if (keyObject is Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters pk)
                {
                    privateKey = pk;
                }
                else
                {
                    throw new ArgumentException("Invalid private key PEM format", nameof(pem));
                }

                var parameters = new RSAParameters
                {
                    Modulus = privateKey.Modulus.ToByteArrayUnsigned(),
                    Exponent = privateKey.PublicExponent.ToByteArrayUnsigned(),
                    D = privateKey.Exponent.ToByteArrayUnsigned(),
                    P = privateKey.P.ToByteArrayUnsigned(),
                    Q = privateKey.Q.ToByteArrayUnsigned(),
                    DP = privateKey.DP.ToByteArrayUnsigned(),
                    DQ = privateKey.DQ.ToByteArrayUnsigned(),
                    InverseQ = privateKey.QInv.ToByteArrayUnsigned()
                };

                rsa.ImportParameters(parameters);
            }
        }

        private static string ExportPublicKeyPemBouncyCastle(RSA rsa)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters: false);

            var publicKey = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(
                isPrivate: false,
                new Org.BouncyCastle.Math.BigInteger(1, parameters.Modulus),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.Exponent));

            var publicKeyInfo = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(publicKey);

            using (var writer = new System.IO.StringWriter())
            {
                var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(writer);
                pemWriter.WriteObject(publicKeyInfo);
                pemWriter.Writer.Flush();
                return writer.ToString();
            }
        }

        private static byte[] ExportSubjectPublicKeyInfoBouncyCastle(RSA rsa)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters: false);

            var publicKey = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(
                isPrivate: false,
                new Org.BouncyCastle.Math.BigInteger(1, parameters.Modulus),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.Exponent));

            var publicKeyInfo = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(publicKey);

            return publicKeyInfo.GetDerEncoded();
        }

        private static string ExportPrivateKeyPemBouncyCastle(RSA rsa)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters: true);

            var privateKey = new Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters(
                new Org.BouncyCastle.Math.BigInteger(1, parameters.Modulus),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.Exponent),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.D),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.P),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.Q),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.DP),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.DQ),
                new Org.BouncyCastle.Math.BigInteger(1, parameters.InverseQ));

            var privateKeyInfo = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory
                .CreatePrivateKeyInfo(privateKey);

            using (var writer = new System.IO.StringWriter())
            {
                var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(writer);
                pemWriter.WriteObject(privateKeyInfo);
                pemWriter.Writer.Flush();
                return writer.ToString();
            }
        }
#endif
    }
}
