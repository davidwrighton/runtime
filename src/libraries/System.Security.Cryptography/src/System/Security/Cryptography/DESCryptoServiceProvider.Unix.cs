// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    [Obsolete(Obsoletions.DerivedCryptographicTypesMessage, DiagnosticId = Obsoletions.DerivedCryptographicTypesDiagId, UrlFormat = Obsoletions.SharedUrlFormat)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class DESCryptoServiceProvider : DES
    {
        private readonly DES _impl;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5351", Justification = "This is the implementation of DESCryptoServiceProvider")]
        public DESCryptoServiceProvider() : base()
        {
            // This class wraps DES
            _impl = DES.Create();
        }

        public override int BlockSize
        {
            get { return _impl.BlockSize; }
            set { _impl.BlockSize = value; }
        }

        public override ICryptoTransform CreateDecryptor() => _impl.CreateDecryptor();
        public override ICryptoTransform CreateEncryptor() => _impl.CreateEncryptor();

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV) =>
            _impl.CreateEncryptor(rgbKey, CapiHelper.TrimLargeIV(rgbIV, BlockSize));

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV) =>
            _impl.CreateDecryptor(rgbKey, CapiHelper.TrimLargeIV(rgbIV, BlockSize));

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _impl.Dispose();
                base.Dispose(disposing);
            }
        }

        public override int FeedbackSize
        {
            get { return _impl.FeedbackSize; }
            set { _impl.FeedbackSize = value; }
        }

        public override void GenerateIV() => _impl.GenerateIV();
        public override void GenerateKey() => _impl.GenerateKey();

        public override byte[] IV
        {
            get { return _impl.IV; }
            set { _impl.IV = value; }
        }

        public override byte[] Key
        {
            get { return _impl.Key; }
            set { _impl.Key = value; }
        }

        public override int KeySize
        {
            get { return _impl.KeySize; }
            set { _impl.KeySize = value; }
        }

        public override KeySizes[] LegalBlockSizes => _impl.LegalBlockSizes;
        public override KeySizes[] LegalKeySizes => _impl.LegalKeySizes;

        public override CipherMode Mode
        {
            get { return _impl.Mode; }
            set { _impl.Mode = value; }
        }

        public override PaddingMode Padding
        {
            get { return _impl.Padding; }
            set { _impl.Padding = value; }
        }

        protected override void SetKeyCore(ReadOnlySpan<byte> key) => _impl.SetKey(key);
    }
}
