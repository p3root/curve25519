using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Curve25519.Core.Tests
{
    [TestClass]
    public class Curve25519TimingTests
    {
        [TestMethod]
        public void Curve25519_GetPublicKey()
        {
            List<long> ticks = new List<long>();
            for (int i = 0; i < 255; i++)
            {
                Stopwatch stopwatch = Stopwatch.StartNew();

                byte[] privateKey = P3.Elliptic.Curve25519.ClampPrivateKey(TestHelpers.GetUniformBytes((byte)i, 32));

                for (int j = 0; j < 1000; j++)
                {
                    byte[] publicKey = P3.Elliptic.Curve25519.GetPublicKey(privateKey);
                }

                ticks.Add(stopwatch.ElapsedMilliseconds);
            }

            long min = long.MaxValue;
            long max = long.MinValue;
            for (int i = 0; i < ticks.Count; i++)
            {
                if (ticks[i] < min) min = ticks[i];
                if (ticks[i] > max) max = ticks[i];
            }

            NUnit.Framework.Assert.Inconclusive("Min: {0}, Max: {1}", min, max);
        }
    }
}
