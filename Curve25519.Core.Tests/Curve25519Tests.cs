using System;
using P3.Elliptic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Curve25519.Core.Tests
{
    [TestClass]
    public class Curve25519Tests
    {
        [TestMethod]
        public void DiffieHellmanSuccess()
        {
            Random random = TestHelpers.CreateSemiRandomGenerator(); // not truly random in case we need to reproduce test values

            for (int i = 0; i < 1000; i++)
            {
                byte[] alicePrivate = P3.Elliptic.Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                byte[] alicePublic = P3.Elliptic.Curve25519.GetPublicKey(alicePrivate);

                byte[] bobPrivate = P3.Elliptic.Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                byte[] bobPublic = P3.Elliptic.Curve25519.GetPublicKey(bobPrivate);

                byte[] aliceShared = P3.Elliptic.Curve25519.GetSharedSecret(alicePrivate, bobPublic);
                byte[] bobShared = P3.Elliptic.Curve25519.GetSharedSecret(bobPrivate, alicePublic);

                NUnit.Framework.Assert.AreEqual(aliceShared, bobShared);
            }
        }

        [TestMethod]
        public void DiffieHellmanFail()
        {
            Random random = TestHelpers.CreateSemiRandomGenerator();
            for (int i = 0; i < 1000; i++)
            {
                byte[] alicePrivate = P3.Elliptic.Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                byte[] alicePublic = P3.Elliptic.Curve25519.GetPublicKey(alicePrivate);

                byte[] bobPrivate = P3.Elliptic.Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                byte[] bobPublic = P3.Elliptic.Curve25519.GetPublicKey(bobPrivate);

                byte[] aliceShared = P3.Elliptic.Curve25519.GetSharedSecret(alicePrivate, bobPublic);

                byte[] alicePublicWithBitToggled = TestHelpers.ToggleBitInKey(alicePublic, random);
                byte[] bobShared = P3.Elliptic.Curve25519.GetSharedSecret(bobPrivate, alicePublicWithBitToggled);

                NUnit.Framework.Assert.AreNotEqual(aliceShared, bobShared);
            }
        }
    }
}

