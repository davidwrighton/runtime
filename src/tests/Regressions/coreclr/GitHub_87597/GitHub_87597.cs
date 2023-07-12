// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;

// Class init for devirtualized calls triggered by PGO does not behave correctly
// This test requires a class initializer on both the interface and on the type in use
// and requires that type to be generic

public class GitHub_87597
{
    public interface IFace
    {
        static IFace() {}
        void Method();
    }

    public class GenericType<T> : IFace
    {
        static GenericType()
        {
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Method()
        {
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void TestL1(IFace iface)
    {
        iface.Method();
    }

    public static int Main()
    {
        for (int i = 0; i < 100; i++)
        {
            System.Threading.Thread.Sleep(16);
            TestL1(new GenericType<string>());
        }

        return 100;
    }
}
