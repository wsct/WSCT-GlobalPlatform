using System;
using System.Collections.Generic;
using System.Text;

namespace WSCT.GlobalPlatform.Security.Scp03;

using System;
using System.Linq;
using System.Security.Cryptography;

public static class AesCmac
{
    public static byte[] Compute(byte[] key, byte[] message)
    {
        byte[] k1, k2;
        GenerateSubKeys(key, out k1, out k2);

        int blockCount = Math.Max(1, (message.Length + 15) / 16);
        bool lastBlockComplete = message.Length != 0 && message.Length % 16 == 0;

        byte[] lastBlock = new byte[16];

        int lastOffset = (blockCount - 1) * 16;
        int lastLength = message.Length - lastOffset;

        if (lastBlockComplete)
        {
            Array.Copy(message, lastOffset, lastBlock, 0, 16);
            Xor(lastBlock, k1);
        }
        else
        {
            if (lastLength > 0)
                Array.Copy(message, lastOffset, lastBlock, 0, lastLength);

            lastBlock[lastLength] = 0x80; // padding CMAC
            Xor(lastBlock, k2);
        }

        byte[] x = new byte[16];

        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using ICryptoTransform encryptor = aes.CreateEncryptor();

        for (int i = 0; i < blockCount - 1; i++)
        {
            byte[] block = new byte[16];
            Array.Copy(message, i * 16, block, 0, 16);

            Xor(block, x);
            x = encryptor.TransformFinalBlock(block, 0, 16);
        }

        Xor(lastBlock, x);
        return encryptor.TransformFinalBlock(lastBlock, 0, 16);
    }

    private static void GenerateSubKeys(byte[] key, out byte[] k1, out byte[] k2)
    {
        byte[] l = new byte[16];

        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using ICryptoTransform encryptor = aes.CreateEncryptor();

        l = encryptor.TransformFinalBlock(new byte[16], 0, 16);

        k1 = ShiftLeft(l);
        if ((l[0] & 0x80) != 0)
            k1[15] ^= 0x87;

        k2 = ShiftLeft(k1);
        if ((k1[0] & 0x80) != 0)
            k2[15] ^= 0x87;
    }

    private static byte[] ShiftLeft(byte[] input)
    {
        byte[] output = new byte[16];
        byte carry = 0;

        for (int i = 15; i >= 0; i--)
        {
            output[i] = (byte)((input[i] << 1) | carry);
            carry = (byte)(input[i] >> 7);
        }

        return output;
    }

    private static void Xor(byte[] a, byte[] b)
    {
        for (int i = 0; i < 16; i++)
            a[i] ^= b[i];
    }
}
