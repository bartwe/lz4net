#region license

/*
Copyright (c) 2013, Milosz Krajewski
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions
  and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions
  and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#endregion

using System;

namespace LZ4pn {
    /// <summary>Unsafe LZ4 codec.</summary>
    public static partial class LZ4Codec {
        /// <summary>Copies block of memory.</summary>
        /// <param name="src">The source.</param>
        /// <param name="dst">The destination.</param>
        /// <param name="len">The length (in bytes).</param>
        static unsafe void BlockCopy(byte* src, byte* dst, int len) {
            while (len >= 8) {
                *(ulong*)dst = *(ulong*)src;
                dst += 8;
                src += 8;
                len -= 8;
            }
            if (len >= 4) {
                *(uint*)dst = *(uint*)src;
                dst += 4;
                src += 4;
                len -= 4;
            }
            if (len >= 2) {
                *(ushort*)dst = *(ushort*)src;
                dst += 2;
                src += 2;
                len -= 2;
            }
            if (len >= 1) {
                *dst = *src; /* d++; s++; l--; */
            }
        }

        /// <summary>Copies block of memory.</summary>
        /// <param name="dst">The destination.</param>
        /// <param name="len">The length (in bytes).</param>
        /// <param name="val">The value.</param>
        static unsafe void BlockFill(byte* dst, int len, byte val) {
            if (len >= 8) {
                ulong mask = val;
                mask |= mask << 8;
                mask |= mask << 16;
                mask |= mask << 32;
                do {
                    *(ulong*)dst = mask;
                    dst += 8;
                    len -= 8;
                } while (len >= 8);
            }

            while (len-- > 0)
                *dst++ = val;
        }

        #region Encode32

        public unsafe class LZ4EncodeContext {
            //normal
            internal ushort[] HASH64K = new ushort[HASH64K_TABLESIZE];
            internal byte*[] HASH = new byte*[HASH_TABLESIZE];

            //hc
            internal byte* src_base;
            internal byte* nextToUpdate;
            internal int[] hashTable = new int[HASHHC_TABLESIZE];
            internal ushort[] chainTable = new ushort[MAXD];

            public void Reset() {
                Array.Clear(HASH64K, 0, HASH64K.Length);
                Array.Clear(HASH, 0, HASH.Length);

                src_base = (byte*)0;
                nextToUpdate = (byte*)0;
                Array.Clear(hashTable, 0, hashTable.Length);
                Array.Clear(chainTable, 0, chainTable.Length);
            }
        }


        /// <summary>Encodes the specified input.</summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="inputLength">Length of the input.</param>
        /// <param name="outputLength">Length of the output.</param>
        /// <returns>Number of bytes written.</returns>
        public static unsafe int Encode32(LZ4EncodeContext lz4EncodeContext,
            byte* input,
            byte* output,
            int inputLength,
            int outputLength) {
            int result;
            if (inputLength < LZ4_64KLIMIT) {
                var hashTable = lz4EncodeContext.HASH64K;
                fixed (ushort* h = &hashTable[0]) {
                    result = LZ4_compress64kCtx_32(h, input, output, inputLength, outputLength);
                }
            }
            else {
                var hashTable = lz4EncodeContext.HASH;
                fixed (byte** h = &hashTable[0]) {
                    result = LZ4_compressCtx_32(h, input, output, inputLength, outputLength);
                }
            }
            lz4EncodeContext.Reset();
            return result;
        }

        /// <summary>Encodes the specified input.</summary>
        /// <param name="input">The input.</param>
        /// <param name="inputOffset">The input offset.</param>
        /// <param name="inputLength">Length of the input.</param>
        /// <param name="output">The output.</param>
        /// <param name="outputOffset">The output offset.</param>
        /// <param name="outputLength">Length of the output.</param>
        /// <returns>Number of bytes written.</returns>
        public static unsafe int Encode32(
            LZ4EncodeContext lz4EncodeContext,
            byte[] input,
            int inputOffset,
            int inputLength,
            byte[] output,
            int outputOffset,
            int outputLength) {
            CheckArguments(
                input, inputOffset, ref inputLength,
                output, outputOffset, ref outputLength);

            if (outputLength == 0)
                return 0;

            fixed (byte* inputPtr = &input[inputOffset])
            fixed (byte* outputPtr = &output[outputOffset]) {
                return Encode32(lz4EncodeContext, inputPtr, outputPtr, inputLength, outputLength);
            }
        }

        #endregion

        #region Decode32

        /// <summary>Decodes the specified input.</summary>
        /// <param name="input">The input.</param>
        /// <param name="inputLength">Length of the input.</param>
        /// <param name="output">The output.</param>
        /// <param name="outputLength">Length of the output.</param>
        /// <param name="knownOutputLength">Set it to <c>true</c> if output length is known.</param>
        /// <returns>Number of bytes written.</returns>
        public static unsafe int Decode32(
            byte* input,
            int inputLength,
            byte* output,
            int outputLength,
            bool knownOutputLength) {
            if (knownOutputLength) {
                var length = LZ4_uncompress_32(input, output, outputLength);
                if (length != inputLength)
                    throw new ArgumentException("LZ4 block is corrupted, or invalid length has been given.");
                return outputLength;
            }
            else {
                var length = LZ4_uncompress_unknownOutputSize_32(input, output, inputLength, outputLength);
                if (length < 0)
                    throw new ArgumentException("LZ4 block is corrupted, or invalid length has been given.");
                return length;
            }
        }

        /// <summary>Decodes the specified input.</summary>
        /// <param name="input">The input.</param>
        /// <param name="inputOffset">The input offset.</param>
        /// <param name="inputLength">Length of the input.</param>
        /// <param name="output">The output.</param>
        /// <param name="outputOffset">The output offset.</param>
        /// <param name="outputLength">Length of the output.</param>
        /// <param name="knownOutputLength">Set it to <c>true</c> if output length is known.</param>
        /// <returns>Number of bytes written.</returns>
        public static unsafe int Decode32(
            byte[] input,
            int inputOffset,
            int inputLength,
            byte[] output,
            int outputOffset,
            int outputLength,
            bool knownOutputLength) {
            CheckArguments(
                input, inputOffset, ref inputLength,
                output, outputOffset, ref outputLength);

            if (outputLength == 0)
                return 0;

            fixed (byte* inputPtr = &input[inputOffset])
            fixed (byte* outputPtr = &output[outputOffset]) {
                return Decode32(inputPtr, inputLength, outputPtr, outputLength, knownOutputLength);
            }
        }

        #endregion

        #region HC utilities

        // ReSharper disable InconsistentNaming

        static unsafe LZ4EncodeContext LZ4HC_Create(LZ4EncodeContext hc4, byte* src) {
            fixed (ushort* ct = &hc4.chainTable[0]) {
                BlockFill((byte*)ct, MAXD * sizeof(ushort), 0xFF);
            }

            hc4.src_base = src;
            hc4.nextToUpdate = src + 1;

            return hc4;
        }

        #endregion

        #region Encode32HC

        static unsafe int LZ4_compressHC_32(LZ4EncodeContext hc4, byte* input, byte* output, int inputLength, int outputLength) {
            return LZ4_compressHCCtx_32(LZ4HC_Create(hc4, input), input, output, inputLength, outputLength);
        }

        /// <summary>Encodes the specified input using HC codec.</summary>
        /// <param name="input">The input.</param>
        /// <param name="inputOffset">The input offset.</param>
        /// <param name="inputLength">Length of the input.</param>
        /// <param name="output">The output.</param>
        /// <param name="outputOffset">The output offset.</param>
        /// <param name="outputLength">Length of the output.</param>
        /// <returns>Number of bytes written. NOTE: when output buffer is too small it returns negative value.</returns>
        public static unsafe int Encode32HC(
            LZ4EncodeContext hc4,
            byte[] input,
            int inputOffset,
            int inputLength,
            byte[] output,
            int outputOffset,
            int outputLength) {
            if (inputLength == 0)
                return 0;

            CheckArguments(
                input, inputOffset, ref inputLength,
                output, outputOffset, ref outputLength);

            fixed (byte* inputPtr = &input[inputOffset])
            fixed (byte* outputPtr = &output[outputOffset]) {
                var length = LZ4_compressHC_32(hc4, inputPtr, outputPtr, inputLength, outputLength);
                hc4.Reset();
                // NOTE: there is a potential problem here as original implementation returns 0 not -1
                return length <= 0 ? -1 : length;
            }
        }

        public static unsafe int Encode32HC(
            LZ4EncodeContext hc4,
            byte* inputPtr,
            byte* outputPtr,
            int inputLength,
            int outputLength) {
            if (inputLength == 0)
                return 0;

            var length = LZ4_compressHC_32(hc4, inputPtr, outputPtr, inputLength, outputLength);
            hc4.Reset();
            // NOTE: there is a potential problem here as original implementation returns 0 not -1

            return length <= 0 ? -1 : length;
        }

        #endregion
    }
}
