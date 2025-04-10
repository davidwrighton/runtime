// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System
{
    // Note that we make a T[] (single-dimensional w/ zero as the lower bound) implement both
    // IList<U> and IReadOnlyList<U>, where T : U dynamically.  See the SZArrayHelper class for details.
    public abstract partial class Array : ICloneable, IList, IStructuralComparable, IStructuralEquatable
    {
        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "Array_CreateInstance")]
        private static unsafe partial void InternalCreate(QCallTypeHandle type, int rank, int* pLengths, int* pLowerBounds,
            [MarshalAs(UnmanagedType.Bool)] bool fromArrayType, ObjectHandleOnStack retArray);

        private static unsafe Array InternalCreate(RuntimeType elementType, int rank, int* pLengths, int* pLowerBounds)
        {
            Array? retArray = null;
            InternalCreate(new QCallTypeHandle(ref elementType), rank, pLengths, pLowerBounds,
                fromArrayType: false, ObjectHandleOnStack.Create(ref retArray));
            return retArray!;
        }

        private static unsafe Array InternalCreateFromArrayType(RuntimeType arrayType, int rank, int* pLengths, int* pLowerBounds)
        {
            Array? retArray = null;
            InternalCreate(new QCallTypeHandle(ref arrayType), rank, pLengths, pLowerBounds,
                fromArrayType: true, ObjectHandleOnStack.Create(ref retArray));
            return retArray!;
        }

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "Array_CreateInstanceMDArray")]
        private static unsafe partial void CreateInstanceMDArray(nint typeHandle, uint dwNumArgs, void* pArgList, ObjectHandleOnStack retArray);

        // implementation of CORINFO_HELP_NEW_MDARR and CORINFO_HELP_NEW_MDARR_RARE.
        [StackTraceHidden]
        [DebuggerStepThrough]
        [DebuggerHidden]
        internal static unsafe object CreateInstanceMDArray(nint typeHandle, uint dwNumArgs, void* pArgList)
        {
            Array? arr = null;
            CreateInstanceMDArray(typeHandle, dwNumArgs, pArgList, ObjectHandleOnStack.Create(ref arr));
            return arr!;
        }

        private static unsafe void CopyImpl(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length, bool reliable)
        {
            if (sourceArray == null)
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.sourceArray);
            if (destinationArray == null)
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.destinationArray);

            if (sourceArray.GetType() != destinationArray.GetType() && sourceArray.Rank != destinationArray.Rank)
                throw new RankException(SR.Rank_MustMatch);

            ArgumentOutOfRangeException.ThrowIfNegative(length);

            int srcLB = sourceArray.GetLowerBound(0);
            ArgumentOutOfRangeException.ThrowIfLessThan(sourceIndex, srcLB);
            ArgumentOutOfRangeException.ThrowIfNegative(sourceIndex - srcLB, nameof(sourceIndex));
            sourceIndex -= srcLB;

            int dstLB = destinationArray.GetLowerBound(0);
            ArgumentOutOfRangeException.ThrowIfLessThan(destinationIndex, dstLB);
            ArgumentOutOfRangeException.ThrowIfNegative(destinationIndex - dstLB, nameof(destinationIndex));
            destinationIndex -= dstLB;

            if ((uint)(sourceIndex + length) > sourceArray.NativeLength)
                throw new ArgumentException(SR.Arg_LongerThanSrcArray, nameof(sourceArray));
            if ((uint)(destinationIndex + length) > destinationArray.NativeLength)
                throw new ArgumentException(SR.Arg_LongerThanDestArray, nameof(destinationArray));

            ArrayAssignType assignType = ArrayAssignType.WrongType;

            if (sourceArray.GetType() == destinationArray.GetType()
                || (assignType = CanAssignArrayType(sourceArray, destinationArray)) == ArrayAssignType.SimpleCopy)
            {
                MethodTable* pMT = RuntimeHelpers.GetMethodTable(sourceArray);

                nuint elementSize = (nuint)pMT->ComponentSize;
                nuint byteCount = (uint)length * elementSize;
                ref byte src = ref Unsafe.AddByteOffset(ref MemoryMarshal.GetArrayDataReference(sourceArray), (uint)sourceIndex * elementSize);
                ref byte dst = ref Unsafe.AddByteOffset(ref MemoryMarshal.GetArrayDataReference(destinationArray), (uint)destinationIndex * elementSize);

                if (pMT->ContainsGCPointers)
                    Buffer.BulkMoveWithWriteBarrier(ref dst, ref src, byteCount);
                else
                    SpanHelpers.Memmove(ref dst, ref src, byteCount);

                // GC.KeepAlive(sourceArray) not required. pMT kept alive via sourceArray
                return;
            }

            // If we were called from Array.ConstrainedCopy, ensure that the array copy
            // is guaranteed to succeed.
            if (reliable)
                throw new ArrayTypeMismatchException(SR.ArrayTypeMismatch_ConstrainedCopy);

            // Rare
            CopySlow(sourceArray, sourceIndex, destinationArray, destinationIndex, length, assignType);
        }

        private static CorElementType GetNormalizedIntegralArrayElementType(CorElementType elementType)
        {
            Debug.Assert(elementType.IsPrimitiveType());

            // Array Primitive types such as E_T_I4 and E_T_U4 are interchangeable
            // Enums with interchangeable underlying types are interchangeable
            // BOOL is NOT interchangeable with I1/U1, neither CHAR -- with I2/U2

            // U1/U2/U4/U8/U
            int shift = (0b0010_0000_0000_0000_1010_1010_0000 >> (int)elementType) & 1;
            return (CorElementType)((int)elementType - shift);
        }

        // Reliability-wise, this method will either possibly corrupt your
        // instance & might fail when called from within a CER, or if the
        // reliable flag is true, it will either always succeed or always
        // throw an exception with no side effects.
        private static void CopySlow(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length, ArrayAssignType assignType)
        {
            Debug.Assert(sourceArray.Rank == destinationArray.Rank);

            if (assignType == ArrayAssignType.WrongType)
                throw new ArrayTypeMismatchException(SR.ArrayTypeMismatch_CantAssignType);

            if (length > 0)
            {
                switch (assignType)
                {
                    case ArrayAssignType.UnboxValueClass:
                        CopyImplUnBoxEachElement(sourceArray, sourceIndex, destinationArray, destinationIndex, length);
                        break;

                    case ArrayAssignType.BoxValueClassOrPrimitive:
                        CopyImplBoxEachElement(sourceArray, sourceIndex, destinationArray, destinationIndex, length);
                        break;

                    case ArrayAssignType.MustCast:
                        CopyImplCastCheckEachElement(sourceArray, sourceIndex, destinationArray, destinationIndex, length);
                        break;

                    case ArrayAssignType.PrimitiveWiden:
                        CopyImplPrimitiveWiden(sourceArray, sourceIndex, destinationArray, destinationIndex, length);
                        break;

                    default:
                        Debug.Fail("Fell through switch in Array.Copy!");
                        break;
                }
            }
        }

        private enum ArrayAssignType
        {
            SimpleCopy,
            WrongType,
            MustCast,
            BoxValueClassOrPrimitive,
            UnboxValueClass,
            PrimitiveWiden,
        }

        private static unsafe ArrayAssignType CanAssignArrayType(Array sourceArray, Array destinationArray)
        {
            TypeHandle srcTH = RuntimeHelpers.GetMethodTable(sourceArray)->GetArrayElementTypeHandle();
            TypeHandle destTH = RuntimeHelpers.GetMethodTable(destinationArray)->GetArrayElementTypeHandle();

            if (TypeHandle.AreSameType(srcTH, destTH)) // This check kicks for different array kind or dimensions
                return ArrayAssignType.SimpleCopy;

            if (!srcTH.IsTypeDesc && !destTH.IsTypeDesc)
            {
                MethodTable* pMTsrc = srcTH.AsMethodTable();
                MethodTable* pMTdest = destTH.AsMethodTable();

                // Value class boxing
                if (pMTsrc->IsValueType && !pMTdest->IsValueType)
                {
                    if (srcTH.CanCastTo(destTH))
                        return ArrayAssignType.BoxValueClassOrPrimitive;
                    else
                        return ArrayAssignType.WrongType;
                }

                // Value class unboxing.
                if (!pMTsrc->IsValueType && pMTdest->IsValueType)
                {
                    if (srcTH.CanCastTo(destTH))
                        return ArrayAssignType.UnboxValueClass;
                    else if (destTH.CanCastTo(srcTH))   // V extends IV. Copying from IV to V, or Object to V.
                        return ArrayAssignType.UnboxValueClass;
                    else
                        return ArrayAssignType.WrongType;
                }

                // Copying primitives from one type to another
                if (pMTsrc->IsPrimitive && pMTdest->IsPrimitive)
                {
                    CorElementType srcElType = pMTsrc->GetPrimitiveCorElementType();
                    CorElementType destElType = pMTdest->GetPrimitiveCorElementType();

                    if (GetNormalizedIntegralArrayElementType(srcElType) == GetNormalizedIntegralArrayElementType(destElType))
                        return ArrayAssignType.SimpleCopy;
                    else if (RuntimeHelpers.CanPrimitiveWiden(srcElType, destElType))
                        return ArrayAssignType.PrimitiveWiden;
                    else
                        return ArrayAssignType.WrongType;
                }

                // src Object extends dest
                if (srcTH.CanCastTo(destTH))
                    return ArrayAssignType.SimpleCopy;

                // dest Object extends src
                if (destTH.CanCastTo(srcTH))
                    return ArrayAssignType.MustCast;

                // class X extends/implements src and implements dest.
                if (pMTdest->IsInterface)
                    return ArrayAssignType.MustCast;

                // class X implements src and extends/implements dest
                if (pMTsrc->IsInterface)
                    return ArrayAssignType.MustCast;
            }
            else
            {
                // Only pointers are valid for TypeDesc in array element

                // Compatible pointers
                if (srcTH.CanCastTo(destTH))
                    return ArrayAssignType.SimpleCopy;
            }

            return ArrayAssignType.WrongType;
        }

        // Unboxes from an Object[] into a value class or primitive array.
        private static unsafe void CopyImplUnBoxEachElement(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length)
        {
            MethodTable* pDestArrayMT = RuntimeHelpers.GetMethodTable(destinationArray);
            TypeHandle destTH = pDestArrayMT->GetArrayElementTypeHandle();

            Debug.Assert(!destTH.IsTypeDesc && destTH.AsMethodTable()->IsValueType);
            Debug.Assert(!RuntimeHelpers.GetMethodTable(sourceArray)->GetArrayElementTypeHandle().AsMethodTable()->IsValueType);

            MethodTable* pDestMT = destTH.AsMethodTable();
            nuint destSize = pDestArrayMT->ComponentSize;
            ref object? srcData = ref Unsafe.Add(ref Unsafe.As<byte, object?>(ref MemoryMarshal.GetArrayDataReference(sourceArray)), sourceIndex);
            ref byte data = ref Unsafe.AddByteOffset(ref MemoryMarshal.GetArrayDataReference(destinationArray), (nuint)destinationIndex * destSize);

            for (int i = 0; i < length; i++)
            {
                object? obj = Unsafe.Add(ref srcData, i);

                // Now that we have retrieved the element, we are no longer subject to race
                // conditions from another array mutator.

                ref byte dest = ref Unsafe.AddByteOffset(ref data, (nuint)i * destSize);

                if (pDestMT->IsNullable)
                {
                    CastHelpers.Unbox_Nullable(ref dest, pDestMT, obj);
                }
                else if (obj is null || RuntimeHelpers.GetMethodTable(obj) != pDestMT)
                {
                    throw new InvalidCastException(SR.InvalidCast_DownCastArrayElement);
                }
                else if (pDestMT->ContainsGCPointers)
                {
                    Buffer.BulkMoveWithWriteBarrier(ref dest, ref obj.GetRawData(), destSize);
                }
                else
                {
                    SpanHelpers.Memmove(ref dest, ref obj.GetRawData(), destSize);
                }
            }
        }

        // Will box each element in an array of value classes or primitives into an array of Objects.
        private static unsafe void CopyImplBoxEachElement(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length)
        {
            MethodTable* pSrcArrayMT = RuntimeHelpers.GetMethodTable(sourceArray);
            TypeHandle srcTH = pSrcArrayMT->GetArrayElementTypeHandle();

            Debug.Assert(!srcTH.IsTypeDesc && srcTH.AsMethodTable()->IsValueType);
            Debug.Assert(!RuntimeHelpers.GetMethodTable(destinationArray)->GetArrayElementTypeHandle().AsMethodTable()->IsValueType);

            MethodTable* pSrcMT = srcTH.AsMethodTable();

            nuint srcSize = pSrcArrayMT->ComponentSize;
            ref byte data = ref Unsafe.AddByteOffset(ref MemoryMarshal.GetArrayDataReference(sourceArray), (nuint)sourceIndex * srcSize);
            ref object? destData = ref Unsafe.Add(ref Unsafe.As<byte, object?>(ref MemoryMarshal.GetArrayDataReference(destinationArray)), destinationIndex);

            for (int i = 0; i < length; i++)
            {
                object? obj = RuntimeHelpers.Box(pSrcMT, ref Unsafe.AddByteOffset(ref data, (nuint)i * srcSize));
                Unsafe.Add(ref destData, i) = obj;
            }
        }

        // Casts and assigns each element of src array to the dest array type.
        private static unsafe void CopyImplCastCheckEachElement(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length)
        {
            void* destTH = RuntimeHelpers.GetMethodTable(destinationArray)->ElementType;

            ref object? srcData = ref Unsafe.Add(ref Unsafe.As<byte, object?>(ref MemoryMarshal.GetArrayDataReference(sourceArray)), sourceIndex);
            ref object? destData = ref Unsafe.Add(ref Unsafe.As<byte, object?>(ref MemoryMarshal.GetArrayDataReference(destinationArray)), destinationIndex);

            for (int i = 0; i < length; i++)
            {
                object? obj = Unsafe.Add(ref srcData, i);

                // Now that we have grabbed obj, we are no longer subject to races from another
                // mutator thread.

                Unsafe.Add(ref destData, i) = CastHelpers.ChkCastAny(destTH, obj);
            }
        }

        // Widen primitive types to another primitive type.
        private static unsafe void CopyImplPrimitiveWiden(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length)
        {
            // Get appropriate sizes, which requires method tables.

            CorElementType srcElType = sourceArray.GetCorElementTypeOfElementType();
            CorElementType destElType = destinationArray.GetCorElementTypeOfElementType();

            nuint srcElSize = RuntimeHelpers.GetMethodTable(sourceArray)->ComponentSize;
            nuint destElSize = RuntimeHelpers.GetMethodTable(destinationArray)->ComponentSize;

            ref byte srcData = ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(sourceArray), (nuint)sourceIndex * srcElSize);
            ref byte data = ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(destinationArray), (nuint)destinationIndex * destElSize);

            for (int i = 0; i < length; i++)
            {
                InvokeUtils.PrimitiveWiden(ref srcData, ref data, srcElType, destElType);
                srcData = ref Unsafe.AddByteOffset(ref srcData, srcElSize);
                data = ref Unsafe.AddByteOffset(ref data, destElSize);
            }
        }

        // Provides a strong exception guarantee - either it succeeds, or
        // it throws an exception with no side effects.  The arrays must be
        // compatible array types based on the array element type - this
        // method does not support casting, boxing, or primitive widening.
        // It will up-cast, assuming the array types are correct.
        public static void ConstrainedCopy(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length)
        {
            CopyImpl(sourceArray, sourceIndex, destinationArray, destinationIndex, length, reliable: true);
        }

        /// <summary>
        /// Clears the contents of an array.
        /// </summary>
        /// <param name="array">The array to clear.</param>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is null.</exception>
        public static unsafe void Clear(Array array)
        {
            if (array == null)
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.array);

            MethodTable* pMT = RuntimeHelpers.GetMethodTable(array);
            nuint totalByteLength = pMT->ComponentSize * array.NativeLength;
            ref byte pStart = ref MemoryMarshal.GetArrayDataReference(array);

            if (!pMT->ContainsGCPointers)
            {
                SpanHelpers.ClearWithoutReferences(ref pStart, totalByteLength);
            }
            else
            {
                Debug.Assert(totalByteLength % (nuint)sizeof(IntPtr) == 0);
                SpanHelpers.ClearWithReferences(ref Unsafe.As<byte, IntPtr>(ref pStart), totalByteLength / (nuint)sizeof(IntPtr));
            }

            // GC.KeepAlive(array) not required. pMT kept alive via `pStart`
        }

        // Sets length elements in array to 0 (or null for Object arrays), starting
        // at index.
        //
        public static unsafe void Clear(Array array, int index, int length)
        {
            if (array == null)
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.array);

            ref byte p = ref Unsafe.As<RawArrayData>(array).Data;
            int lowerBound = 0;

            MethodTable* pMT = RuntimeHelpers.GetMethodTable(array);
            if (pMT->IsMultiDimensionalArray)
            {
                int rank = pMT->MultiDimensionalArrayRank;
                lowerBound = Unsafe.Add(ref Unsafe.As<byte, int>(ref p), rank);
                p = ref Unsafe.Add(ref p, 2 * sizeof(int) * rank); // skip the bounds
            }

            int offset = index - lowerBound;

            if (index < lowerBound || offset < 0 || length < 0 || (uint)(offset + length) > array.NativeLength)
                ThrowHelper.ThrowIndexOutOfRangeException();

            nuint elementSize = pMT->ComponentSize;

            ref byte ptr = ref Unsafe.AddByteOffset(ref p, (uint)offset * elementSize);
            nuint byteLength = (uint)length * elementSize;

            if (pMT->ContainsGCPointers)
                SpanHelpers.ClearWithReferences(ref Unsafe.As<byte, IntPtr>(ref ptr), byteLength / (uint)sizeof(IntPtr));
            else
                SpanHelpers.ClearWithoutReferences(ref ptr, byteLength);

            // GC.KeepAlive(array) not required. pMT kept alive via `ptr`
        }

        private unsafe nint GetFlattenedIndex(int rawIndex)
        {
            // Checked by the caller
            Debug.Assert(Rank == 1);

            if (RuntimeHelpers.GetMethodTable(this)->IsMultiDimensionalArray)
            {
                ref int bounds = ref RuntimeHelpers.GetMultiDimensionalArrayBounds(this);
                rawIndex -= Unsafe.Add(ref bounds, 1);
            }

            if ((uint)rawIndex >= (uint)LongLength)
                ThrowHelper.ThrowIndexOutOfRangeException();
            return rawIndex;
        }

        private unsafe nint GetFlattenedIndex(ReadOnlySpan<int> indices)
        {
            // Checked by the caller
            Debug.Assert(indices.Length == Rank);

            if (RuntimeHelpers.GetMethodTable(this)->IsMultiDimensionalArray)
            {
                ref int bounds = ref RuntimeHelpers.GetMultiDimensionalArrayBounds(this);
                nint flattenedIndex = 0;
                for (int i = 0; i < indices.Length; i++)
                {
                    int index = indices[i] - Unsafe.Add(ref bounds, indices.Length + i);
                    int length = Unsafe.Add(ref bounds, i);
                    if ((uint)index >= (uint)length)
                        ThrowHelper.ThrowIndexOutOfRangeException();
                    flattenedIndex = (length * flattenedIndex) + index;
                }
                Debug.Assert((nuint)flattenedIndex < (nuint)LongLength);
                return flattenedIndex;
            }
            else
            {
                int index = indices[0];
                if ((uint)index >= (uint)LongLength)
                    ThrowHelper.ThrowIndexOutOfRangeException();
                return index;
            }
        }

        internal unsafe object? InternalGetValue(nint flattenedIndex)
        {
            MethodTable* pMethodTable = RuntimeHelpers.GetMethodTable(this);

            TypeHandle arrayElementTypeHandle = pMethodTable->GetArrayElementTypeHandle();

            // Legacy behavior (none of the cases where the element type is a type descriptor are supported).
            // That is, this happens when the element type is either a pointer or a function pointer type.
            if (arrayElementTypeHandle.IsTypeDesc)
            {
                ThrowHelper.ThrowNotSupportedException(ExceptionResource.Arg_TypeNotSupported);
            }

            Debug.Assert((nuint)flattenedIndex < NativeLength);

            ref byte arrayDataRef = ref MemoryMarshal.GetArrayDataReference(this);
            object? result;

            MethodTable* pElementMethodTable = arrayElementTypeHandle.AsMethodTable();

            if (pElementMethodTable->IsValueType)
            {
                // If the element is a value type, shift to the right offset using the component size, then box
                ref byte offsetDataRef = ref Unsafe.Add(ref arrayDataRef, flattenedIndex * pMethodTable->ComponentSize);

                result = RuntimeHelpers.Box(pElementMethodTable, ref offsetDataRef);
            }
            else
            {
                // The element is a reference type, so no need to retrieve the component size.
                // Just offset with object size as element type, since it's the same regardless of T.
                ref object elementRef = ref Unsafe.As<byte, object>(ref arrayDataRef);
                ref object offsetElementRef = ref Unsafe.Add(ref elementRef, (nuint)flattenedIndex);

                result = offsetElementRef;
            }

            GC.KeepAlive(this); // Keep the method table alive

            return result;
        }

        private unsafe void InternalSetValue(object? value, nint flattenedIndex)
        {
            MethodTable* pMethodTable = RuntimeHelpers.GetMethodTable(this);

            TypeHandle arrayElementTypeHandle = pMethodTable->GetArrayElementTypeHandle();

            // Legacy behavior (this handles pointers and function pointers)
            if (arrayElementTypeHandle.IsTypeDesc)
            {
                ThrowHelper.ThrowNotSupportedException(ExceptionResource.Arg_TypeNotSupported);
            }

            Debug.Assert((nuint)flattenedIndex < NativeLength);

            ref byte arrayDataRef = ref MemoryMarshal.GetArrayDataReference(this);

            MethodTable* pElementMethodTable = arrayElementTypeHandle.AsMethodTable();

            if (value == null)
            {
                // Null is the universal zero...
                if (pElementMethodTable->IsValueType)
                {
                    ref byte offsetDataRef = ref Unsafe.Add(ref arrayDataRef, flattenedIndex * pMethodTable->ComponentSize);
                    if (pElementMethodTable->ContainsGCPointers)
                    {
                        nuint elementSize = pElementMethodTable->GetNumInstanceFieldBytesIfContainsGCPointers();
                        SpanHelpers.ClearWithReferences(ref Unsafe.As<byte, nint>(ref offsetDataRef), elementSize / (nuint)sizeof(IntPtr));
                    }
                    else
                    {
                        nuint elementSize = pElementMethodTable->GetNumInstanceFieldBytes();
                        SpanHelpers.ClearWithoutReferences(ref offsetDataRef, elementSize);
                    }
                }
                else
                {
                    Unsafe.Add(ref Unsafe.As<byte, object?>(ref arrayDataRef), (nuint)flattenedIndex) = null;
                }
            }
            else if (!pElementMethodTable->IsValueType)
            {
                if (pElementMethodTable != TypeHandle.TypeHandleOf<object>().AsMethodTable() //  Everything is compatible with Object
                    && CastHelpers.IsInstanceOfAny(pElementMethodTable, value) == null)
                    throw new InvalidCastException(SR.InvalidCast_StoreArrayElement);

                Unsafe.Add(ref Unsafe.As<byte, object?>(ref arrayDataRef), (nuint)flattenedIndex) = value;
            }
            else
            {
                // value class or primitive type

                ref byte offsetDataRef = ref Unsafe.Add(ref arrayDataRef, flattenedIndex * pMethodTable->ComponentSize);
                if (CastHelpers.IsInstanceOfAny(pElementMethodTable, value) != null)
                {
                    if (pElementMethodTable->IsNullable)
                    {
                        CastHelpers.Unbox_Nullable(ref offsetDataRef, pElementMethodTable, value);
                    }
                    else
                    {
                        if (pElementMethodTable->ContainsGCPointers)
                        {
                            nuint elementSize = pElementMethodTable->GetNumInstanceFieldBytesIfContainsGCPointers();
                            Buffer.BulkMoveWithWriteBarrier(ref offsetDataRef, ref value.GetRawData(), elementSize);
                        }
                        else
                        {
                            nuint elementSize = pElementMethodTable->GetNumInstanceFieldBytes();
                            SpanHelpers.Memmove(ref offsetDataRef, ref value.GetRawData(), elementSize);
                        }
                    }
                }
                else
                {
                    // Allow enum -> primitive conversion, disallow primitive -> enum conversion
                    MethodTable* pValueMethodTable = RuntimeHelpers.GetMethodTable(value);

                    // Array.SetValue() does *not* permit conversion from a primitive to an Enum.
                    if (!pValueMethodTable->IsPrimitive || !pElementMethodTable->IsTruePrimitive)
                        throw new InvalidCastException(SR.InvalidCast_StoreArrayElement);

                    CorElementType srcType = pValueMethodTable->GetPrimitiveCorElementType();
                    CorElementType targetType = pElementMethodTable->GetPrimitiveCorElementType();

                    // Get a properly widened type
                    if (!RuntimeHelpers.CanPrimitiveWiden(srcType, targetType))
                        throw new ArgumentException(SR.Arg_PrimWiden);

                    if (srcType == targetType)
                    {
                        // Primitive types are always tightly packed in array, using ComponentSize is sufficient.
                        SpanHelpers.Memmove(ref offsetDataRef, ref value.GetRawData(), pMethodTable->ComponentSize);
                    }
                    else
                    {
                        InvokeUtils.PrimitiveWiden(ref value.GetRawData(), ref offsetDataRef, srcType, targetType);
                    }
                }
            }

            GC.KeepAlive(this); // Keep the method table alive
        }

        public int Length => checked((int)Unsafe.As<RawArrayData>(this).Length);

        // This could return a length greater than int.MaxValue
        internal nuint NativeLength => Unsafe.As<RawArrayData>(this).Length;

        public long LongLength => (long)NativeLength;

        public int Rank
        {
            get
            {
                int rank = RuntimeHelpers.GetMultiDimensionalArrayRank(this);
                return (rank != 0) ? rank : 1;
            }
        }

        [Intrinsic]
        public int GetLength(int dimension)
        {
            int rank = RuntimeHelpers.GetMultiDimensionalArrayRank(this);
            if (rank == 0 && dimension == 0)
                return Length;

            if ((uint)dimension >= (uint)rank)
                throw new IndexOutOfRangeException(SR.IndexOutOfRange_ArrayRankIndex);

            return Unsafe.Add(ref RuntimeHelpers.GetMultiDimensionalArrayBounds(this), dimension);
        }

        [Intrinsic]
        public int GetUpperBound(int dimension)
        {
            int rank = RuntimeHelpers.GetMultiDimensionalArrayRank(this);
            if (rank == 0 && dimension == 0)
                return Length - 1;

            if ((uint)dimension >= (uint)rank)
                throw new IndexOutOfRangeException(SR.IndexOutOfRange_ArrayRankIndex);

            ref int bounds = ref RuntimeHelpers.GetMultiDimensionalArrayBounds(this);
            return Unsafe.Add(ref bounds, dimension) + Unsafe.Add(ref bounds, rank + dimension) - 1;
        }

        [Intrinsic]
        public int GetLowerBound(int dimension)
        {
            int rank = RuntimeHelpers.GetMultiDimensionalArrayRank(this);
            if (rank == 0 && dimension == 0)
                return 0;

            if ((uint)dimension >= (uint)rank)
                throw new IndexOutOfRangeException(SR.IndexOutOfRange_ArrayRankIndex);

            return Unsafe.Add(ref RuntimeHelpers.GetMultiDimensionalArrayBounds(this), rank + dimension);
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        internal extern CorElementType GetCorElementTypeOfElementType();

        private unsafe bool IsValueOfElementType(object value)
        {
            MethodTable* thisMT = RuntimeHelpers.GetMethodTable(this);
            return (IntPtr)thisMT->ElementType == (IntPtr)RuntimeHelpers.GetMethodTable(value);
        }

        // if this is an array of value classes and that value class has a default constructor
        // then this calls this default constructor on every element in the value class array.
        // otherwise this is a no-op.  Generally this method is called automatically by the compiler
        public unsafe void Initialize()
        {
            MethodTable* pArrayMT = RuntimeHelpers.GetMethodTable(this);
            TypeHandle thElem = pArrayMT->GetArrayElementTypeHandle();
            if (thElem.IsTypeDesc)
            {
                return;
            }

            MethodTable* pElemMT = thElem.AsMethodTable();
            if (!pElemMT->HasDefaultConstructor || !pElemMT->IsValueType)
            {
                return;
            }

            RuntimeType arrayType = (RuntimeType)GetType();

            ArrayInitializeCache cache = arrayType.GetOrCreateCacheEntry<ArrayInitializeCache>();

            delegate*<ref byte, void> constructorFtn = cache.ConstructorEntrypoint;
            ref byte arrayRef = ref MemoryMarshal.GetArrayDataReference(this);
            nuint elementSize = pArrayMT->ComponentSize;

            for (nuint i = 0; i < NativeLength; i++)
            {
                constructorFtn(ref arrayRef);
                arrayRef = ref Unsafe.Add(ref arrayRef, elementSize);
            }
        }

        internal sealed unsafe partial class ArrayInitializeCache : RuntimeType.IGenericCacheEntry<ArrayInitializeCache>
        {
            internal readonly delegate*<ref byte, void> ConstructorEntrypoint;

            [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "Array_GetElementConstructorEntrypoint")]
            private static partial delegate*<ref byte, void> GetElementConstructorEntrypoint(QCallTypeHandle arrayType);

            private ArrayInitializeCache(delegate*<ref byte, void> constructorEntrypoint)
            {
                ConstructorEntrypoint = constructorEntrypoint;
            }

            public static ArrayInitializeCache Create(RuntimeType arrayType) => new(GetElementConstructorEntrypoint(new QCallTypeHandle(ref arrayType)));
            public void InitializeCompositeCache(RuntimeType.CompositeCacheEntry compositeEntry) => compositeEntry._arrayInitializeCache = this;
            public static ref ArrayInitializeCache? GetStorageRef(RuntimeType.CompositeCacheEntry compositeEntry) => ref compositeEntry._arrayInitializeCache;
        }
    }

#pragma warning disable CA1822 // Mark members as static
    //----------------------------------------------------------------------------------------
    // ! READ THIS BEFORE YOU WORK ON THIS CLASS.
    //
    // The methods on this class must be written VERY carefully to avoid introducing security holes.
    // That's because they are invoked with special "this"! The "this" object
    // for all of these methods are not SZArrayHelper objects. Rather, they are of type U[]
    // where U[] is castable to T[]. No actual SZArrayHelper object is ever instantiated. Thus, you will
    // see a lot of expressions that cast "this" "T[]".
    //
    // This class is needed to allow an SZ array of type T[] to expose IList<T>,
    // IList<T.BaseType>, etc., etc. all the way up to IList<Object>. When the following call is
    // made:
    //
    //   ((IList<T>) (new U[n])).SomeIListMethod()
    //
    // the interface stub dispatcher treats this as a special case, loads up SZArrayHelper,
    // finds the corresponding generic method (matched simply by method name), instantiates
    // it for type <T> and executes it.
    //
    // The "T" will reflect the interface used to invoke the method. The actual runtime "this" will be
    // array that is castable to "T[]" (i.e. for primitives and valuetypes, it will be exactly
    // "T[]" - for orefs, it may be a "U[]" where U derives from T.)
    //----------------------------------------------------------------------------------------
    internal sealed class SZArrayHelper
    {
        // It is never legal to instantiate this class.
        private SZArrayHelper()
        {
            Debug.Fail("Hey! How'd I get here?");
        }

        [Intrinsic]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal IEnumerator<T> GetEnumerator<T>()
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!
            T[] @this = Unsafe.As<T[]>(this);
            int length = @this.Length;
            return length == 0 ? SZGenericArrayEnumerator<T>.Empty : new SZGenericArrayEnumerator<T>(@this, length);
        }

        private void CopyTo<T>(T[] array, int index)
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!

            T[] @this = Unsafe.As<T[]>(this);
            Array.Copy(@this, 0, array, index, @this.Length);
        }

        internal int get_Count<T>()
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!
            T[] @this = Unsafe.As<T[]>(this);
            return @this.Length;
        }

        internal T get_Item<T>(int index)
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!
            T[] @this = Unsafe.As<T[]>(this);
            if ((uint)index >= (uint)@this.Length)
            {
                ThrowHelper.ThrowArgumentOutOfRange_IndexMustBeLessException();
            }

            return @this[index];
        }

        internal void set_Item<T>(int index, T value)
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!
            T[] @this = Unsafe.As<T[]>(this);
            if ((uint)index >= (uint)@this.Length)
            {
                ThrowHelper.ThrowArgumentOutOfRange_IndexMustBeLessException();
            }

            @this[index] = value;
        }

        private void Add<T>(T _)
        {
            // Not meaningful for arrays.
            ThrowHelper.ThrowNotSupportedException(ExceptionResource.NotSupported_FixedSizeCollection);
        }

        private bool Contains<T>(T value)
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!
            T[] @this = Unsafe.As<T[]>(this);
            return Array.IndexOf(@this, value, 0, @this.Length) >= 0;
        }

        private bool get_IsReadOnly<T>()
        {
            return true;
        }

        private void Clear<T>()
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!

            ThrowHelper.ThrowNotSupportedException(ExceptionResource.NotSupported_ReadOnlyCollection);
        }

        private int IndexOf<T>(T value)
        {
            // ! Warning: "this" is an array, not an SZArrayHelper. See comments above
            // ! or you may introduce a security hole!
            T[] @this = Unsafe.As<T[]>(this);
            return Array.IndexOf(@this, value, 0, @this.Length);
        }

        private void Insert<T>(int _, T _1)
        {
            // Not meaningful for arrays
            ThrowHelper.ThrowNotSupportedException(ExceptionResource.NotSupported_FixedSizeCollection);
        }

        private bool Remove<T>(T _)
        {
            // Not meaningful for arrays
            ThrowHelper.ThrowNotSupportedException(ExceptionResource.NotSupported_FixedSizeCollection);
            return default;
        }

        private void RemoveAt<T>(int _)
        {
            // Not meaningful for arrays
            ThrowHelper.ThrowNotSupportedException(ExceptionResource.NotSupported_FixedSizeCollection);
        }
    }
#pragma warning restore CA1822
}
